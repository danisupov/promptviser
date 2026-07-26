package command

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/api/version"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/internal/llm"
	"github.com/effective-security/promptviser/internal/reporter"
	"github.com/effective-security/promptviser/internal/scanner"
)

// ScanCmd scans prompts and returns the findings
type ScanCmd struct {
	Path        string `arg:"" help:"Path to the project directory to scan" type:"existingdir"`
	Save        bool   `help:"Save scan results to ~/.config/promptviser/scans/"`
	Verbose     bool   `short:"v" help:"Verbose output"`
	Remediate   bool   `help:"Generate LLM remediation suggestions for each file with findings"`
	Sarif       bool   `help:"Write SARIF output instead of human-readable text"`
	SarifOutput string `help:"SARIF output file path" default:"promptviser.sarif.json"`
}

// Run the command
func (a *ScanCmd) Run(c *cli.Cli) error {
	ctx := c.Context()

	fmt.Fprintf(c.ErrWriter(), "%s	loading config: %s\n", reporter.Working, c.Cfg)
	cfg, err := config.Load(c.Cfg)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to load config: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	provider, err := llm.New(cfg.LLM)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to create LLM provider: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "%s	scanning: %s\n", reporter.Working, a.Path)
	results, err := scanner.Scan(ctx, a.Path, provider)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	scan failed: %v\n", reporter.Warn, err)
		return fmt.Errorf("scan failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "%s	scanned %d file(s)\n", reporter.Info, len(results))

	adviser, err := c.AdviserClient(true)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	failed to connect to adviser: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to connect to adviser: %w", err)
	}

	fmt.Fprintf(c.ErrWriter(), "%s	matching rules...\n", reporter.Working)
	resp, err := adviser.MatchRules(ctx, &pb.MatchRulesRequest{
		FileResults: results,
	})
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s	rule matching failed: %v\n", reporter.Warn, err)
		return fmt.Errorf("rule matching failed: %w", err)
	}
	fmt.Fprintf(c.ErrWriter(), "%s	found findings in %d file(s)\n", reporter.Info, len(resp.Findings))

	if a.Save {
		scanID, err := saveScanResult(a.Path, resp)
		if err != nil {
			// non-fatal: print warning but still show results
			fmt.Fprintf(c.ErrWriter(), "%s	warning: failed to save scan: %v\n", reporter.Warn, err)
		} else {
			fmt.Fprintf(c.ErrWriter(), "%s	saved scan: %s\n", reporter.Info, scanID)
		}
		if a.Verbose || !reporter.IsTerminal() {
			return c.Print(resp)
		}
		reporter.PrintScanSummary(resp, scanID)
		if a.Remediate {
			runRemediation(ctx, c, provider, resp)
		}
		return nil
	}

	if a.Sarif {
		sarif := reporter.BuildSARIF(resp, version.Current().String())
		if err := reporter.WriteSARIF(a.SarifOutput, sarif); err != nil {
			fmt.Fprintf(c.ErrWriter(), "%s	failed to write SARIF: %v\n", reporter.Warn, err)
			return fmt.Errorf("failed to write SARIF: %w", err)
		}
		if a.Remediate {
			runRemediation(ctx, c, provider, resp)
		}
		return nil
	}

	if a.Verbose || !reporter.IsTerminal() {
		return c.Print(resp)
	}

	reporter.PrintScanSummary(resp, "")
	if a.Remediate {
		runRemediation(ctx, c, provider, resp)
	}
	return nil
}

// saveScanResult writes the findings to ~/.config/promptviser/scans/<slug>_<id>_<timestamp>.json
// and returns the scan ID derived from the content hash.
func saveScanResult(scanPath string, resp *pb.MatchRulesResponse) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	scansDir := filepath.Join(home, ".config", "promptviser", "scans")
	if err := os.MkdirAll(scansDir, 0o700); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", err
	}

	// derive a stable 8-char ID from the content hash
	hash := sha256.Sum256(data)
	id := fmt.Sprintf("%x", hash[:4])

	// build a filesystem-safe slug from the scanned path
	abs, _ := filepath.Abs(scanPath)
	slug := reporter.ShortPath(abs)
	slug = strings.NewReplacer("/", "_", "\\", "_", " ", "-", ":", "").Replace(strings.TrimPrefix(slug, "/"))
	ts := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s_%s_%s.json", slug, id, ts)

	dest := filepath.Join(scansDir, filename)
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", err
	}

	fmt.Printf("%s\tsaved: %s\n", reporter.Info, dest)
	return id, nil
}

// runRemediation calls the LLM remediation for each file that has findings and
// prints lint-style output. It is shared by ScanCmd (--remediate) and ScanRemediateCmd.
func runRemediation(ctx context.Context, c *cli.Cli, provider llm.Provider, resp *pb.MatchRulesResponse) {
	for _, ff := range resp.Findings {
		if len(ff.Findings) == 0 {
			continue
		}
		content, err := os.ReadFile(ff.FileName)
		if err != nil {
			fmt.Fprintf(c.ErrWriter(), "%s\tskipping remediation for %s (cannot read file): %v\n", reporter.Warn, ff.FileName, err)
			continue
		}
		violations := make([]llm.RemediationViolation, 0, len(ff.Findings))
		for _, f := range ff.Findings {
			violations = append(violations, llm.RemediationViolation{
				RuleID:      f.RuleID,
				RuleName:    f.Title,
				Severity:    f.Severity,
				TriggerType: f.TriggerType,
				Remediation: f.Remediation,
			})
		}
		userMsg, err := llm.RenderRemediationMessage(string(content), violations)
		if err != nil {
			fmt.Fprintf(c.ErrWriter(), "%s\tfailed to build remediation message for %s: %v\n", reporter.Warn, ff.FileName, err)
			continue
		}
		fmt.Fprintf(c.ErrWriter(), "%s\tremediating: %s\n", reporter.Working, ff.FileName)
		result, err := provider.Remediate(ctx, []byte(userMsg))
		if err != nil {
			fmt.Fprintf(c.ErrWriter(), "%s\tremediation failed for %s: %v\n", reporter.Warn, ff.FileName, err)
			continue
		}
		reporter.PrintRemediations(ff.FileName, result.Remediations)
	}
}
