package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/effective-security/promptviser/api/pb"
)

type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription SARIFMessage        `json:"shortDescription"`
	FullDescription  SARIFMessage        `json:"fullDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       SARIFRuleProperties `json:"properties"`
}

type SARIFRuleProperties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"problem.severity"` // "error", "warning", "recommendation"
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // "error", "warning", "note"
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

func severityToLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func BuildSARIF(resp *pb.MatchRulesResponse, version string) SARIF {
	sarifRulesByID := map[string]SARIFRule{}
	sarifResults := make([]SARIFResult, 0)

	if resp != nil {
		for _, fileResult := range resp.GetFindings() {
			artifactURI := filepath.ToSlash(fileResult.GetFileName())
			for _, finding := range fileResult.GetFindings() {
				ruleID := finding.GetRuleID()
				if _, ok := sarifRulesByID[ruleID]; !ok {
					sarifRulesByID[ruleID] = SARIFRule{
						ID:               ruleID,
						Name:             finding.GetTitle(),
						ShortDescription: SARIFMessage{Text: finding.GetTitle()},
						FullDescription:  SARIFMessage{Text: finding.GetRemediation()},
						Properties: SARIFRuleProperties{
							Tags:     finding.GetStandards(),
							Severity: strings.ToLower(finding.GetSeverity()),
						},
					}
				}

				messageText := strings.TrimSpace(finding.GetTitle())
				if remediation := strings.TrimSpace(finding.GetRemediation()); remediation != "" {
					if messageText != "" {
						messageText += ". "
					}
					messageText += remediation
				}

				sarifResults = append(sarifResults, SARIFResult{
					RuleID:  ruleID,
					Level:   severityToLevel(finding.GetSeverity()),
					Message: SARIFMessage{Text: messageText},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: artifactURI},
							Region:           SARIFRegion{StartLine: 1},
						},
					}},
				})
			}
		}
	}

	sarifRules := make([]SARIFRule, 0, len(sarifRulesByID))
	ruleIDs := make([]string, 0, len(sarifRulesByID))
	for ruleID := range sarifRulesByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		sarifRules = append(sarifRules, sarifRulesByID[ruleID])
	}

	return SARIF{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "promptviser",
				Version:        version,
				InformationURI: "https://github.com/danisupov/promptviser",
				Rules:          sarifRules,
			}},
			Results: sarifResults,
		}},
	}
}

func WriteSARIF(path string, s SARIF) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if path == "" || path == "-" {
		return enc.Encode(s)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc = json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
