package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/llm"
	pass3 "github.com/effective-security/promptviser/internal/scanner/pass3"
	advisersvc "github.com/effective-security/promptviser/server/service/adviser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_collectPromptFiles(t *testing.T) {
	dir := "./testdata/fake-project"
	expectedFiles := []string{
		"testdata/fake-project/prompts/patient-intake.yaml",
		"testdata/fake-project/prompts/rag-search.yaml",
		"testdata/fake-project/prompts/fully-compliant.yaml",
		"testdata/fake-project/prompts/hardcoded-secret.yaml",
		"testdata/fake-project/prompts/more/hiring-bot.yaml",
		"testdata/fake-project/prompts/crisis-support.yaml",
		"testdata/fake-project/prompts/more/agent-executor.yaml",
	}

	// Test with a directory path
	files, err := collectPromptFiles(dir)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	assert.ElementsMatch(t, files, expectedFiles)

	// Test with a file path
	path := "testdata/fake-project/prompts/patient-intake.yaml"
	files, err = collectPromptFiles(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, files, []string{path})

	// Test with a non-existent path
	_, err = collectPromptFiles("nonexistent/path")
	require.Error(t, err)

	// Test with a path that has no prompt files
	files, err = collectPromptFiles("testdata/fake-project/empty-dir")
	require.NoError(t, err)
	assert.Empty(t, files)
}

func Test_Scan(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{
		Provider: "stub",
	})
	require.NoError(t, err)

	dir := "./testdata/fake-project"
	results, err := Scan(ctx, dir, provider)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Check that we got results with scores — not every file is guaranteed to
	// have static triggers (e.g. a well-written prompt with a persona and no
	// injection surface).
	for _, result := range results {
		assert.NotNil(t, result.Scores)
	}
}

func Test_ScanAndMatchRules(t *testing.T) {
	// A representative subset of rules — static-only and meta-only rules that
	// fire deterministically regardless of LLM scores.
	rules := []*adviserdb.Rule{
		{
			RuleID:         "SEC-001",
			Domain:         "Security & Injection Resistance",
			Name:           "User input not structurally delimited",
			Severity:       "High",
			TriggerType:    "static",
			StaticTriggers: []string{"MISSING_DELIMITER"},
		},
		{
			RuleID:         "SEC-003",
			Domain:         "Security & Injection Resistance",
			Name:           "Excessive tool agency without confirmation gate",
			Severity:       "High",
			TriggerType:    "combined",
			StaticTriggers: []string{"EXCESSIVE_TOOL_AGENCY"},
		},
		{
			RuleID:        "SEC-006",
			Domain:        "Security & Injection Resistance",
			Name:          "No rate limiting or abuse signal in agent prompt",
			Severity:      "Low",
			TriggerType:   "meta",
			MetadataFlags: []string{"no_timeout", "loop_or_batch_context"},
		},
	}

	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	fileResults, err := Scan(ctx, "./testdata/fake-project", provider)
	require.NoError(t, err)
	require.NotEmpty(t, fileResults)

	// Match each file result against the rule set.
	type fileFindings struct {
		fileName string
		ruleIDs  []string
	}
	var got []fileFindings
	for _, fr := range fileResults {
		pf := advisersvc.FindingsForFile(fr, rules)
		if len(pf.Findings) == 0 {
			continue
		}
		ids := make([]string, 0, len(pf.Findings))
		for _, f := range pf.Findings {
			ids = append(ids, f.RuleID)
		}
		got = append(got, fileFindings{fileName: pf.FileName, ruleIDs: ids})
	}

	// Every file containing {{.UserInput}} should trigger SEC-001.
	findRuleIDs := func(fileName string) []string {
		for _, ff := range got {
			if ff.fileName == fileName {
				return ff.ruleIDs
			}
		}
		return nil
	}

	assert.Contains(t, findRuleIDs("testdata/fake-project/prompts/patient-intake.yaml"), "SEC-001")
	assert.Contains(t, findRuleIDs("testdata/fake-project/prompts/crisis-support.yaml"), "SEC-001")

	// agent-executor has irreversible tools → SEC-003 and SEC-006.
	// Note: it uses {{.UserTask}} not {{.UserInput}}, so SEC-001 does not fire.
	agentIDs := findRuleIDs("testdata/fake-project/prompts/more/agent-executor.yaml")
	assert.NotContains(t, agentIDs, "SEC-001")
	assert.Contains(t, agentIDs, "SEC-003")
	assert.Contains(t, agentIDs, "SEC-006")
}

func Test_ScanReal(t *testing.T) {
	t.Skip()
	apiKey := "" // set your OpenAI API key here for testing

	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{
		Provider:   "azure",
		Model:      "gpt-5.1",
		BaseURL:    "https://secdi-ai-dev.openai.azure.com/",
		APIKey:     apiKey,
		APIVersion: "2025-04-01-preview",
	})
	require.NoError(t, err)

	dir := "./testdata/fake-project"
	results, err := Scan(ctx, dir, provider)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Print results for manual inspection
	jsonResults, _ := json.MarshalIndent(results, "", "  ")
	fmt.Printf("Scan results:\n%s\n", string(jsonResults))
	t.Fail()
}

func Test_ScanCoverageBad(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	results, err := Scan(ctx, "./testdata/coverage-bad", provider)
	require.NoError(t, err)
	require.Len(t, results, 6)

	// Index results by filename for stable lookups regardless of walk order.
	byFile := make(map[string]*pb.FileScanResult, len(results))
	for _, r := range results {
		byFile[r.FileName] = r
	}

	check := func(file string, wantTriggers, wantFlags []string) {
		t.Helper()
		r, ok := byFile[file]
		require.Truef(t, ok, "file not found in results: %s", file)
		assert.ElementsMatch(t, wantTriggers, r.StaticTriggers, "triggers for %s", file)
		assert.ElementsMatch(t, wantFlags, r.MetadataFlags, "flags for %s", file)
	}

	// agent-loop: has "You are", irreversible tool names in prompt text
	check("testdata/coverage-bad/prompts/agent-loop.yaml",
		[]string{"EXCESSIVE_TOOL_AGENCY"},
		[]string{"no_timeout", "loop_or_batch_context"},
	)

	// data-collection: no persona, PII vars, Bearer secret, confidentiality phrase, memory ref, user input
	check("testdata/coverage-bad/prompts/data-collection.yaml",
		[]string{"PII_VARIABLE", "HARDCODED_SECRET", "CONFIDENTIALITY_INSTRUCTION", "MEMORY_REFERENCE", "MISSING_DELIMITER", "MISSING_PERSONA", "NEGATIVE_ONLY_INSTRUCTION"},
		[]string{"is_user_facing", "domain:medical"},
	)

	// decision-bot: no persona, bias keywords, synthetic media
	check("testdata/coverage-bad/prompts/decision-bot.yaml",
		[]string{"MISSING_BIAS_GUARDRAIL", "SYNTHETIC_MEDIA_GENERATION", "MISSING_PERSONA"},
		[]string{"is_user_facing", "domain:hiring"},
	)

	// high-stakes: has "You are", crisis keywords, loop, uncertainty phrase, RAG block, user input
	check("testdata/coverage-bad/prompts/high-stakes.yaml",
		[]string{"MISSING_UNCERTAINTY_CLAUSE", "MISSING_CRISIS_ESCALATION", "AGENTIC_LOOP_NO_TERMINATION", "NEGATIVE_ONLY_INSTRUCTION", "MISSING_DELIMITER"},
		[]string{"is_user_facing", "domain:mental_health"},
	)

	// injection-surface: no "You are", retrieved content, multi-agent, unsanitized output, user input
	check("testdata/coverage-bad/prompts/injection-surface.yaml",
		[]string{"EXTERNAL_CONTENT_INGESTION", "MULTI_AGENT_REFERENCE", "UNSANITIZED_OUTPUT", "MISSING_DELIMITER", "MISSING_PERSONA"},
		[]string{"is_user_facing"},
	)

	// poorly-engineered: no persona, negative-only, conflicting instructions, user input
	check("testdata/coverage-bad/prompts/poorly-engineered.yaml",
		[]string{"MISSING_PERSONA", "NEGATIVE_ONLY_INSTRUCTION", "CONFLICTING_INSTRUCTIONS", "MISSING_DELIMITER"},
		[]string{},
	)
}

func Test_ScanCoverageFixed(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	results, err := Scan(ctx, "./testdata/coverage-fixed", provider)
	require.NoError(t, err)
	require.Len(t, results, 6)

	// Check that no static triggers fire on the fixed versions of the prompts.
	// MetadataFlags (is_user_facing, domain:*) are not checked here — they are
	// legitimate domain attributes of a well-written prompt, not scanner-detected
	// problems. Rule findings derived from those flags are tested separately.
	for _, r := range results {
		assert.Empty(t, r.StaticTriggers, "expected no triggers for %s", r.FileName)
	}
}

func Test_ScanConcurrency(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{
		Provider: "stub",
	})
	require.NoError(t, err)

	dir := "./testdata/fake-project"
	results, err := Scan(ctx, dir, provider)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Check that all files were processed
	files, err := collectPromptFiles(dir)
	require.NoError(t, err)
	require.Equal(t, len(files), len(results))

	// Check that LLM scoring was called concurrently
	// This is a stubbed test since the actual concurrency is hard to measure directly
	// but we can ensure no duplicate scores exist for the same dimension in a file
	for _, result := range results {
		seen := make(map[string]bool)
		for _, score := range result.Scores {
			assert.False(t, seen[score.Dimension], "Duplicate score for dimension %s", score.Dimension)
			seen[score.Dimension] = true
		}
	}
}

// ----- findCallerFiles tests --------------------------------------------------

func callerPaths(callers []pass3.CallerFile) []string {
	paths := make([]string, len(callers))
	for i, c := range callers {
		paths[i] = filepath.ToSlash(c.Path)
	}
	return paths
}

func Test_findCallerFiles_PatientIntake(t *testing.T) {
	// src/main.go contains "patient-intake.yaml" so it should be found.
	got := findCallerFiles(
		"testdata/fake-project/prompts/patient-intake.yaml",
		"testdata/fake-project",
	)
	paths := callerPaths(got)
	assert.Contains(t, paths, "testdata/fake-project/src/main.go")
	// handler.py references crisis-support, not patient-intake.
	assert.NotContains(t, paths, "testdata/fake-project/src/handler.py")
}

func Test_findCallerFiles_CrisisSupport(t *testing.T) {
	// src/handler.py contains "crisis-support.yaml" so it should be found.
	got := findCallerFiles(
		"testdata/fake-project/prompts/crisis-support.yaml",
		"testdata/fake-project",
	)
	paths := callerPaths(got)
	assert.Contains(t, paths, "testdata/fake-project/src/handler.py")
	assert.NotContains(t, paths, "testdata/fake-project/src/main.go")
}

func Test_findCallerFiles_NoCallers(t *testing.T) {
	// fully-compliant.yaml is not referenced by any source file.
	got := findCallerFiles(
		"testdata/fake-project/prompts/fully-compliant.yaml",
		"testdata/fake-project",
	)
	assert.Empty(t, got)
}

func Test_findCallerFiles_NonexistentRoot(t *testing.T) {
	// A non-existent root directory should return an empty slice, not panic.
	got := findCallerFiles("prompts/patient-intake.yaml", "nonexistent/dir")
	assert.Empty(t, got)
}
