package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/stretchr/testify/require"
)

func TestBuildSARIF(t *testing.T) {
	resp := &pb.MatchRulesResponse{
		Findings: []*pb.PromptFindings{
			{
				FileName: "prompts/agent.yaml",
				Findings: []*pb.Finding{
					{
						RuleID:      "PRIV-001",
						Title:       "PII in prompt",
						Severity:    "High",
						Remediation: "Remove sensitive identifiers before submission.",
						Standards:   []string{"OWASP LLM01"},
					},
					{
						RuleID:      "PRIV-001",
						Title:       "PII in prompt",
						Severity:    "High",
						Remediation: "Remove sensitive identifiers before submission.",
					},
				},
			},
		},
	}

	sarif := BuildSARIF(resp, "1.2.3")
	require.Equal(t, "2.1.0", sarif.Version)
	require.Len(t, sarif.Runs, 1)
	require.Equal(t, "promptviser", sarif.Runs[0].Tool.Driver.Name)
	require.Len(t, sarif.Runs[0].Tool.Driver.Rules, 1)
	require.Len(t, sarif.Runs[0].Results, 2)
	require.Equal(t, "prompts/agent.yaml", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.Equal(t, "error", sarif.Runs[0].Results[0].Level)

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "promptviser.sarif.json")
	require.NoError(t, WriteSARIF(outputPath, sarif))

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var written SARIF
	require.NoError(t, json.Unmarshal(content, &written))
	require.Equal(t, sarif.Version, written.Version)
	require.Len(t, written.Runs[0].Results, 2)
}
