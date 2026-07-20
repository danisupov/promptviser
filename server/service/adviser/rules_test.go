package adviser_test

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/adviserdb/model"
	"github.com/effective-security/promptviser/mocks/mockadviserdb"
	"github.com/effective-security/promptviser/server/service/adviser"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newService creates an adviser.Service with a mock DB, bypassing the dig
// container so tests can run without a live gRPC server or database.
func newService(t *testing.T) (*adviser.Service, *mockadviserdb.MockAdviserDb) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockDB := mockadviserdb.NewMockAdviserDb(ctrl)
	svc := adviser.NewServiceForTest(mockDB)
	return svc, mockDB
}

// ----- sample rules used across tests ----------------------------------------

var sampleRules = []*adviserdb.Rule{
	{
		RuleID:         "REL-003",
		Domain:         "Reliability & Safety",
		Name:           "High-stakes output with no human oversight clause",
		Severity:       "High",
		TriggerType:    "score",
		ScoreTriggers:  map[string]float64{"output_consequence_gt": 0.75, "human_oversight_gt": 0.6},
		StaticTriggers: nil,
		MetadataFlags:  nil,
		Remediation:    "Add a human oversight clause.",
		Standards:      []string{"AIUC-1 E1", "EU AI Act Art.14"},
	},
	{
		RuleID:         "PRIV-001",
		Domain:         "Data Privacy & Confidentiality",
		Name:           "PII variable sent to an external model",
		Severity:       "High",
		TriggerType:    "combined",
		ScoreTriggers:  map[string]float64{"pii_exposure_gt": 0.7},
		StaticTriggers: []string{"PII_VARIABLE"},
		MetadataFlags:  nil,
		Remediation:    "Use redacted placeholders.",
		Standards:      []string{"OWASP LLM02", "GDPR Art.25"},
	},
	{
		RuleID:         "SEC-001",
		Domain:         "Security & Injection Resistance",
		Name:           "User input not structurally delimited",
		Severity:       "High",
		TriggerType:    "static",
		ScoreTriggers:  nil,
		StaticTriggers: []string{"MISSING_DELIMITER"},
		MetadataFlags:  nil,
		Remediation:    "Wrap user input with structural delimiters.",
		Standards:      []string{"OWASP LLM01"},
	},
	{
		RuleID:         "ACC-001",
		Domain:         "Accountability & Transparency",
		Name:           "User-facing AI without self-identification",
		Severity:       "High",
		TriggerType:    "combined",
		ScoreTriggers:  nil,
		StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
		MetadataFlags:  []string{"is_user_facing"},
		Remediation:    "Add AI self-identification.",
		Standards:      []string{"EU AI Act Art.50"},
	},
}

// ----- MatchRules tests -------------------------------------------------------

func TestMatchRules_GreaterThanThresholdMatchesAtBoundary(t *testing.T) {
	svc, mockDB := newService(t)

	rule := &adviserdb.Rule{
		RuleID:      "TEST-001",
		Domain:      "Test",
		Name:        "Boundary threshold",
		Severity:    "High",
		TriggerType: "score",
		ScoreTriggers: map[string]float64{
			"output_consequence_gt": 0.8,
		},
	}

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return([]*adviserdb.Rule{rule}, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{{
			FileName: "prompts/boundary.yaml",
			Scores:   []*pb.DimensionScore{{Dimension: "output_consequence", Score: 0.8}},
		}},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/boundary.yaml")
	require.Contains(t, ruleIDs, "TEST-001")
}

func TestMatchRules_HighRefusalInstructions_ReturnsREL004(t *testing.T) {
	svc, mockDB := newService(t)

	rule := &adviserdb.Rule{
		RuleID:      "REL-004",
		Domain:      "Reliability & Safety",
		Name:        "No refusal or out-of-scope handling instruction",
		Severity:    "Medium",
		TriggerType: "score",
		ScoreTriggers: map[string]float64{
			"refusal_instructions_gt": 0.6,
		},
	}

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return([]*adviserdb.Rule{rule}, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{{
			FileName: "prompts/refusal.yaml",
			Scores:   []*pb.DimensionScore{{Dimension: "refusal_instructions", Score: 0.9}},
		}},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/refusal.yaml")
	require.Contains(t, ruleIDs, "REL-004")
}

func TestMatchRules_HighConsequenceHighOversight_ReturnsREL003(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName: "prompts/agent.yaml",
				Scores: []*pb.DimensionScore{
					{Dimension: "output_consequence", Score: 0.9},
					{Dimension: "human_oversight", Score: 0.9},
				},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "prompts/agent.yaml", resp.Findings[0].FileName)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/agent.yaml")
	require.Contains(t, ruleIDs, "REL-003")
}

func TestMatchRules_StaticTrigger_ReturnsSEC001(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/chat.yaml",
				StaticTriggers: []string{"MISSING_DELIMITER"},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "prompts/chat.yaml", resp.Findings[0].FileName)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/chat.yaml")
	require.Contains(t, ruleIDs, "SEC-001")
	require.NotContains(t, ruleIDs, "REL-003") // score thresholds not met
}

func TestMatchRules_CombinedRule_RequiresBothStaticAndMeta(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/ui.yaml",
				StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
				MetadataFlags:  []string{"is_user_facing"},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)

	ruleIDs := ruleIDsForFile(resp.Findings, "prompts/ui.yaml")
	require.Contains(t, ruleIDs, "ACC-001")
}

func TestMatchRules_CombinedRule_MissingMetaFlag_NoMatch(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/internal.yaml",
				StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
				// is_user_facing flag absent — ACC-001 should not fire
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	// No rules matched — Findings slice should be empty (files with no hits are omitted)
	require.Empty(t, resp.Findings)
}

func TestMatchRules_NoRulesMatched_ReturnsEmptyFindings(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/clean.yaml",
				StaticTriggers: []string{"UNRELATED_TRIGGER"},
				MetadataFlags:  []string{"unrelated_flag"},
				Scores: []*pb.DimensionScore{
					{Dimension: "unrelated_score", Score: 0.5},
				},
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Empty(t, resp.Findings)
}

func TestMatchRules_DBError_ReturnsError(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(nil, fmt.Errorf("database error"))

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName: "prompts/agent.yaml",
				Scores: []*pb.DimensionScore{
					{Dimension: "output_consequence", Score: 0.9},
					{Dimension: "human_oversight", Score: 0.1},
				},
			},
		},
	}

	_, err := svc.MatchRules(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch rules")
}

func TestMatchRules_MultipleFiles_MatchesCorrectly(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)
	mockDB.EXPECT().
		RecordFindings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()

	req := &pb.MatchRulesRequest{
		FileResults: []*pb.FileScanResult{
			{
				FileName:       "prompts/agent.yaml",
				StaticTriggers: []string{"MISSING_AI_DISCLOSURE"},
				MetadataFlags:  []string{"is_user_facing"},
			},
			{
				FileName:       "prompts/chat.yaml",
				StaticTriggers: []string{"MISSING_DELIMITER"},
			},
			{
				FileName: "prompts/clean.yaml", // no triggers
			},
		},
	}

	resp, err := svc.MatchRules(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 2) // two files with matches

	ruleIDsAgent := ruleIDsForFile(resp.Findings, "prompts/agent.yaml")
	require.Contains(t, ruleIDsAgent, "ACC-001")
	require.NotContains(t, ruleIDsAgent, "SEC-001")

	ruleIDsChat := ruleIDsForFile(resp.Findings, "prompts/chat.yaml")
	require.Contains(t, ruleIDsChat, "SEC-001")
	require.NotContains(t, ruleIDsChat, "ACC-001")
}

func TestMatchRules_NilRequest_ReturnsError(t *testing.T) {
	svc, _ := newService(t)

	_, err := svc.MatchRules(context.Background(), nil)
	require.Error(t, err)
}

func Test_sortFindings_SortsBySeverity(t *testing.T) {
	findings := []*pb.Finding{
		{RuleID: "LOW-001", Severity: "Low"},
		{RuleID: "HIGH-001", Severity: "High"},
		{RuleID: "MEDIUM-001", Severity: "Medium"},
	}
	adviser.SortFindings(&findings)
	require.Equal(t, "High", findings[0].Severity)
	require.Equal(t, "Medium", findings[1].Severity)
	require.Equal(t, "Low", findings[2].Severity)
}

func Test_sortFindings_SortsByRuleIDWhenSeverityTied(t *testing.T) {
	findings := []*pb.Finding{
		{RuleID: "B-001", Severity: "High"},
		{RuleID: "A-001", Severity: "High"},
	}
	adviser.SortFindings(&findings)
	require.Equal(t, "A-001", findings[0].RuleID)
	require.Equal(t, "B-001", findings[1].RuleID)
}

// ----- helpers ----------------------------------------------------------------

// ruleIDsForFile extracts all matched rule IDs for the first PromptFindings
// entry whose FileName matches. Panics if not found — tests should call
// require.Len(t, resp.Findings, ...) first if needed.
func ruleIDsForFile(findings []*pb.PromptFindings, fileName string) []string {
	for _, pf := range findings {
		if pf.FileName == fileName {
			ids := make([]string, 0, len(pf.Findings))
			for _, f := range pf.Findings {
				ids = append(ids, f.RuleID)
			}
			return ids
		}
	}
	return nil
}

// ----- GetRules tests ---------------------------------------------------------

func TestGetRules_ReturnsAllRules(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(sampleRules, nil)

	resp, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Rules, len(sampleRules))

	ids := make([]string, len(resp.Rules))
	for i, r := range resp.Rules {
		ids[i] = r.RuleID
	}
	require.Contains(t, ids, "REL-003")
	require.Contains(t, ids, "SEC-001")
}

func TestGetRules_FiltersByDomainAndSeverity(t *testing.T) {
	svc, mockDB := newService(t)

	filtered := []*adviserdb.Rule{sampleRules[2]} // SEC-001 only
	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "Security & Injection Resistance", "High").
		Return(filtered, nil)

	resp, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{
		Domain:   "Security & Injection Resistance",
		Severity: "High",
	})
	require.NoError(t, err)
	require.Len(t, resp.Rules, 1)
	require.Equal(t, "SEC-001", resp.Rules[0].RuleID)
}

func TestGetRules_NilRequest_ReturnsError(t *testing.T) {
	svc, _ := newService(t)

	_, err := svc.GetRules(context.Background(), nil)
	require.Error(t, err)
}

func TestGetRules_DBError_ReturnsError(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return(nil, fmt.Errorf("connection refused"))

	_, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch rules")
}

func TestGetRules_EmptyDB_ReturnsEmptyList(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetAllRules(gomock.Any(), "", "").
		Return([]*adviserdb.Rule{}, nil)

	resp, err := svc.GetRules(context.Background(), &pb.GetRulesRequest{})
	require.NoError(t, err)
	require.Empty(t, resp.Rules)
}

// ----- GetStats tests ---------------------------------------------------------

func TestGetStats_ReturnsTopViolations(t *testing.T) {
	svc, mockDB := newService(t)

	entries := []*model.RuleStatEntry{
		{RuleID: "SEC-001", Name: "Missing delimiter", Severity: "High", Domain: "Security", Count: 42},
		{RuleID: "PRIV-001", Name: "PII variable", Severity: "High", Domain: "Privacy", Count: 17},
	}
	mockDB.EXPECT().
		GetRuleStats(gomock.Any(), 10).
		Return(entries, nil)

	resp, err := svc.GetStats(context.Background(), &pb.GetStatsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.TopViolations, 2)
	require.Equal(t, "SEC-001", resp.TopViolations[0].RuleID)
	require.Equal(t, int64(42), resp.TopViolations[0].Count)
	require.Equal(t, "PRIV-001", resp.TopViolations[1].RuleID)
}

func TestGetStats_CustomLimit(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetRuleStats(gomock.Any(), 5).
		Return([]*model.RuleStatEntry{}, nil)

	resp, err := svc.GetStats(context.Background(), &pb.GetStatsRequest{Limit: 5})
	require.NoError(t, err)
	require.Empty(t, resp.TopViolations)
}

func TestGetStats_NilRequest_UsesDefaultLimit(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetRuleStats(gomock.Any(), 10).
		Return([]*model.RuleStatEntry{}, nil)

	resp, err := svc.GetStats(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestGetStats_DBError_ReturnsError(t *testing.T) {
	svc, mockDB := newService(t)

	mockDB.EXPECT().
		GetRuleStats(gomock.Any(), 10).
		Return(nil, fmt.Errorf("timeout"))

	_, err := svc.GetStats(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch stats")
}

// ----- Submit tests -----------------------------------------------------------

func TestSubmit_ReturnsID(t *testing.T) {
	svc, _ := newService(t)

	resp, err := svc.Submit(context.Background(), &pb.SubmitRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)
}

// ----- Service lifecycle tests ------------------------------------------------

func TestService_Name(t *testing.T) {
	svc, _ := newService(t)
	require.Equal(t, adviser.ServiceName, svc.Name())
}

func TestService_IsReady(t *testing.T) {
	svc, _ := newService(t)
	require.True(t, svc.IsReady())
}

func TestService_Close_DoesNotPanic(t *testing.T) {
	svc, _ := newService(t)
	require.NotPanics(t, func() { svc.Close() })
}
