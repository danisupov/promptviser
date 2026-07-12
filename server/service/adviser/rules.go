package adviser

import (
	"context"
	"sort"
	"strings"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/adviserdb/model"
	"github.com/effective-security/x/guid"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MatchRules evaluates the anonymised dimension scores and static triggers sent
// by the client and returns every rule whose conditions are satisfied.
// No prompt text is processed here — only numeric scores and named flags.
func (s *Service) MatchRules(ctx context.Context, req *pb.MatchRulesRequest) (*pb.MatchRulesResponse, error) {
	if req == nil || len(req.FileResults) == 0 {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	rules, err := s.db.GetAllRules(ctx, "", "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch rules: %v", err)
	}

	var findings []*pb.PromptFindings
	for _, fr := range req.FileResults {
		pf := FindingsForFile(fr, rules)
		if len(pf.Findings) > 0 {
			SortFindings(&pf.Findings)
			findings = append(findings, pf)
		}
	}

	resp := &pb.MatchRulesResponse{Findings: findings}

	// Persist violations for stats aggregation — best-effort; never fail the RPC.
	if len(findings) > 0 {
		scanID := guid.MustCreate()
		records := make([]model.FindingRecord, 0, len(findings))
		for _, pf := range findings {
			for _, f := range pf.Findings {
				records = append(records, model.FindingRecord{
					RuleID:   f.RuleID,
					FileName: pf.FileName,
				})
			}
		}
		if recErr := s.db.RecordFindings(ctx, scanID, records); recErr != nil {
			logger.KV(xlog.WARNING, "reason", "record_findings_failed", "err", recErr.Error())
		}
	}

	return resp, nil
}

// FindingsForFile returns a PromptFindings grouping all matched rules for a
// single scanned file. It is a pure function with no I/O.
func FindingsForFile(fr *pb.FileScanResult, rules []*adviserdb.Rule) *pb.PromptFindings {
	// build lookup sets once so each rule check is O(1)
	staticSet := toSet(fr.StaticTriggers)
	// AST triggers (pass3) participate in the same static matching logic.
	for _, t := range fr.ASTTriggers {
		staticSet[t] = true
	}
	metaSet := toSet(fr.MetadataFlags)
	scoreMap := make(map[string]float64, len(fr.Scores))
	for _, s := range fr.Scores {
		scoreMap[s.Dimension] = float64(s.Score)
	}

	pf := &pb.PromptFindings{FileName: fr.FileName}
	for _, r := range rules {
		if ruleMatches(r, staticSet, metaSet, scoreMap) {
			pf.Findings = append(pf.Findings, ruleToFinding(r))
		}
	}
	return pf
}

// ruleMatches returns true when all conditions of the rule are satisfied.
func ruleMatches(r *adviserdb.Rule, staticSet, metaSet map[string]bool, scoreMap map[string]float64) bool {
	// static triggers: at least one must appear
	if len(r.StaticTriggers) > 0 && !anyInSet(r.StaticTriggers, staticSet) {
		return false
	}
	// metadata flags: all required flags must be present
	if len(r.MetadataFlags) > 0 && !allInSet(r.MetadataFlags, metaSet) {
		return false
	}
	// score thresholds: all must be satisfied
	for key, threshold := range r.ScoreTriggers {
		if strings.HasSuffix(key, "_gt") {
			dim := strings.TrimSuffix(key, "_gt")
			if scoreMap[dim] <= threshold {
				return false
			}
		} else if strings.HasSuffix(key, "_lt") {
			dim := strings.TrimSuffix(key, "_lt")
			if scoreMap[dim] >= threshold {
				return false
			}
		}
	}
	return true
}

func SortFindings(findings *[]*pb.Finding) {
	// sort findings by severity (High > Medium > Low) then by rule ID
	severityRank := map[string]int{"High": 3, "Medium": 2, "Low": 1}
	sort.SliceStable(*findings, func(i, j int) bool {
		a, b := (*findings)[i], (*findings)[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		return a.RuleID < b.RuleID
	})
}

// GetRules returns the full rule catalogue, optionally filtered by domain and/or severity.
func (s *Service) GetRules(ctx context.Context, req *pb.GetRulesRequest) (*pb.GetRulesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	rules, err := s.db.GetAllRules(ctx, req.Domain, req.Severity)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch rules: %v", err)
	}

	findings := make([]*pb.Finding, 0, len(rules))
	for _, r := range rules {
		findings = append(findings, ruleToFinding(r))
	}

	return &pb.GetRulesResponse{Rules: findings}, nil
}

func ruleToFinding(r *adviserdb.Rule) *pb.Finding {
	return &pb.Finding{
		RuleID:      r.RuleID,
		Title:       r.Name,
		Severity:    r.Severity,
		Domain:      r.Domain,
		Remediation: r.Remediation,
		Standards:   r.Standards,
		TriggerType: r.TriggerType,
	}
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, v := range items {
		s[v] = true
	}
	return s
}

func anyInSet(items []string, set map[string]bool) bool {
	for _, v := range items {
		if set[v] {
			return true
		}
	}
	return false
}

func allInSet(items []string, set map[string]bool) bool {
	for _, v := range items {
		if !set[v] {
			return false
		}
	}
	return true
}
