package pass1

import (
	"bytes"
	"regexp"
)

// pattern holds a compiled regex and the trigger name it fires.
type pattern struct {
	re      *regexp.Regexp
	trigger string
}

// personaPattern matches the presence of a role/persona declaration.
// Used as an absence check: if it does NOT match, MISSING_PERSONA fires.
var personaPattern = regexp.MustCompile(`(?i)\b(?:You\s+are|Your\s+role\s+is|Act\s+as\s+a|As\s+a\s+\w+\s+assistant)\b`)

// patterns is the list of all Pass 1 regex rules.
// Each entry maps to a StaticTrigger name that the server rules reference.
var patterns = []pattern{
	// PII template variables
	{regexp.MustCompile(`\{\{\.(?:SSN|DOB|Email|Phone|MedicalRecord|DateOfBirth|SocialSecurity)\}\}`), "PII_VARIABLE"},

	// Hardcoded secrets / credentials
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`), "HARDCODED_SECRET"},           // OpenAI key
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "HARDCODED_SECRET"},              // AWS access key
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "HARDCODED_SECRET"},           // GitHub PAT
	{regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-]{20,}`), "HARDCODED_SECRET"}, // Bearer token

	// Confidentiality instruction
	{regexp.MustCompile(`(?i)keep\s+this\s+confidential|do\s+not\s+reveal`), "CONFIDENTIALITY_INSTRUCTION"},

	// Cross-session memory references
	{regexp.MustCompile(`(?i)\b(?:remember|last\s+time|your\s+history|previous\s+conversation)\b`), "MEMORY_REFERENCE"},

	// Indirect injection / external content ingestion
	{regexp.MustCompile(`(?i)\b(?:browse|fetch|read\s+url|search\s+web|retrieved\s+documents|from\s+the\s+following\s+webpage)\b`), "EXTERNAL_CONTENT_INGESTION"},

	// Excessive tool agency keywords
	{regexp.MustCompile(`(?i)\b(?:db_write|file_delete|send_email|execute_code|git_push)\b`), "EXCESSIVE_TOOL_AGENCY"},

	// Unsanitized output destination keywords
	{regexp.MustCompile(`(?i)\b(?:ResponseWriter|template\.HTML)\b`), "UNSANITIZED_OUTPUT"},

	// Multi-agent references without trust declaration
	{regexp.MustCompile(`(?i)\b(?:other\s+agent|sub-agent|orchestrator|tool\s+output|agent\s+result)\b`), "MULTI_AGENT_REFERENCE"},

	// Missing uncertainty clause in fact-retrieval prompts
	// This fires when there is no hedge phrase (will be checked inverted by the scorer).
	// Here we detect fact-retrieval prompts that lack any uncertainty language.
	// NOTE: absence-based rules are hard to do in pure regex — this flags the
	// presence of a positive assertion without the hedge. The LLM pass refines this.
	{regexp.MustCompile(`(?i)\b(?:the\s+answer\s+is|the\s+fact\s+is|definitively)\b`), "MISSING_UNCERTAINTY_CLAUSE"},

	// RAG context block without citation instruction
	{regexp.MustCompile(`(?i)^(?:context|retrieved|documents|search\s+results)\s*:`), "RAG_WITHOUT_CITATION"},

	// Missing refusal instruction
	{regexp.MustCompile(`(?i)\b(?:outside\s+my\s+scope|I\s+cannot\s+help\s+with|not\s+designed\s+to)\b`), "MISSING_REFUSAL_INSTRUCTION"},

	// Agentic loop without termination
	{regexp.MustCompile(`(?i)\b(?:repeat\s+until|loop\s+until|keep\s+trying|retry\s+indefinitely)\b`), "AGENTIC_LOOP_NO_TERMINATION"},

	// Synthetic media generation
	{regexp.MustCompile(`(?i)\b(?:generate\s+image\s+of|create\s+a\s+photo|make\s+a\s+voice|synthesize\s+audio|impersonate|write\s+as\s+if\s+you\s+are)\b`), "SYNTHETIC_MEDIA_GENERATION"},

	// Token-heavy prompt (rough heuristic: file > 3000 bytes)
	// Handled separately in Check() below.

	// Conflicting instructions
	{regexp.MustCompile(`(?i)\bbe\s+concise\b`), "CONFLICTING_INSTRUCTIONS"},
	{regexp.MustCompile(`(?i)\bprovide\s+comprehensive\b`), "CONFLICTING_INSTRUCTIONS"},

	// Output going to DB or file
	{regexp.MustCompile(`(?i)(?:db\.Exec|file\.Write|os\.WriteFile|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b`), "OUTPUT_TO_DB_OR_FILE"},

	// No role or persona definition — absence check, handled in Check() below.
	// Do NOT add a presence pattern here.

	// Missing bias guardrail — fires when the prompt instructs the model to
	// actively use protected characteristics as selection criteria, or when
	// a weak/inverted guardrail ("do not consider") is present.
	{regexp.MustCompile(`(?i)\b(?:do\s+not\s+consider|ignore\s+protected|consider\s+their\s+(?:race|gender|age|religion))\b`), "MISSING_BIAS_GUARDRAIL"},
}

// tokenHeavyThreshold is the byte size above which TOKEN_HEAVY_PROMPT fires.
const tokenHeavyThreshold = 3000

// negOnlyRe / negOnlyThreshold implement NEGATIVE_ONLY_INSTRUCTION: fire only
// when the prompt contains 4 or more negative directives, indicating it relies
// predominantly on prohibitions rather than positive guidance.
var negOnlyRe = regexp.MustCompile(`(?i)\b(?:do\s+not|never|avoid)\b`)

const negOnlyThreshold = 4

// delimVarRe matches a user-input template variable that stands alone on its
// line (the form that should be wrapped in structural delimiters).
// inlineVarRe matches the same variable anywhere on a line.
// delimLineRe matches structural delimiter markers (### or """).
var (
	delimVarRe  = regexp.MustCompile(`(?i)^\s*\{\{\.(?:UserInput|UserMessage|Query|Prompt)\}\}\s*$`)
	inlineVarRe = regexp.MustCompile(`(?i)\{\{\.(?:UserInput|UserMessage|Query|Prompt)\}\}`)
	delimLineRe = regexp.MustCompile(`###|"""`)
)

// crisisRe matches crisis / self-harm keywords.
// escalationRe matches explicit escalation-path phrases (988, crisis line, etc.).
// MISSING_CRISIS_ESCALATION fires when crisis keywords are present but no
// escalation path has been provided.
var (
	crisisRe     = regexp.MustCompile(`(?i)\b(?:self[\s.\-]?harm|suicide|suicidal)\b`)
	escalationRe = regexp.MustCompile(`(?i)\b(?:988|crisis\s+line|crisis\s+lifeline|emergency\s+services)\b`)
)

// Check runs all Pass 1 regex patterns against content and returns the list
// of unique StaticTrigger names that fired. Duplicates are collapsed.
func Check(content []byte) []string {
	triggered := make(map[string]struct{})

	for _, p := range patterns {
		if p.re.Match(content) {
			triggered[p.trigger] = struct{}{}
		}
	}

	// Token-heavy heuristic
	if len(content) > tokenHeavyThreshold {
		triggered["TOKEN_HEAVY_PROMPT"] = struct{}{}
	}

	// Fire MISSING_PERSONA only when no persona declaration is found.
	if !personaPattern.Match(content) {
		triggered["MISSING_PERSONA"] = struct{}{}
	}

	// NEGATIVE_ONLY_INSTRUCTION: fire when 4+ negative directives are present.
	if len(negOnlyRe.FindAll(content, -1)) >= negOnlyThreshold {
		triggered["NEGATIVE_ONLY_INSTRUCTION"] = struct{}{}
	}

	// MISSING_DELIMITER: fire when a user-input variable appears without a
	// structural delimiter (### or """) on the immediately preceding line.
	if hasUndelimitedInput(content) {
		triggered["MISSING_DELIMITER"] = struct{}{}
	}

	// MISSING_CRISIS_ESCALATION: fire when crisis keywords are present but no
	// escalation path (988, crisis line, etc.) is provided.
	if crisisRe.Match(content) && !escalationRe.Match(content) {
		triggered["MISSING_CRISIS_ESCALATION"] = struct{}{}
	}

	result := make([]string, 0, len(triggered))
	for name := range triggered {
		result = append(result, name)
	}
	return result
}

// hasUndelimitedInput returns true if any user-input template variable
// ({{.UserInput}}, {{.UserMessage}}, etc.) appears either:
//   - inline on a line with other text (always undelimited), or
//   - alone on a line that is NOT immediately preceded by a ### / """ marker.
func hasUndelimitedInput(content []byte) bool {
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		if !inlineVarRe.Match(line) {
			continue
		}
		// Variable embedded inline with other text → undelimited.
		if !delimVarRe.Match(line) {
			return true
		}
		// Variable is alone on its line; check the immediately preceding
		// non-empty line for a structural delimiter marker.
		precededByDelimiter := false
		for j := i - 1; j >= 0; j-- {
			if len(bytes.TrimSpace(lines[j])) == 0 {
				continue
			}
			if delimLineRe.Match(lines[j]) {
				precededByDelimiter = true
			}
			break
		}
		if !precededByDelimiter {
			return true
		}
	}
	return false
}
