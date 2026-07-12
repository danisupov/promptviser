package pass3

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// CallerFile is a source code file that was found to reference a prompt file.
type CallerFile struct {
	// Path is the project-relative or absolute path to the source file.
	Path string
	// Content is the raw file content.
	Content []byte
}

// Analyze dispatches to language-specific visitors for each caller file and
// returns deduplicated static trigger names to feed into the rule engine.
// Callers with different extensions run independent visitors; triggers from all
// callers are merged into a single de-duped result.
func Analyze(callers []CallerFile) []string {
	seen := make(map[string]struct{})
	for _, f := range callers {
		var triggers []string
		switch strings.ToLower(filepath.Ext(f.Path)) {
		case ".go":
			triggers = analyzeGo(f.Content)
		case ".py":
			triggers = analyzePython(f.Content)
		case ".js", ".ts":
			triggers = analyzeJS(f.Content)
		}
		for _, t := range triggers {
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for t := range seen {
		result = append(result, t)
	}
	return result
}

// =============================================================================
// Go visitor
// =============================================================================

// goSimplePattern maps a compiled regex to the trigger it fires when found
// anywhere in the file — same structure as pass1 patterns.
type goSimplePattern struct {
	re      *regexp.Regexp
	trigger string
}

// goSimplePatterns are checked against the full file content.
var goSimplePatterns = []goSimplePattern{
	// Model identity: which LLM client / model string is referenced.
	// No rule fires on LLM_MODEL_DETECTED today; it is recorded for future
	// model-suggestion rules (e.g. "switch from gpt-3.5 to gpt-4o-mini").
	{regexp.MustCompile(`(?i)\b(?:openai\.NewClient|anthropic\.NewClient|genai\.NewClient|ollama\.New)\b`), "LLM_MODEL_DETECTED"},
	{regexp.MustCompile(`"(?:gpt-4|gpt-3\.5|claude-|gemini-|llama|mistral)[^"]*"`), "LLM_MODEL_DETECTED"},
}

// llmCallRe matches a method call that looks like an LLM completion/chat site.
var llmCallRe = regexp.MustCompile(
	`(?i)\.(?:Complete|Chat|Generate|Invoke|CreateChatCompletion|CreateCompletion|ChatCompletion)\s*\(`)

// httpWriteRe matches writes to an HTTP response writer.
var httpWriteRe = regexp.MustCompile(
	`(?i)(?:\.Write\s*\(|\.WriteString\s*\(|fmt\.Fprintf\s*\(\s*\w|http\.Error\s*\()`)

// dbWriteRe matches writes to a SQL database.
var dbWriteRe = regexp.MustCompile(
	`(?i)(?:db\.Exec\b|db\.ExecContext\b|db\.Query\b|db\.QueryContext\b|db\.Prepare\b|tx\.Exec\b|tx\.Query\b)`)

// httpInputRe matches reads of user-controlled HTTP request data.
var httpInputRe = regexp.MustCompile(
	`(?i)(?:r\.FormValue\s*\(|r\.PostFormValue\s*\(|r\.URL\.Query\(\)|r\.Body\b|r\.PathValue\s*\()`)

// promptInsertRe matches substitution of a value into a prompt template string.
var promptInsertRe = regexp.MustCompile(
	`(?i)(?:strings\.Replace\s*\(|strings\.NewReplacer\s*\(|fmt\.Sprintf\s*\(|tmpl\.Execute\s*\()`)

// goroutineRe matches a goroutine launch site.
var goroutineRe = regexp.MustCompile(`\bgo\s+func\s*\(`)

// contextTimeoutRe matches any timeout / deadline setup.
var contextTimeoutRe = regexp.MustCompile(
	`(?i)(?:context\.WithTimeout\b|context\.WithDeadline\b|time\.After\b|time\.NewTimer\b)`)

// analyzeGo runs all Go-specific patterns against a single .go file.
func analyzeGo(content []byte) []string {
	seen := make(map[string]struct{})

	// 1. Simple whole-file patterns (model identity, etc.)
	for _, p := range goSimplePatterns {
		if p.re.Match(content) {
			seen[p.trigger] = struct{}{}
		}
	}

	lines := bytes.Split(content, []byte("\n"))

	// 2. LLM output written directly to HTTP response — SEC-004 (UNSANITIZED_OUTPUT).
	//    Fires when an LLM call is followed by an HTTP write within 8 lines.
	if windowContainsBoth(lines, llmCallRe, httpWriteRe, 8) {
		seen["UNSANITIZED_OUTPUT"] = struct{}{}
	}

	// 3. User HTTP input flowing into a prompt template — SEC-001 (MISSING_DELIMITER).
	//    Fires when HTTP input reading is followed by a prompt-string insertion within 10 lines.
	if windowContainsBoth(lines, httpInputRe, promptInsertRe, 10) {
		seen["MISSING_DELIMITER"] = struct{}{}
	}

	// 4. LLM output written directly to a database — OUTPUT_TO_DB_OR_FILE (ACC-004).
	//    Fires when an LLM call is followed by a DB write within 8 lines.
	if windowContainsBoth(lines, llmCallRe, dbWriteRe, 8) {
		seen["OUTPUT_TO_DB_OR_FILE"] = struct{}{}
	}

	// 5. LLM call in a goroutine with no timeout — AGENTIC_LOOP_NO_TERMINATION (REL-006).
	if detectLLMGoroutineNoTimeout(content) {
		seen["AGENTIC_LOOP_NO_TERMINATION"] = struct{}{}
	}

	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for t := range seen {
		result = append(result, t)
	}
	return result
}

// windowContainsBoth returns true when sinkRe is found within window lines
// after any line matching sourceRe.  The search is directional: it always
// looks forward (source before sink), matching typical top-down data flow.
func windowContainsBoth(lines [][]byte, sourceRe, sinkRe *regexp.Regexp, window int) bool {
	for i, line := range lines {
		if !sourceRe.Match(line) {
			continue
		}
		end := i + 1 + window
		if end > len(lines) {
			end = len(lines)
		}
		for _, candidate := range lines[i+1 : end] {
			if sinkRe.Match(candidate) {
				return true
			}
		}
	}
	return false
}

// detectLLMGoroutineNoTimeout fires when a file launches a goroutine that
// contains an LLM call but has no context timeout or deadline anywhere in the
// file.  This is a file-level heuristic rather than scope-aware analysis.
func detectLLMGoroutineNoTimeout(content []byte) bool {
	return goroutineRe.Match(content) &&
		llmCallRe.Match(content) &&
		!contextTimeoutRe.Match(content)
}

// =============================================================================
// Python visitor (stub — patterns to be added)
// =============================================================================

// analyzePython will detect Python-specific patterns, for example:
//   - f-string injection:          f"You are helpful. {user_input}"
//   - response → cursor.execute:   cursor.execute(f"INSERT ... {llm_response}")
//   - response → flask response:   return llm_response  (in a Flask route)
func analyzePython(_ []byte) []string {
	return nil
}

// =============================================================================
// JavaScript / TypeScript visitor (stub — patterns to be added)
// =============================================================================

// analyzeJS will detect JS/TS-specific patterns, for example:
//   - template literal injection:  `You are helpful. ${userInput}`
//   - LLM response → innerHTML:    element.innerHTML = llmResponse
//   - LLM response → db.query:     db.query(`INSERT ... ${llmResponse}`)
func analyzeJS(_ []byte) []string {
	return nil
}
