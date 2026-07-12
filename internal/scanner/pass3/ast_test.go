package pass3

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Analyze dispatch tests
// =============================================================================

func Test_Analyze_NoCallers(t *testing.T) {
	assert.Empty(t, Analyze(nil))
	assert.Empty(t, Analyze([]CallerFile{}))
}

func Test_Analyze_DispatchByExtension(t *testing.T) {
	// Only .go files run the Go visitor; .py and .js are stubbed.
	// This snippet triggers UNSANITIZED_OUTPUT in Go.
	goSrc := []byte("resp := llmClient.Complete(prompt)\nw.Write([]byte(resp))")
	assert.Contains(t, Analyze([]CallerFile{{Path: "main.go", Content: goSrc}}), "UNSANITIZED_OUTPUT")
	assert.Empty(t, Analyze([]CallerFile{{Path: "main.py", Content: goSrc}}))
	assert.Empty(t, Analyze([]CallerFile{{Path: "main.js", Content: goSrc}}))
}

func Test_Analyze_DeduplicatesAcrossCallers(t *testing.T) {
	// Two different Go files that both trigger UNSANITIZED_OUTPUT → only one entry.
	src := []byte("resp := llmClient.Complete(prompt)\nw.Write([]byte(resp))")
	result := Analyze([]CallerFile{
		{Path: "a.go", Content: src},
		{Path: "b.go", Content: src},
	})
	count := 0
	for _, t := range result {
		if t == "UNSANITIZED_OUTPUT" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate triggers should be collapsed")
}

// =============================================================================
// Go visitor — individual pattern tests
// =============================================================================

func Test_analyzeGo_UnsanitizedOutput(t *testing.T) {
	src := []byte(`package main

func handler(w http.ResponseWriter, r *http.Request) {
	resp := llmClient.Complete(prompt)
	w.Write([]byte(resp))
}`)
	assert.Contains(t, analyzeGo(src), "UNSANITIZED_OUTPUT")
}

func Test_analyzeGo_UnsanitizedOutput_FmtFprintf(t *testing.T) {
	// fmt.Fprintf variant
	src := []byte(`func h(w http.ResponseWriter, r *http.Request) {
	text := client.CreateChatCompletion(ctx, req)
	fmt.Fprintf(w, "%s", text)
}`)
	assert.Contains(t, analyzeGo(src), "UNSANITIZED_OUTPUT")
}

func Test_analyzeGo_UserInputToPrompt(t *testing.T) {
	src := []byte(`func handler(w http.ResponseWriter, r *http.Request) {
	userMsg := r.FormValue("message")
	prompt := strings.Replace(template, "{{.UserInput}}", userMsg, 1)
}`)
	assert.Contains(t, analyzeGo(src), "MISSING_DELIMITER")
}

func Test_analyzeGo_UserInputToPrompt_Sprintf(t *testing.T) {
	src := []byte(`func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prompt := fmt.Sprintf("Answer: %s", q.Get("q"))
}`)
	assert.Contains(t, analyzeGo(src), "MISSING_DELIMITER")
}

func Test_analyzeGo_LLMOutputToDB(t *testing.T) {
	src := []byte(`func processDecision(ctx context.Context) {
	result := llmClient.Complete(prompt)
	db.Exec("INSERT INTO decisions VALUES (?)", result)
}`)
	assert.Contains(t, analyzeGo(src), "OUTPUT_TO_DB_OR_FILE")
}

func Test_analyzeGo_LLMOutputToDB_ExecContext(t *testing.T) {
	src := []byte(`func save(ctx context.Context) {
	answer := client.Chat(ctx, messages)
	db.ExecContext(ctx, "INSERT INTO answers(body) VALUES(?)", answer)
}`)
	assert.Contains(t, analyzeGo(src), "OUTPUT_TO_DB_OR_FILE")
}

func Test_analyzeGo_ModelIdentity_ClientConstructor(t *testing.T) {
	src := []byte(`client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))`)
	assert.Contains(t, analyzeGo(src), "LLM_MODEL_DETECTED")
}

func Test_analyzeGo_ModelIdentity_StringLiteral(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"gpt-4o", `model := "gpt-4o"`},
		{"gpt-3.5-turbo", `model := "gpt-3.5-turbo"`},
		{"claude-3", `model := "claude-3-haiku-20240307"`},
		{"gemini-pro", `model := "gemini-pro"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, analyzeGo([]byte(tt.src)), "LLM_MODEL_DETECTED")
		})
	}
}

func Test_analyzeGo_GoroutineNoTimeout(t *testing.T) {
	src := []byte(`func run() {
	go func() {
		resp := llmClient.Complete(prompt)
		_ = resp
	}()
}`)
	assert.Contains(t, analyzeGo(src), "AGENTIC_LOOP_NO_TERMINATION")
}

func Test_analyzeGo_GoroutineWithTimeout_NoTrigger(t *testing.T) {
	// context.WithTimeout present — should NOT fire.
	src := []byte(`func run() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		resp := llmClient.Complete(ctx, prompt)
		_ = resp
	}()
}`)
	assert.NotContains(t, analyzeGo(src), "AGENTIC_LOOP_NO_TERMINATION")
}

func Test_analyzeGo_CleanCode_NoTriggers(t *testing.T) {
	// No LLM calls, no HTTP input, no goroutines, no model strings.
	src := []byte(`package main

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}`)
	assert.Empty(t, analyzeGo(src))
}

// =============================================================================
// windowContainsBoth unit tests
// =============================================================================

func Test_windowContainsBoth_FoundWithinWindow(t *testing.T) {
	lines := [][]byte{
		[]byte("result := llmClient.Complete(prompt)"),
		[]byte("// log response"),
		[]byte("w.Write([]byte(result))"),
	}
	src := regexp.MustCompile(`Complete\(`)
	sink := regexp.MustCompile(`\.Write\(`)

	assert.True(t, windowContainsBoth(lines, src, sink, 5))
}

func Test_windowContainsBoth_WindowTooSmall(t *testing.T) {
	lines := [][]byte{
		[]byte("result := llmClient.Complete(prompt)"),
		[]byte("// log response"),
		[]byte("w.Write([]byte(result))"),
	}
	src := regexp.MustCompile(`Complete\(`)
	sink := regexp.MustCompile(`\.Write\(`)

	// window=1 only looks 1 line ahead — sink is 2 lines down, so not found.
	assert.False(t, windowContainsBoth(lines, src, sink, 1))
}

func Test_windowContainsBoth_SinkBeforeSource_NoTrigger(t *testing.T) {
	// sink appears BEFORE source — should not fire (directional check).
	lines := [][]byte{
		[]byte("w.Write([]byte(result))"),
		[]byte("result := llmClient.Complete(prompt)"),
	}
	src := regexp.MustCompile(`Complete\(`)
	sink := regexp.MustCompile(`\.Write\(`)
	assert.False(t, windowContainsBoth(lines, src, sink, 5))
}

func Test_windowContainsBoth_Empty(t *testing.T) {
	src := regexp.MustCompile(`Complete\(`)
	sink := regexp.MustCompile(`\.Write\(`)
	assert.False(t, windowContainsBoth(nil, src, sink, 5))
	assert.False(t, windowContainsBoth([][]byte{}, src, sink, 5))
}

// =============================================================================
// Testdata-based smoke tests
// =============================================================================

func Test_Analyze_FromTestdata(t *testing.T) {
	// The testdata caller files are intentionally clean — no patterns triggered.
	paths := []string{
		"testdata/callers/go-caller.go",
		"testdata/callers/py-caller.py",
		"testdata/callers/js-caller.js",
	}
	callers := make([]CallerFile, 0, len(paths))
	for _, p := range paths {
		content, err := os.ReadFile(p)
		require.NoError(t, err, "missing testdata file: %s", p)
		callers = append(callers, CallerFile{Path: p, Content: content})
	}
	assert.Empty(t, Analyze(callers))
}

func Test_Analyze_SingleCaller(t *testing.T) {
	tests := []struct{ name, path string }{
		{"Go caller", "testdata/callers/go-caller.go"},
		{"Python caller", "testdata/callers/py-caller.py"},
		{"JavaScript caller", "testdata/callers/js-caller.js"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(tt.path)
			require.NoError(t, err)
			assert.Empty(t, Analyze([]CallerFile{{Path: tt.path, Content: content}}))
		})
	}
}
