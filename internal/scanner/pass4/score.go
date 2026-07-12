package pass4

import (
	"bytes"
	"context"
	"strings"
	"text/template"

	pb "github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/llm"
)

// userMsgTmpl is compiled once from llm.UserMessageTemplate at package init.
// llm.init() is guaranteed to run before pass3.init() since pass3 imports llm.
var userMsgTmpl *template.Template

func init() {
	userMsgTmpl = template.Must(template.New("user_msg").Parse(llm.UserMessageTemplate))
}

// Score calls the LLM provider with the prompt content and pre-computed signals
// from pass1 and pass2, returning dimension scores in [0, 1].
// The prompt text is sent to the LLM configured by the user — it is NOT
// forwarded to the promptviser server.
func Score(ctx context.Context, content []byte, staticTriggers, metadataFlags []string, provider llm.Provider) ([]*pb.DimensionScore, error) {
	userMsg := buildUserMessage(content, staticTriggers, metadataFlags)
	return provider.Score(ctx, []byte(userMsg))
}

// buildUserMessage renders the user_message_template from score_prompt.yaml.
// Structure (delimiters, signals section) lives in the YAML, not in Go code.
func buildUserMessage(content []byte, staticTriggers, metadataFlags []string) string {
	var buf bytes.Buffer
	err := userMsgTmpl.Execute(&buf, struct {
		UserPrompt     string
		StaticTriggers string
		MetadataFlags  string
	}{
		UserPrompt:     string(content),
		StaticTriggers: strings.Join(staticTriggers, ", "),
		MetadataFlags:  strings.Join(metadataFlags, ", "),
	})
	if err != nil {
		// template execution should never fail with well-formed YAML;
		// fall back to raw content so scanning can still proceed.
		return string(content)
	}
	return buf.String()
}
