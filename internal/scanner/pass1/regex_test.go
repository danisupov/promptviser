package pass1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_regex(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "No triggers",
			content: `
				You are a simple assistant.
				This is a simple prompt file with no issues.
				It contains static text and no variables.
			`,
			expected: nil,
		},
		{
			name: "Missing delimiter",
			content: `
				You are a test assistant.
				Write a response to the following user input:
				{{.UserInput}}
			`,
			expected: []string{"MISSING_DELIMITER"},
		},
		{
			name: "Token-heavy prompt",
			content: `
				You are a test assistant.
				This prompt is very long and contains many tokens. ` + strings.Repeat("Lorem ipsum dolor sit amet, ", 1000),
			expected: []string{"TOKEN_HEAVY_PROMPT"},
		},
		{
			name: "Missing persona",
			content: `
				{{define "main"}}
				Helpful assistant.
				{{end}}
			`,
			expected: []string{"MISSING_PERSONA"},
		},
		{
			name: "No missing persona",
			content: `
				You are a helpful assistant. {{define "main"}} Please answer the user's question. {{end}}
			`,
			expected: []string{},
		},
		{
			name: "Missing crisis escalation",
			content: `
				The user is in a crisis and needs support.
				Provide calm, compassionate guidance.
			`,
			expected: []string{"MISSING_PERSONA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			triggers := Check([]byte(tt.content))
			assert.ElementsMatch(t, tt.expected, triggers)
		})
	}
}
