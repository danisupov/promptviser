package pass4

import (
	"context"
	"os"
	"testing"

	"github.com/effective-security/promptviser/internal/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildUserMessage(t *testing.T) {
	content := []byte("What is the capital of France?")
	staticTriggers := []string{"MISSING_DELIMITER", "MISSING_PERSONA"}
	metadataFlags := []string{"is_user_facing"}

	data, err := os.ReadFile("testdata/expected_user_message.md")
	require.NoError(t, err)

	expected := string(data)
	result := buildUserMessage(content, staticTriggers, metadataFlags)
	assert.Equal(t, expected, result)
}

func Test_Score(t *testing.T) {
	ctx := context.Background()
	provider, err := llm.New(llm.LLMConfig{Provider: "stub"})
	require.NoError(t, err)

	scores, err := Score(ctx, []byte("You are helpful. User: {{.Input}}"), []string{"MISSING_DELIMITER"}, []string{"is_user_facing"}, provider)
	require.NoError(t, err)
	assert.Len(t, scores, 6)

	dims := make(map[string]float64, len(scores))
	for _, d := range scores {
		dims[d.Dimension] = float64(d.Score)
	}
	assert.Contains(t, dims, "pii_exposure")
	assert.Contains(t, dims, "human_oversight")
}
