package callers

import "os"

// Example Go caller file for pass3 AST testing.
// References a prompt file by name — findCallerFiles will detect this.

// LoadPrompt loads the named prompt file.
// TODO: AST visitor should flag unsafe string concatenation into prompt templates.
func LoadPrompt() ([]byte, error) {
	return os.ReadFile("prompts/patient-intake.yaml")
}
