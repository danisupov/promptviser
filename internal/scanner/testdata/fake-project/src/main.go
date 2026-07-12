package main

import "os"

// LoadPatientIntakePrompt reads the patient intake system prompt from disk.
// The prompt path is hardcoded here as a representative example of a
// caller that will be detected by the AST scanning pass.
func LoadPatientIntakePrompt() ([]byte, error) {
	return os.ReadFile("prompts/patient-intake.yaml")
}
