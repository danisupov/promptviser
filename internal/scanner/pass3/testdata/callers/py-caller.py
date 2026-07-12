# Example Python caller file for pass3 AST testing.
# References a prompt file by name — findCallerFiles will detect this.
# TODO: AST visitor should flag f-string injection into prompt templates.

def load_prompt():
    with open("prompts/crisis-support.yaml") as f:
        return f.read()
