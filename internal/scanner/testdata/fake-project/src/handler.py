def load_crisis_support_prompt() -> str:
    """Load the crisis-support system prompt from disk."""
    with open("prompts/crisis-support.yaml") as f:
        return f.read()
