import g4f

def enhance_with_llm(text: str, mode: str = "notes") -> str:
    """Uses a free LLM provider (g4f) to enrich the text structure."""
    prompt = f"Convert this text into clean markdown using headings, bullets, code blocks, and structure. Mode: {mode}. Ensure the output is strictly markdown.\n\n{text}"
    
    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_35_turbo,
            messages=[{"role": "user", "content": prompt}]
        )
        return response
    except Exception as e:
        print(f"LLM Enrichment Failed: {e}. Falling back to rule-based formatter.")
        return ""
