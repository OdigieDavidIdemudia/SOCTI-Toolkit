from typing import List

def assemble_document(formatted_chunks: List[str]) -> str:
    """Assembles individual Markdown chunks into a final document."""
    # Ensure chunks have space between them
    return "\n\n".join(formatted_chunks)
