from .classifier import ChunkType
from .chunker import Chunk

def format_chunk(chunk: Chunk, chunk_type: ChunkType) -> str:
    """Applies Markdown formatting to a chunk based on its type."""
    text = chunk.text
    if chunk_type == ChunkType.HEADING:
        # Title case and make it an H2
        return f"## {text.title()}"
        
    elif chunk_type == ChunkType.BULLET_LIST:
        lines = text.split('\n')
        formatted_lines = []
        for line in lines:
            if not line.strip().startswith(('-', '*', '1.', '2.', '3.')):
                formatted_lines.append(f"- {line.strip().capitalize()}")
            else:
                formatted_lines.append(line.strip())
        return "\n".join(formatted_lines)
            
    elif chunk_type == ChunkType.CODE:
        # Defaulting to python for MVP
        return f"```python\n{text}\n```"

    elif chunk_type == ChunkType.TABLE:
        # Tables extracted from ingestor (like pandas) will come pre-formatted as markdown tables
        # if we do `df.to_markdown()` but let's just return the raw text since we will format it there
        return text
        
    else:
        # Paragraph formatting
        formatted = text.strip()
        if not formatted:
            return ""
        formatted = formatted[0].upper() + formatted[1:]
        if not formatted.endswith(('.', '!', '?')):
            formatted += '.'
        return formatted
