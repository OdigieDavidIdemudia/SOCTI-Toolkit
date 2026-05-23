from .classifier import ChunkType

def format_chunk(chunk: str, chunk_type: ChunkType) -> str:
    """Applies Markdown formatting to a chunk based on its type."""
    if chunk_type == ChunkType.HEADING:
        # Title case and make it an H2
        return f"## {chunk.title()}"
        
    elif chunk_type == ChunkType.BULLET_LIST:
        lines = chunk.split('\n')
        formatted_lines = []
        for line in lines:
            if not line.strip().startswith(('-', '*', '1.', '2.', '3.')):
                formatted_lines.append(f"- {line.strip().capitalize()}")
            else:
                formatted_lines.append(line.strip())
        return "\n".join(formatted_lines)
            
    elif chunk_type == ChunkType.CODE:
        # Defaulting to python for MVP
        return f"```python\n{chunk}\n```"
        
    else:
        # Paragraph formatting
        formatted = chunk.strip()
        if not formatted:
            return ""
        formatted = formatted[0].upper() + formatted[1:]
        if not formatted.endswith(('.', '!', '?')):
            formatted += '.'
        return formatted
