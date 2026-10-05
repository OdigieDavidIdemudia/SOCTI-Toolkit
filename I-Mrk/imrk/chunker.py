import re
from typing import List, Optional, Union
from dataclasses import dataclass

@dataclass
class Chunk:
    text: str
    hint: Optional[str] = None

def chunk_text(text_or_chunks: Union[str, List[Chunk]], method: str = "paragraph") -> List[Chunk]:
    """Splits raw text into chunks or passes through pre-chunked objects."""
    if isinstance(text_or_chunks, list):
        return text_or_chunks
        
    text = text_or_chunks
    if method == "paragraph":
        # Split by double newline (or more)
        raw_chunks = re.split(r'\n\s*\n', text.strip())
    elif method == "newline":
        # Split by any newline
        raw_chunks = text.strip().split('\n')
    else:
        # Default to paragraph
        raw_chunks = re.split(r'\n\s*\n', text.strip())
    
    return [Chunk(text=c.strip()) for c in raw_chunks if c.strip()]
