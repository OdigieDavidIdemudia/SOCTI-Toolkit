import re
from typing import List

def chunk_text(text: str, method: str = "paragraph") -> List[str]:
    """Splits raw text into chunks based on the chosen method."""
    if method == "paragraph":
        # Split by double newline (or more)
        chunks = re.split(r'\n\s*\n', text.strip())
    elif method == "newline":
        # Split by any newline
        chunks = text.strip().split('\n')
    else:
        # Default to paragraph
        chunks = re.split(r'\n\s*\n', text.strip())
    
    return [c.strip() for c in chunks if c.strip()]
