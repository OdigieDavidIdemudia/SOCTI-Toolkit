from enum import Enum
from .chunker import Chunk

class ChunkType(Enum):
    HEADING = "heading"
    BULLET_LIST = "bullet_list"
    CODE = "code"
    PARAGRAPH = "paragraph"
    TABLE = "table"

def classify_chunk(chunk: Chunk) -> ChunkType:
    """Classifies a chunk of text to determine its structural type."""
    if chunk.hint:
        try:
            return ChunkType(chunk.hint.lower())
        except ValueError:
            pass # Fallback to heuristic if hint is unknown
            
    text = chunk.text
    lines = text.split('\n')
    
    # 1. Code check: contains common programming keywords
    code_keywords = ['print(', 'def ', 'class ', 'import ', 'return ', 'console.log(', 'var ', 'let ', 'const ', 'function ']
    if any(keyword in text for keyword in code_keywords):
        return ChunkType.CODE

    # 2. Heading check: short text, single line
    if len(lines) == 1 and len(text) < 60 and not text.endswith('.'):
        # A simple check: if it looks like a sentence without a period, or just a few words
        if " is " not in text and " are " not in text:
            return ChunkType.HEADING
        
    # 3. List check: multiple lines starting with dash/star/number OR a comma separated string without verbs
    if len(lines) > 1 and all(line.strip().startswith(('-', '*', '1.', '2.', '3.')) for line in lines):
        return ChunkType.BULLET_LIST
        
    return ChunkType.PARAGRAPH
