from enum import Enum

class ChunkType(Enum):
    HEADING = "heading"
    BULLET_LIST = "bullet_list"
    CODE = "code"
    PARAGRAPH = "paragraph"

def classify_chunk(chunk: str) -> ChunkType:
    """Classifies a chunk of text to determine its structural type."""
    lines = chunk.split('\n')
    
    # 1. Code check: contains common programming keywords
    code_keywords = ['print(', 'def ', 'class ', 'import ', 'return ', 'console.log(', 'var ', 'let ', 'const ', 'function ']
    if any(keyword in chunk for keyword in code_keywords):
        return ChunkType.CODE

    # 2. Heading check: short text, single line
    if len(lines) == 1 and len(chunk) < 60 and not chunk.endswith('.'):
        # A simple check: if it looks like a sentence without a period, or just a few words
        if " is " not in chunk and " are " not in chunk:
            return ChunkType.HEADING
        
    # 3. List check: multiple lines starting with dash/star/number OR a comma separated string without verbs
    if len(lines) > 1 and all(line.strip().startswith(('-', '*', '1.', '2.', '3.')) for line in lines):
        return ChunkType.BULLET_LIST
        
    return ChunkType.PARAGRAPH
