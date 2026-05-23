from pathlib import Path

def export_markdown(content: str, output_path: str):
    """Writes the markdown string to the specified file."""
    path = Path(output_path)
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
