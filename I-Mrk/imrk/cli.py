import typer
from rich.console import Console
from rich.markdown import Markdown
from pathlib import Path
from .chunker import chunk_text
from .classifier import classify_chunk
from .formatter import format_chunk
from .renderer import assemble_document
from .exporter import export_markdown
from .llm import enhance_with_llm

app = typer.Typer(help="I-Mrk: A Markdown document generator from raw text.")
console = Console()

@app.command()
def mdify(
    input_path: str = typer.Argument(..., help="Path to input text file"),
    output_path: str = typer.Argument(..., help="Path to output markdown file"),
    mode: str = typer.Option("documentation", "--mode", help="Output mode: notes, meeting, documentation, blog"),
    llm: bool = typer.Option(False, "--llm", help="Use LLM to enhance formatting")
):
    """Converts a raw text file into structured Markdown."""
    from .ingestor import DocumentIngestor
    
    input_file = Path(input_path)
    if not input_file.exists():
        console.print(f"[bold red]Error:[/] Input file '{input_path}' not found.")
        raise typer.Exit(code=1)
        
    console.print(f"[bold green]Ingesting {input_file.suffix} file...[/]")
    try:
        ingested_data = DocumentIngestor.ingest(input_file)
    except Exception as e:
        console.print(f"[bold red]Error parsing file:[/] {e}")
        raise typer.Exit(code=1)
    
    if llm:
        raw_text = "\n\n".join([c.text for c in ingested_data]) if isinstance(ingested_data, list) else ingested_data
        console.print("[cyan]Applying LLM enrichment (this may take a moment)...[/]")
        enhanced = enhance_with_llm(raw_text, mode)
        if enhanced:
            export_markdown(enhanced, output_path)
            console.print(f"[bold green]Success![/] LLM output saved to {output_path}")
            return
            
    # Standard rule-based pipeline
    chunks = chunk_text(ingested_data, method="paragraph")
    formatted_chunks = []
    
    for chunk in chunks:
        ctype = classify_chunk(chunk)
        fchunk = format_chunk(chunk, ctype)
        formatted_chunks.append(fchunk)
        
    final_md = assemble_document(formatted_chunks)
    export_markdown(final_md, output_path)
    
    console.print(f"[bold green]Success![/] Saved structured markdown to {output_path}")

if __name__ == "__main__":
    app()
