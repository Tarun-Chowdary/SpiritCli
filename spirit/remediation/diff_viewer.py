import difflib
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

class DiffViewer:
    
    def show(self, original, modified, filepath):
        """
        Show a colored before/after diff in terminal
        """
        original_lines = original.splitlines(keepends=True)
        modified_lines = modified.splitlines(keepends=True)
        
        diff = list(difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"before/{filepath}",
            tofile=f"after/{filepath}",
            lineterm=""
        ))
        
        if not diff:
            return
        
        diff_text = Text()
        
        for line in diff:
            if line.startswith("+++") or line.startswith("---"):
                diff_text.append(line + "\n", style="bold cyan")
            elif line.startswith("@@"):
                diff_text.append(line + "\n", style="bold magenta")
            elif line.startswith("+"):
                diff_text.append(line + "\n", style="bold green")
            elif line.startswith("-"):
                diff_text.append(line + "\n", style="bold red")
            else:
                diff_text.append(line + "\n", style="dim")
        
        console.print(Panel(
            diff_text,
            title=f"[cyan]Diff — {filepath}[/cyan]",
            border_style="cyan"
        ))
    
    def get_diff_lines(self, original, modified):
        """Returns list of diff lines for programmatic use"""
        original_lines = original.splitlines(keepends=True)
        modified_lines = modified.splitlines(keepends=True)
        
        return list(difflib.unified_diff(
            original_lines,
            modified_lines,
            lineterm=""
        ))