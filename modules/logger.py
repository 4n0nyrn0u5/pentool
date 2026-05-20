"""
Markazlashtirilgan log moduli.
"""
from rich.console import Console

_console = Console(stderr=False)

class Logger:
    def info(self, msg):
        _console.print(f"[bold yellow][*][/bold yellow] {msg}")

    def success(self, msg):
        _console.print(f"[bold green][+][/bold green] {msg}")

    def warn(self, msg):
        _console.print(f"[yellow][!][/yellow] {msg}")

    def error(self, msg):
        _console.print(f"[bold red][✗][/bold red] {msg}")

    def debug(self, msg):
        _console.print(f"[dim][d] {msg}[/dim]")

    def vuln(self, severity: str, msg: str):
        colors = {
            "critical": "bold red",
            "high"    : "red",
            "medium"  : "yellow",
            "low"     : "blue",
            "info"    : "dim",
        }
        c = colors.get(severity.lower(), "white")
        _console.print(f"  [{c}][{severity.upper()}][/{c}] {msg}")


log = Logger()
