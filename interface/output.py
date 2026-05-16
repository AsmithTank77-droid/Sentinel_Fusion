"""
interface/output.py — Shared Rich output helpers for all CLI commands.

All console output goes through this module to keep styling consistent.
Import `console` directly for one-off prints; use the helper functions
for structured tables and panels.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ── Color maps ────────────────────────────────────────────────────────────────

SEVERITY_COLOR: dict[str, str] = {
    "critical": "bold red",
    "high":     "dark_orange",
    "medium":   "yellow",
    "low":      "green",
    "unknown":  "dim",
}

STATUS_COLOR: dict[str, str] = {
    "open":          "red",
    "investigating":  "yellow",
    "contained":      "cyan",
    "closed":         "dim green",
    "running":        "blue",
    "completed":      "green",
    "failed":         "red",
}


# ── Formatters ────────────────────────────────────────────────────────────────

def severity_badge(value: str) -> Text:
    color = SEVERITY_COLOR.get(value.lower(), "dim")
    return Text(value.upper(), style=f"bold {color}")


def status_badge(value: str) -> Text:
    color = STATUS_COLOR.get(value.lower(), "dim")
    return Text(value, style=color)


def confidence_bar(score: float, width: int = 10) -> str:
    filled = round(score * width)
    empty  = width - filled
    return "█" * filled + "░" * empty + f"  {score:.2f}"


def int_severity_color(severity: int) -> str:
    if severity >= 8:
        return "bold red"
    if severity >= 6:
        return "dark_orange"
    if severity >= 4:
        return "yellow"
    return "green"


# ── Table builders ────────────────────────────────────────────────────────────

def make_table(title: str, *columns: tuple[str, str | None]) -> Table:
    """
    Create a Rich table with standard Sentinel Fusion styling.

    columns: sequence of (header, justify) pairs.
             justify defaults to "left" when None.
    """
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        header_style="bold bright_white",
        show_lines=False,
        title_style="bold cyan",
        title_justify="left",
    )
    for header, justify in columns:
        table.add_column(header, justify=justify or "left")
    return table


def error(msg: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {msg}")


def success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}")


def info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


def kv_panel(title: str, items: dict, style: str = "cyan") -> Panel:
    """Build a Panel from a flat key→value dict."""
    lines = "\n".join(
        f"[dim]{k:<22}[/dim] {v}" for k, v in items.items()
    )
    return Panel(lines, title=f"[bold]{title}[/bold]", border_style=style, expand=False)
