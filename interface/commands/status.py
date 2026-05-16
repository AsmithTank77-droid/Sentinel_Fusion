"""
interface/commands/status.py — sentinel status
"""

from __future__ import annotations

import typer

from interface._state import get_db
from interface.output import (
    console,
    int_severity_color,
    make_table,
    severity_badge,
    status_badge,
)
from storage.store import StorageLayer

app = typer.Typer(help="Show platform health and statistics.")


@app.callback(invoke_without_command=True)
def status() -> None:
    """Display event, alert, case, and run counts plus top risk hosts."""
    with StorageLayer(get_db()) as store:
        s = store.summary()

    # ── Counts panel ──────────────────────────────────────────────────────────
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.text import Text

    stats = [
        Panel(f"[bold cyan]{s['total_events']:,}[/bold cyan]\n[dim]Events[/dim]",    expand=True),
        Panel(f"[bold red]{s['total_alerts']:,}[/bold red]\n[dim]Alerts[/dim]",      expand=True),
        Panel(f"[bold yellow]{s['total_cases']:,}[/bold yellow]\n[dim]Cases[/dim]",  expand=True),
        Panel(f"[bold green]{s['total_runs']:,}[/bold green]\n[dim]Runs[/dim]",      expand=True),
    ]
    console.print(Columns(stats))

    # ── Alert status breakdown ────────────────────────────────────────────────
    if s["alerts_by_status"]:
        tbl = make_table("Alert Status", ("Status", None), ("Count", "right"))
        for stat, count in sorted(s["alerts_by_status"].items()):
            tbl.add_row(status_badge(stat), str(count))
        console.print(tbl)

    # ── Top risk hosts ────────────────────────────────────────────────────────
    if s["top_risk_hosts"]:
        tbl = make_table(
            "Top Risk Hosts",
            ("Host", None),
            ("Score", "right"),
            ("Label", None),
            ("Scored At", None),
        )
        for h in s["top_risk_hosts"]:
            tbl.add_row(
                h["target"],
                f"[{int_severity_color(int(h['score']))}]{h['score']:.2f}[/]",
                severity_badge(h["label"]),
                h.get("scored_at", "—"),
            )
        console.print(tbl)
