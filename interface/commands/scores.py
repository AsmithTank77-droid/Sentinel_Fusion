"""
interface/commands/scores.py — sentinel scores
"""

from __future__ import annotations

from typing import Optional

import typer

from interface._state import get_db
from interface.output import console, int_severity_color, make_table, severity_badge
from storage.store import StorageLayer

app = typer.Typer(help="View host risk and attack surface scores.")


@app.callback(invoke_without_command=True)
def scores(
    ctx:  typer.Context,
    host: Optional[str] = typer.Option(None, "--host", "-h", help="Show score history for a specific host IP."),
    atk:  bool          = typer.Option(False, "--attack-surface", "-a", help="Show attack surface history instead."),
    limit: int          = typer.Option(30, "--limit", "-n", help="Max rows."),
) -> None:
    """Display the latest host risk scores, or history for a specific host."""
    if ctx.invoked_subcommand:
        return

    with StorageLayer(get_db()) as store:
        if atk:
            rows = store.scores.get_attack_surface_history(limit=limit)
            title = "Attack Surface History"
        elif host:
            rows = store.scores.get_host_history(host, limit=limit)
            title = f"Score History — {host}"
        else:
            rows = store.scores.get_latest_host_scores()
            title = "Host Risk Scores (Latest)"

    if not rows:
        console.print("[dim]No scores found.[/dim]")
        return

    tbl = make_table(
        title,
        ("Target",     None),
        ("Type",       None),
        ("Score",      "right"),
        ("Label",      None),
        ("Run ID",     None),
        ("Scored At",  None),
    )
    for s in rows:
        tbl.add_row(
            s.target,
            s.score_type,
            f"[{int_severity_color(int(s.score))}]{s.score:.2f}[/]",
            severity_badge(s.label),
            s.run_id,
            s.scored_at[:19],
        )
    console.print(tbl)
