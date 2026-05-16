"""
interface/commands/events.py — sentinel events
"""

from __future__ import annotations

from typing import Optional

import typer

from interface._state import get_db
from interface.output import console, int_severity_color, make_table
from storage.store import StorageLayer

app = typer.Typer(help="Query stored normalized events.")


@app.callback(invoke_without_command=True)
def events(
    run_id:     Optional[str] = typer.Option(None, "--run-id",  "-r", help="Filter by pipeline run ID."),
    src_ip:     Optional[str] = typer.Option(None, "--src-ip",  "-s", help="Filter by source IP."),
    event_type: Optional[str] = typer.Option(None, "--type",    "-t", help="Filter by event type."),
    limit:      int           = typer.Option(50,   "--limit",   "-n", help="Max rows to display."),
) -> None:
    """
    List recent normalized events. Filters are evaluated in priority order:
    --run-id → --src-ip → --type → most recent N events.
    """
    with StorageLayer(get_db()) as store:
        if run_id:
            rows = store.events.get_by_run(run_id)
        elif src_ip:
            rows = store.events.get_by_src_ip(src_ip, limit=limit)
        elif event_type:
            rows = store.events.get_by_event_type(event_type, limit=limit)
        else:
            rows = store.events.get_recent(limit=limit)

    rows = rows[:limit]

    if not rows:
        console.print("[dim]No events found.[/dim]")
        return

    tbl = make_table(
        f"Events ({len(rows)})",
        ("ID",         "right"),
        ("Timestamp",  None),
        ("Type",       None),
        ("Source",     None),
        ("Src IP",     None),
        ("Dst IP",     None),
        ("Sev",        "right"),
        ("Run ID",     None),
    )

    for e in rows:
        tbl.add_row(
            str(e.id or "—"),
            e.timestamp[:19],
            e.event_type,
            e.source_type,
            e.src_ip,
            e.dst_ip,
            f"[{int_severity_color(e.severity)}]{e.severity}[/]",
            e.run_id,
        )

    console.print(tbl)
