"""
interface/commands/runs.py — sentinel runs / get
"""

from __future__ import annotations

import typer

from interface._state import get_db
from interface.output import console, error, kv_panel, make_table, status_badge
from storage.store import StorageLayer

app = typer.Typer(help="Inspect pipeline run history.")


@app.callback(invoke_without_command=True)
def runs_list(
    ctx:   typer.Context,
    limit: int = typer.Option(20, "--limit", "-n", help="Max runs to show."),
) -> None:
    """List recent pipeline runs, newest first."""
    if ctx.invoked_subcommand:
        return

    with StorageLayer(get_db()) as store:
        rows = store.audit.get_recent_runs(limit=limit)

    if not rows:
        console.print("[dim]No pipeline runs recorded yet.[/dim]")
        return

    tbl = make_table(
        f"Pipeline Runs ({len(rows)})",
        ("Run ID",      None),
        ("Status",      None),
        ("Events",      "right"),
        ("Alerts",      "right"),
        ("Started At",  None),
        ("Completed At",None),
    )
    for r in rows:
        tbl.add_row(
            r.run_id,
            status_badge(r.status),
            str(r.event_count),
            str(r.alert_count),
            r.started_at[:19],
            r.completed_at[:19] if r.completed_at else "—",
        )
    console.print(tbl)


@app.command("get")
def get_run(run_id: str = typer.Argument(..., help="Pipeline run ID (e.g. run-20260510T...)")) -> None:
    """Show details and audit log for a specific pipeline run."""
    with StorageLayer(get_db()) as store:
        run  = store.audit.get_run(run_id)
        log  = store.audit.get_run_log(run_id) if run else []
        evts = store.events.count_by_run(run_id) if run else 0

    if run is None:
        error(f"Run '{run_id}' not found.")
        raise typer.Exit(1)

    items = {
        "Run ID":       run.run_id,
        "Status":       run.status,
        "Event Count":  str(run.event_count),
        "Alert Count":  str(run.alert_count),
        "Started At":   run.started_at,
        "Completed At": run.completed_at or "—",
    }
    console.print(kv_panel(run.run_id, items))

    if log:
        console.print()
        tbl = make_table(
            "Audit Log",
            ("Stage",  None),
            ("Action", None),
            ("Detail", None),
            ("Time",   None),
        )
        for entry in log:
            tbl.add_row(
                entry.stage,
                entry.action,
                entry.detail or "—",
                entry.created_at[:19],
            )
        console.print(tbl)
