"""
interface/commands/alerts.py — sentinel alerts / get / update
"""

from __future__ import annotations

import json
from typing import Optional

import typer

from interface._state import get_db
from interface.output import (
    confidence_bar,
    console,
    error,
    int_severity_color,
    kv_panel,
    make_table,
    severity_badge,
    status_badge,
    success,
)
from storage.models import ALERT_STATUSES
from storage.store import StorageLayer

app = typer.Typer(help="Query and manage detection alerts.")


def _row(a) -> tuple:
    return (
        str(a.id or "—"),
        a.alert_type,
        confidence_bar(a.confidence),
        a.src_ip,
        a.dst_ip,
        f"[{int_severity_color(a.severity)}]{a.severity}[/]",
        a.mitre_tactic,
        status_badge(a.status),
        a.created_at[:10],
    )


@app.callback(invoke_without_command=True)
def alerts_list(
    ctx:            typer.Context = typer.Context,
    alert_status:   Optional[str] = typer.Option(None, "--status", "-s", help="Filter: open|investigating|contained|closed"),
    min_confidence: float         = typer.Option(0.0,  "--confidence", "-c", help="Minimum confidence (0.0–1.0)"),
    limit:          int           = typer.Option(50,   "--limit", "-n", help="Max rows"),
) -> None:
    """List alerts, newest first. Filter by status and/or minimum confidence."""
    if ctx.invoked_subcommand:
        return

    with StorageLayer(get_db()) as store:
        if alert_status:
            try:
                rows = store.alerts.get_by_status(alert_status)
            except ValueError as exc:
                error(str(exc))
                raise typer.Exit(1)
        else:
            rows = store.alerts.get_recent(limit=limit)

    if min_confidence > 0:
        rows = [r for r in rows if r.confidence >= min_confidence]
    rows = rows[:limit]

    if not rows:
        console.print("[dim]No alerts found.[/dim]")
        return

    tbl = make_table(
        f"Alerts ({len(rows)})",
        ("ID",         "right"),
        ("Type",       None),
        ("Confidence", None),
        ("Src IP",     None),
        ("Dst IP",     None),
        ("Sev",        "right"),
        ("MITRE",      None),
        ("Status",     None),
        ("Date",       None),
    )
    for a in rows:
        tbl.add_row(*_row(a))
    console.print(tbl)


@app.command("get")
def get_alert(alert_id: int = typer.Argument(..., help="Alert database ID")) -> None:
    """Show full details for a single alert."""
    with StorageLayer(get_db()) as store:
        a = store.alerts.get_by_id(alert_id)

    if a is None:
        error(f"Alert {alert_id} not found.")
        raise typer.Exit(1)

    items = {
        "ID":           str(a.id),
        "Hash":         a.alert_hash,
        "Run ID":       a.run_id,
        "Type":         a.alert_type,
        "Status":       a.status,
        "Confidence":   confidence_bar(a.confidence),
        "Src IP":       a.src_ip,
        "Dst IP":       a.dst_ip,
        "Severity":     str(a.severity),
        "MITRE Tactic": a.mitre_tactic,
        "Created At":   a.created_at,
        "Updated At":   a.updated_at,
    }
    console.print(kv_panel(f"Alert {alert_id}", items))
    console.print("\n[bold]Details:[/bold]")
    console.print_json(json.dumps(a.details, indent=2))


@app.command("update")
def update_alert(
    alert_id: int = typer.Argument(..., help="Alert database ID"),
    new_status: str = typer.Option(..., "--status", "-s",
                                   help=f"New status: {', '.join(sorted(ALERT_STATUSES))}"),
) -> None:
    """Update the lifecycle status of an alert."""
    with StorageLayer(get_db()) as store:
        a = store.alerts.get_by_id(alert_id)
        if a is None:
            error(f"Alert {alert_id} not found.")
            raise typer.Exit(1)
        try:
            store.alerts.update_status(alert_id, new_status)
        except ValueError as exc:
            error(str(exc))
            raise typer.Exit(1)

    success(f"Alert {alert_id} status → [bold]{new_status}[/bold]")
