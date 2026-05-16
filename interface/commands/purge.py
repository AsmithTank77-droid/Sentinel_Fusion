"""
interface/commands/purge.py — sentinel purge
"""

from __future__ import annotations

import typer

from interface._state import get_db
from interface.output import console, error, success
from config.settings import settings
from storage.store import StorageLayer

app = typer.Typer(help="Enforce event data retention policy.")


@app.callback(invoke_without_command=True)
def purge(
    days: int  = typer.Option(settings.retention_days, "--days", "-d",
                              help="Delete events older than this many days."),
    yes:  bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """
    Delete events older than N days. Alerts and cases are never auto-purged —
    they require explicit analyst closure to preserve audit trail integrity.
    """
    if not yes:
        typer.confirm(
            f"Delete all events older than {days} day(s)?",
            abort=True,
        )

    with StorageLayer(get_db()) as store:
        try:
            result = store.purge(days=days)
        except ValueError as exc:
            error(str(exc))
            raise typer.Exit(1)

    deleted = result.get("events", 0)
    if deleted:
        console.print(f"[bold red]Purged[/bold red] [bold]{deleted:,}[/bold] event(s) older than {days} day(s).")
    else:
        success(f"No events older than {days} day(s) — nothing purged.")
