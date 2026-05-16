"""
interface/commands/cases.py — sentinel cases / create / get / update / assign / note / link
"""

from __future__ import annotations

from typing import Optional

import typer

from interface._state import get_db
from interface.output import (
    console,
    error,
    kv_panel,
    make_table,
    severity_badge,
    status_badge,
    success,
)
from storage.models import CASE_SEVERITIES, CASE_STATUSES
from storage.store import StorageLayer

app = typer.Typer(help="Create and manage incident cases.")


def _case_row(c) -> tuple:
    return (
        c.case_ref,
        c.title[:48] + "…" if len(c.title) > 48 else c.title,
        severity_badge(c.severity),
        status_badge(c.status),
        c.assigned_to or "—",
        c.updated_at[:10],
    )


@app.callback(invoke_without_command=True)
def cases_list(
    ctx: typer.Context,
    case_status: Optional[str] = typer.Option(None, "--status", "-s",
                                               help="Filter: open|investigating|contained|closed"),
) -> None:
    """List incident cases, most recently updated first."""
    if ctx.invoked_subcommand:
        return

    with StorageLayer(get_db()) as store:
        try:
            cases = store.cases.get_all(status=case_status)
        except ValueError as exc:
            error(str(exc))
            raise typer.Exit(1)

    if not cases:
        console.print("[dim]No cases found.[/dim]")
        return

    tbl = make_table(
        f"Cases ({len(cases)})",
        ("Ref",        None),
        ("Title",      None),
        ("Severity",   None),
        ("Status",     None),
        ("Assigned To",None),
        ("Updated",    None),
    )
    for c in cases:
        tbl.add_row(*_case_row(c))
    console.print(tbl)


@app.command("create")
def create_case(
    title:       str           = typer.Option(..., "--title", "-t",    prompt="Case title",
                                              help="Short descriptive title."),
    severity:    str           = typer.Option("medium", "--severity", "-s",
                                              help=f"Severity: {', '.join(sorted(CASE_SEVERITIES))}"),
    assigned_to: Optional[str] = typer.Option(None, "--assigned-to", "-a",
                                              help="Analyst email or name."),
) -> None:
    """Open a new incident case with a sequential CASE-YYYY-NNNN reference."""
    with StorageLayer(get_db()) as store:
        try:
            case = store.cases.create(
                title=title,
                severity=severity,
                assigned_to=assigned_to or "",
            )
        except ValueError as exc:
            error(str(exc))
            raise typer.Exit(1)

    success(f"Created [bold]{case.case_ref}[/bold]  [{severity.upper()}]  {title}")


@app.command("get")
def get_case(case_ref: str = typer.Argument(..., help="Case reference (e.g. CASE-2026-0001)")) -> None:
    """Show full details for a single case including analyst notes."""
    with StorageLayer(get_db()) as store:
        c = store.cases.get(case_ref)
        notes = store.cases.get_notes(case_ref) if c else []
        linked = store.cases.get_alert_ids(case_ref) if c else []

    if c is None:
        error(f"Case '{case_ref}' not found.")
        raise typer.Exit(1)

    items = {
        "Case Ref":    c.case_ref,
        "Title":       c.title,
        "Severity":    c.severity.upper(),
        "Status":      c.status,
        "Assigned To": c.assigned_to or "—",
        "Created At":  c.created_at,
        "Updated At":  c.updated_at,
        "Linked Alerts": ", ".join(str(i) for i in linked) or "none",
    }
    console.print(kv_panel(c.case_ref, items))

    if notes:
        console.print()
        tbl = make_table(
            "Analyst Notes",
            ("Author", None),
            ("Date",   None),
            ("Note",   None),
        )
        for n in notes:
            tbl.add_row(n.author, n.created_at[:10], n.note)
        console.print(tbl)


@app.command("update")
def update_case(
    case_ref: str = typer.Argument(..., help="Case reference"),
    new_status: str = typer.Option(..., "--status", "-s",
                                   help=f"New status: {', '.join(sorted(CASE_STATUSES))}"),
) -> None:
    """Advance a case through its lifecycle status."""
    with StorageLayer(get_db()) as store:
        if store.cases.get(case_ref) is None:
            error(f"Case '{case_ref}' not found.")
            raise typer.Exit(1)
        try:
            store.cases.update_status(case_ref, new_status)
        except ValueError as exc:
            error(str(exc))
            raise typer.Exit(1)

    success(f"{case_ref} status → [bold]{new_status}[/bold]")


@app.command("assign")
def assign_case(
    case_ref: str = typer.Argument(..., help="Case reference"),
    analyst:  str = typer.Option(..., "--to", "-t", prompt="Assign to", help="Analyst name or email."),
) -> None:
    """Assign a case to an analyst."""
    with StorageLayer(get_db()) as store:
        if store.cases.get(case_ref) is None:
            error(f"Case '{case_ref}' not found.")
            raise typer.Exit(1)
        store.cases.assign(case_ref, analyst)

    success(f"{case_ref} assigned to [bold]{analyst}[/bold]")


@app.command("note")
def add_note(
    case_ref: str           = typer.Argument(..., help="Case reference"),
    note:     str           = typer.Option(..., "--note", "-n", prompt="Note text", help="Analyst observation."),
    author:   Optional[str] = typer.Option(None, "--author", "-a", help="Note author (default: analyst)."),
) -> None:
    """Append an analyst note to a case."""
    with StorageLayer(get_db()) as store:
        if store.cases.get(case_ref) is None:
            error(f"Case '{case_ref}' not found.")
            raise typer.Exit(1)
        store.cases.add_note(case_ref, note=note, author=author or "analyst")

    success(f"Note added to [bold]{case_ref}[/bold]")


@app.command("link")
def link_alert(
    case_ref: str = typer.Argument(..., help="Case reference"),
    alert_id: int = typer.Option(..., "--alert-id", "-a", help="Alert database ID to link."),
) -> None:
    """Link an existing alert to a case (idempotent)."""
    with StorageLayer(get_db()) as store:
        if store.cases.get(case_ref) is None:
            error(f"Case '{case_ref}' not found.")
            raise typer.Exit(1)
        if store.alerts.get_by_id(alert_id) is None:
            error(f"Alert {alert_id} not found.")
            raise typer.Exit(1)
        store.cases.link_alert(case_ref, alert_id)

    success(f"Alert [bold]{alert_id}[/bold] linked to [bold]{case_ref}[/bold]")
