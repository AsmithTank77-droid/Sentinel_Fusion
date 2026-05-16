"""
interface/commands/watch.py — sentinel watch

Continuous file-tail mode. Polls one or more event files at a fixed interval,
detects new events appended since the last cycle, and runs the full pipeline
on each batch of new events. Designed for ongoing monitoring of growing log
files without the overhead of re-processing everything every cycle.

Supports the same sources as `sentinel run`:
    --winlog <file.json>   Windows event log JSON array
    --nra    <file.json>   NRA (Nmap) JSON array
    --mock   <file.json>   Simulated event JSON array

State is tracked per-file as (mtime, last_event_count). When a file shrinks
(log rotation), the cursor resets and all events are treated as new.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path
from typing import Optional

import typer

from interface._state import get_db
from interface.output import confidence_bar, console, error, make_table, success
from storage.store import StorageLayer

app = typer.Typer(help="Watch event files and run the pipeline on new events.")

# ── File cursor ──────────────────────────────────────────────────────────────

class _FileCursor:
    """Tracks position in a growing JSON-array event file."""

    def __init__(self, path: Path) -> None:
        self.path       = path
        self._mtime:    float = 0.0
        self._count:    int   = 0

    def poll(self) -> list[dict]:
        """Return any events added since the last poll. Empty list if unchanged."""
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return []

        if mtime == self._mtime:
            return []

        try:
            events = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

        if not isinstance(events, list):
            return []

        self._mtime = mtime

        if len(events) < self._count:
            # File was rotated or truncated — start fresh
            self._count = 0

        new_events   = events[self._count:]
        self._count  = len(events)
        return new_events


# ── Core watch loop (factored out for testability) ───────────────────────────

def _run_watch_cycle(
    cursors:  dict[str, _FileCursor],
    db_path:  str,
    cycle_n:  int,
) -> dict | None:
    """
    Poll all cursors, collect new events, run the pipeline if anything changed.

    Returns the pipeline result dict, or None if no new events were found.
    """
    from core.pipeline.orchestrator import PipelineOrchestrator, PipelineStageError

    inputs: dict[str, list[dict]] = {}
    for source_type, cursor in cursors.items():
        new = cursor.poll()
        if new:
            inputs[source_type] = new

    if not inputs:
        return None

    total = sum(len(v) for v in inputs.values())
    console.print(
        f"\n[dim]Cycle {cycle_n}[/dim]  "
        f"[bold cyan]{total}[/bold cyan] new event(s) detected — running pipeline..."
    )

    try:
        result = PipelineOrchestrator().run(inputs)
    except PipelineStageError as exc:
        error(f"Pipeline failed at stage [bold]{exc.stage}[/bold]: {exc.cause}")
        return None

    with StorageLayer(db_path) as store:
        run_id = store.persist_run(result)

    alerts = result.get("alerts") or []

    # Summary table
    tbl = make_table(
        f"Cycle {cycle_n} — {run_id}",
        ("Metric", None),
        ("Value", "right"),
    )
    tbl.add_row("New events",  str(result["event_count"]))
    tbl.add_row("Alerts",      str(len(alerts)))

    scores    = result.get("scores") or {}
    host_risk = scores.get("host_risk") or {}
    if host_risk:
        top_host, top_data = max(host_risk.items(), key=lambda kv: kv[1].get("risk_score", 0))
        tbl.add_row(
            "Highest risk host",
            f"{top_host} — {top_data.get('risk_label', '?').upper()} "
            f"({top_data.get('risk_score', 0):.1f}/10)",
        )

    winlog_rules = sorted({
        str(a.get("alert_type", ""))
        for a in alerts
        if str(a.get("alert_type", "")).startswith("WINLOG-")
    })
    if winlog_rules:
        tbl.add_row("WINLOG rules fired", ", ".join(winlog_rules))

    console.print(tbl)

    # Top alert (highest confidence)
    if alerts:
        top = max(alerts, key=lambda a: float(a.get("confidence") or 0))
        console.print(
            f"  [bold red]Top alert:[/bold red] {top.get('alert_type')} "
            f"{confidence_bar(float(top.get('confidence') or 0))} "
            f"src=[cyan]{top.get('src_ip') or top.get('initial_src_ip') or '—'}[/cyan]"
        )

    return result


# ── Typer command ─────────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def watch(
    winlog:   Optional[Path] = typer.Option(None, "--winlog", help="Winlog JSON array file to tail.", exists=True),
    nra:      Optional[Path] = typer.Option(None, "--nra",    help="NRA JSON array file to tail.",    exists=True),
    mock:     Optional[Path] = typer.Option(None, "--mock",   help="Mock event JSON array to tail.",  exists=True),
    interval: int            = typer.Option(10,  "--interval", "-i", help="Poll interval in seconds.", min=1, max=3600),
) -> None:
    """
    Watch event files and run the pipeline on each new batch of events.

    Files are polled every INTERVAL seconds. Only events appended since the
    last cycle are processed — the full file is never re-processed.

    Press Ctrl+C to stop.

    Examples:
        sentinel watch --winlog data/samples/windows_log.json
        sentinel watch --winlog events.json --nra scan.json --interval 30
    """
    sources: dict[str, Path] = {}
    if winlog:
        sources["winlog"] = winlog
    if nra:
        sources["nra"] = nra
    if mock:
        sources["mock"] = mock

    if not sources:
        error("Supply at least one of --winlog, --nra, or --mock.")
        raise typer.Exit(1)

    db_path = get_db()

    cursors: dict[str, _FileCursor] = {
        source_type: _FileCursor(path)
        for source_type, path in sources.items()
    }

    file_list = ", ".join(str(p) for p in sources.values())
    console.print(
        f"\n[bold cyan]Sentinel Watch[/bold cyan] — "
        f"monitoring [dim]{file_list}[/dim] every [bold]{interval}s[/bold]"
    )
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    # Catch Ctrl+C cleanly
    _stop = False

    def _handle_sigint(sig: int, frame: object) -> None:
        nonlocal _stop
        _stop = True

    signal.signal(signal.SIGINT, _handle_sigint)

    cycle_n   = 0
    last_run  = 0.0

    # Run first cycle immediately on startup
    while not _stop:
        now = time.monotonic()
        if now - last_run >= interval or cycle_n == 0:
            cycle_n  += 1
            last_run  = now
            _run_watch_cycle(cursors, db_path, cycle_n)

        if not _stop:
            time.sleep(min(1.0, interval))

    success("Watch stopped.")
