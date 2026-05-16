"""
interface/commands/pipeline.py — sentinel run
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from interface._state import get_db
from interface.output import (
    confidence_bar,
    console,
    error,
    int_severity_color,
    make_table,
    severity_badge,
    status_badge,
    success,
)
from storage.store import StorageLayer

app = typer.Typer(help="Execute the detection pipeline.")


@app.callback(invoke_without_command=True)
def run(
    nra:    Optional[Path] = typer.Option(None, "--nra",    help="NRA input: Nmap XML (.xml) or JSON event array (.json).", exists=True),
    winlog: Optional[Path] = typer.Option(None, "--winlog", help="Winlog input: binary .evtx or JSON event array (.json).",  exists=True),
    mock:   Optional[Path] = typer.Option(None, "--mock",   help="Simulated attack events (.json array).",                   exists=True),
    report: bool           = typer.Option(False, "--report", "-r", help="Print the full Markdown SOC report."),
) -> None:
    """
    Run the full 8-stage Sentinel Fusion pipeline over one or more event sources.

    At least one of --nra, --winlog, or --mock must be supplied.

    Native file formats are supported:
        --nra scan.xml          Nmap XML output (parsed per-host)
        --nra scan.json         Pre-exported JSON array of host dicts
        --winlog Security.evtx  Binary Windows Event Log (requires python-evtx)
        --winlog events.json    Pre-exported JSON array of event dicts

    Examples:
        sentinel run --nra scan.xml
        sentinel run --nra scan.xml --winlog Security.evtx --report
        sentinel run --mock data/samples/simulated_attack.json
    """
    from core.pipeline.orchestrator import PipelineOrchestrator, PipelineStageError
    from core.pipeline.ingest import load_nra_file, load_winlog_file

    inputs: dict[str, list] = {}

    def _load_json(path: Path, key: str) -> None:
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, list):
                error(f"{path}: expected a JSON array of event dicts, got {type(data).__name__}")
                raise typer.Exit(1)
            inputs[key] = data
        except json.JSONDecodeError as exc:
            error(f"{path}: invalid JSON — {exc}")
            raise typer.Exit(1)

    if nra:
        suffix = nra.suffix.lower()
        if suffix == ".xml":
            try:
                inputs["nra"] = load_nra_file(str(nra))
                console.print(f"[dim]NRA: parsed {len(inputs['nra'])} host(s) from {nra.name}[/dim]")
            except (OSError, ValueError) as exc:
                error(f"Failed to parse NRA file: {exc}")
                raise typer.Exit(1)
        else:
            _load_json(nra, "nra")

    if winlog:
        suffix = winlog.suffix.lower()
        if suffix == ".evtx":
            try:
                inputs["winlog"] = load_winlog_file(str(winlog))
                console.print(f"[dim]Winlog: parsed {len(inputs['winlog'])} event(s) from {winlog.name}[/dim]")
            except ImportError as exc:
                error(f"Cannot parse .evtx — {exc}")
                raise typer.Exit(1)
            except (OSError, FileNotFoundError, ValueError) as exc:
                error(f"Failed to parse Winlog file: {exc}")
                raise typer.Exit(1)
        else:
            _load_json(winlog, "winlog")

    if mock:
        _load_json(mock, "mock")

    if not inputs:
        error("Supply at least one of --nra, --winlog, or --mock.")
        raise typer.Exit(1)

    total_events = sum(len(v) for v in inputs.values())
    console.print(f"\n[bold cyan]Running pipeline[/bold cyan] over [bold]{total_events}[/bold] input event(s)...\n")

    with console.status("[cyan]Executing pipeline stages...[/cyan]", spinner="dots"):
        try:
            result = PipelineOrchestrator().run(inputs)
        except PipelineStageError as exc:
            error(f"Pipeline failed at stage [bold]{exc.stage}[/bold]: {exc.cause}")
            raise typer.Exit(1)

    # ── Trace table ───────────────────────────────────────────────────────────
    tbl = make_table("Pipeline Trace", ("Stage", None), ("Status", None), ("Count", "right"))
    for entry in result["trace"]:
        tbl.add_row(
            entry.get("stage", "?"),
            status_badge(entry.get("status", "?")),
            str(entry["count"]) if "count" in entry else "—",
        )
    console.print(tbl)

    # ── Persist ───────────────────────────────────────────────────────────────
    with StorageLayer(get_db()) as store:
        run_id = store.persist_run(result)

    success(f"Persisted as [bold]{run_id}[/bold]")
    console.print(
        f"  Events: [cyan]{result['event_count']}[/cyan]  │  "
        f"Alerts: [red]{len(result['alerts'])}[/red]  │  "
        f"Run ID: [dim]{run_id}[/dim]\n"
    )

    # ── Top alerts ────────────────────────────────────────────────────────────
    alerts = sorted(result["alerts"], key=lambda a: a.get("confidence", 0), reverse=True)[:5]
    if alerts:
        tbl = make_table(
            "Top Alerts",
            ("Type", None),
            ("Confidence", None),
            ("Src IP", None),
            ("MITRE", None),
        )
        for a in alerts:
            mitre = a.get("mitre_tactic") or (a.get("mitre_tactics") or ["—"])[0]
            tbl.add_row(
                a.get("alert_type", "—"),
                confidence_bar(float(a.get("confidence", 0))),
                a.get("src_ip") or a.get("initial_src_ip") or "—",
                mitre,
            )
        console.print(tbl)

    # ── Full report (optional) ────────────────────────────────────────────────
    if report:
        console.rule("[bold cyan]SOC Report[/bold cyan]")
        from rich.markdown import Markdown
        console.print(Markdown(result["report"]["markdown"]))
