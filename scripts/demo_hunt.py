#!/usr/bin/env python3
"""
scripts/demo_hunt.py — Multi-run hunt engine demonstration.

Simulates 6 days of slow-burn attacker activity then lets the hunt engine
surface cross-run patterns invisible to any single pipeline run:

  • low_and_slow_brute_force  — 3 auth failures/run × 6 runs, sub-threshold each time
  • beacon                    — same src→dst pair in 6 runs (C2 check-in pattern)
  • persistent_threat_actor   — same external IP across 6 runs
  • alert_cluster             — open alerts from the same IP building up

Usage:
    python scripts/demo_hunt.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.rule import Rule

console = Console()

# ---------------------------------------------------------------------------
# Attacker profiles
# ---------------------------------------------------------------------------

_SLOW_ATTACKER = "45.33.32.156"   # Shodan scanner — known noisy recon IP
_C2_BEACON_SRC = "91.92.251.103"  # Known C2 infrastructure IP
_TARGET_HOST   = "10.0.0.5"
_TARGET_HOST_2 = "10.0.0.12"

_RUN_DAYS = [
    "2026-06-01",
    "2026-06-02",
    "2026-06-03",
    "2026-06-04",
    "2026-06-05",
    "2026-06-06",
]


def _build_run_events(day: str) -> list[dict]:
    """
    One day of events: 3 sub-threshold auth failures (slow BF) +
    1 C2 beacon contact + 1 noise event.
    Stays below the 5-failure live detection threshold every run.
    """
    return [
        # Slow brute force — 3 failures, below live threshold of 5
        {
            "src_ip":     _SLOW_ATTACKER,
            "dst_ip":     _TARGET_HOST,
            "event_type": "authentication_failure",
            "severity":   "medium",
            "timestamp":  f"{day}T03:12:00Z",
        },
        {
            "src_ip":     _SLOW_ATTACKER,
            "dst_ip":     _TARGET_HOST,
            "event_type": "authentication_failure",
            "severity":   "medium",
            "timestamp":  f"{day}T03:14:00Z",
        },
        {
            "src_ip":     _SLOW_ATTACKER,
            "dst_ip":     _TARGET_HOST,
            "event_type": "authentication_failure",
            "severity":   "medium",
            "timestamp":  f"{day}T03:16:00Z",
        },
        # C2 beacon — same src→dst pair appearing in every run
        {
            "src_ip":     _C2_BEACON_SRC,
            "dst_ip":     _TARGET_HOST_2,
            "event_type": "port_scan",
            "severity":   "low",
            "timestamp":  f"{day}T04:00:00Z",
        },
        # Normal internal traffic (noise)
        {
            "src_ip":     "10.0.0.1",
            "dst_ip":     "10.0.0.5",
            "event_type": "connection",
            "severity":   "low",
            "timestamp":  f"{day}T09:00:00Z",
        },
    ]


def _render_findings(findings: list[dict]) -> None:
    if not findings:
        console.print("[yellow]No hunt findings.[/yellow]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Hunt Type",  style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Src IP",     style="cyan")
    table.add_column("Runs", justify="right")
    table.add_column("Sev",  justify="center")
    table.add_column("MITRE")

    for f in findings:
        conf = f["confidence"]
        bar  = "█" * int(conf * 10)
        sev  = f["severity"].upper()
        color = "red" if sev == "HIGH" else "yellow"
        table.add_row(
            f["hunt_type"],
            f"{bar}  {conf:.2f}",
            f["src_ip"] or "—",
            str(f["run_count"]),
            f"[{color}]{sev}[/{color}]",
            f["mitre_tactic"],
        )

    console.print(table)
    console.print()

    for f in findings:
        console.print(Panel(
            f["analyst_note"],
            title=f"[bold]{f['hunt_type']}[/bold]",
            border_style="yellow",
            padding=(0, 1),
        ))
        console.print()


def main() -> None:
    from core.pipeline.orchestrator import PipelineOrchestrator
    from storage.store import StorageLayer
    from config.settings import settings

    db_path = str(settings.db_path)

    console.print()
    console.rule("[bold cyan]Sentinel_Fusion — Hunt Engine Demo[/bold cyan]")
    console.print()
    console.print(
        "  Simulating [bold]6 days[/bold] of slow-burn attacker activity.\n"
        "  Each run stays [bold]below[/bold] the live detection threshold — no\n"
        "  brute-force alert fires on any single run. The hunt engine surfaces\n"
        "  the pattern by aggregating across all runs.\n"
    )

    with StorageLayer(db_path) as store:

        # -------------------------------------------------------------------
        # Runs 1–6: persist each run so history builds up in the DB
        # -------------------------------------------------------------------
        for i, day in enumerate(_RUN_DAYS, start=1):
            events = _build_run_events(day)
            result = PipelineOrchestrator().run({"mock": events})
            run_id = store.persist_run(result)
            alerts = result.get("alerts") or []

            console.print(
                f"  [dim]Run {i}/6[/dim]  {day}  "
                f"({len(events)} events — 3 auth failures + 1 beacon + 1 noise)  "
                f"[green]✓[/green] {run_id}  alerts={len(alerts)}"
            )
            time.sleep(0.05)

        # -------------------------------------------------------------------
        # Final run: pass the connected store so hunt engine sees all history
        # -------------------------------------------------------------------
        console.print()
        console.print("  [dim]Run 7/7[/dim]  2026-06-07  (final run — hunt engine active)")
        final = PipelineOrchestrator().run(
            {"mock": _build_run_events("2026-06-07")},
            store=store,
        )
        store.persist_run(final)
        findings = final.get("hunt_findings") or []

        # -------------------------------------------------------------------
        # Show findings
        # -------------------------------------------------------------------
        console.print()
        console.rule("[bold yellow]Hunt Engine Findings — after 7 runs[/bold yellow]")
        console.print()

        if findings:
            console.print(
                f"  [bold green]{len(findings)} cross-run pattern(s) detected[/bold green] "
                f"— invisible to any single pipeline run.\n"
            )
            _render_findings(findings)
        else:
            console.print("[yellow]No findings returned.[/yellow]")

    console.rule()
    console.print()


if __name__ == "__main__":
    main()
