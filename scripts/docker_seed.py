#!/usr/bin/env python3
"""
scripts/docker_seed.py — First-boot database seeder.

Runs on every container start. Skips immediately if the database already
contains events so re-starts are instant.

Seeds two scenarios:
  1. Full incident run — NRA + Windows logs → Critical verdict, 16 alerts
  2. Hunt engine demo  — 6 slow-burn attacker runs → all 4 hunt patterns fire
"""

from __future__ import annotations

import os
import sys

# Resolve project root whether running inside Docker (/app) or locally
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


def _already_seeded(store) -> bool:
    try:
        return store.events.count() > 0
    except Exception:
        return False


def _run_incident(store) -> None:
    """Full incident: NRA scan + Windows event logs."""
    import json
    from core.pipeline.ingest import load_nra_file
    from core.pipeline.orchestrator import PipelineOrchestrator

    nra_events = load_nra_file(os.path.join(_ROOT, "data/samples/nmap_scan.xml"))
    with open(os.path.join(_ROOT, "data/samples/windows_log.json")) as f:
        winlog_events = json.load(f)

    result = PipelineOrchestrator().run(
        {"nra": nra_events, "winlog": winlog_events}
    )
    run_id = store.persist_run(result)
    alerts = len(result.get("alerts") or [])
    print(f"  [seed] incident run → {run_id}  alerts={alerts}")


def _run_hunt_demo(store) -> None:
    """6 days of slow-burn attacker activity to seed hunt engine findings."""
    from core.pipeline.orchestrator import PipelineOrchestrator

    attacker = "45.33.32.156"
    c2       = "91.92.251.103"
    days = [
        "2026-06-01", "2026-06-02", "2026-06-03",
        "2026-06-04", "2026-06-05", "2026-06-06",
    ]

    for day in days:
        events = [
            {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": f"{day}T03:12:00Z"},
            {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": f"{day}T03:14:00Z"},
            {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": f"{day}T03:16:00Z"},
            {"src_ip": c2,       "dst_ip": "10.0.0.12", "event_type": "port_scan",              "severity": "low",    "timestamp": f"{day}T04:00:00Z"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.5", "event_type": "connection",            "severity": "low",    "timestamp": f"{day}T09:00:00Z"},
        ]
        result = PipelineOrchestrator().run({"mock": events})
        store.persist_run(result)

    # Final run with store passed so hunt engine surfaces findings
    final_events = [
        {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": "2026-06-07T03:12:00Z"},
        {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": "2026-06-07T03:14:00Z"},
        {"src_ip": attacker, "dst_ip": "10.0.0.5",  "event_type": "authentication_failure", "severity": "medium", "timestamp": "2026-06-07T03:16:00Z"},
        {"src_ip": c2,       "dst_ip": "10.0.0.12", "event_type": "port_scan",              "severity": "low",    "timestamp": "2026-06-07T04:00:00Z"},
    ]
    final = PipelineOrchestrator().run({"mock": final_events}, store=store)
    run_id = store.persist_run(final)
    findings = len(final.get("hunt_findings") or [])
    print(f"  [seed] hunt demo  → {run_id}  hunt_findings={findings}")


def main() -> None:
    from storage.store import StorageLayer
    from config.settings import settings

    db_path = str(settings.db_path)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    with StorageLayer(db_path) as store:
        if _already_seeded(store):
            print("  [seed] database already seeded — skipping")
            return

        print("  [seed] first boot — seeding database with sample data...")
        _run_incident(store)
        _run_hunt_demo(store)
        print("  [seed] done — dashboard ready at http://localhost:8000/dashboard")


if __name__ == "__main__":
    main()
