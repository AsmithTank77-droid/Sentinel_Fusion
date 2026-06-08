"""
demo/demo_runner.py — Full end-to-end SOC pipeline demonstration.

Simulates a realistic multi-stage cyber attack and runs it through the
complete Sentinel_Fusion 10-stage pipeline:

    ingest → normalize → enrich → sigma → correlate → detect → score → timeline → report → hunt

Attack scenario:
    Attacker:   185.220.101.45  (Russian TOR exit node, known malicious)
    Target DC:  10.0.0.5        (DC01, Windows domain controller)
    LM Target:  10.0.0.10       (FS01, internal file server)

    02:14Z — Nmap port scan of DC01 (NRA)
    02:15Z — SSH brute force attempt #1 (Winlog 4625)
    02:16Z — SSH brute force attempt #2 (Winlog 4625)
    02:16Z — SSH brute force attempt #3 (Winlog 4625)
    02:17Z — SSH brute force attempt #4 (Winlog 4625)
    02:17Z — SSH brute force attempt #5 (Winlog 4625)
    02:20Z — Successful login (Winlog 4624)
    02:22Z — Lateral movement DC01 → FS01 (Mock)

Usage:
    cd /home/cyb3rgoon/projects/Sentinel_Fusion
    python -m demo.demo_runner

Output: Markdown SOC report printed to stdout; JSON report written to
        demo/output/demo_report.json (if demo/output/ exists).
"""

from __future__ import annotations

import json
import os
import sys

# Ensure project root is on the path when run directly
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.pipeline.orchestrator import PipelineOrchestrator


# ---------------------------------------------------------------------------
# Attack scenario events
# ---------------------------------------------------------------------------

_NRA_EVENTS: list[dict] = [
    {
        "scanner_ip": "185.220.101.45",
        "host":       "10.0.0.5",
        "scan_time":  "2026-05-09T02:14:00Z",
        "event_type": "port_scan",
        "risk_level": "high",
        "ports_scanned": [22, 80, 443, 3389, 445],
        "open_ports":    [22, 445],
        "scanner_tool":  "nmap",
    },
]

_WINLOG_EVENTS: list[dict] = [
    # Brute force — 5 failed login attempts
    {
        "EventID":     4625,
        "TimeCreated": "2026-05-09T02:15:00Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "SubStatus":       "0xC000006A",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
    {
        "EventID":     4625,
        "TimeCreated": "2026-05-09T02:16:00Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "SubStatus":       "0xC000006A",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
    {
        "EventID":     4625,
        "TimeCreated": "2026-05-09T02:16:30Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "SubStatus":       "0xC000006A",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
    {
        "EventID":     4625,
        "TimeCreated": "2026-05-09T02:17:00Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "SubStatus":       "0xC000006A",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
    {
        "EventID":     4625,
        "TimeCreated": "2026-05-09T02:17:45Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "SubStatus":       "0xC000006A",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
    # Successful login
    {
        "EventID":     4624,
        "TimeCreated": "2026-05-09T02:20:00Z",
        "Computer":    "DC01",
        "IpAddress":   "185.220.101.45",
        "dst_ip":      "10.0.0.5",
        "EventData": {
            "TargetUserName":  "Administrator",
            "LogonType":       "10",
            "IpAddress":       "185.220.101.45",
            "TargetIpAddress": "10.0.0.5",
        },
    },
]

_MOCK_EVENTS: list[dict] = [
    # Lateral movement: DC01 (now compromised) connects to FS01
    {
        "timestamp":  "2026-05-09T02:22:00Z",
        "src_ip":     "10.0.0.5",
        "dst_ip":     "10.0.0.10",
        "event_type": "lateral_movement",
        "severity":   "high",
        "metadata": {
            "protocol":       "SMB",
            "tool":           "psexec",
            "target_share":   "ADMIN$",
            "pivot_from":     "DC01",
            "lateral_target": "FS01",
        },
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _print_separator(char: str = "=", width: int = 72) -> None:
    print(char * width)


def _print_stage_trace(trace: list[dict]) -> None:
    print("\nPipeline Execution Trace:")
    _print_separator("-", 48)
    for step in trace:
        count_str = f"  [{step['count']} items]" if "count" in step else ""
        print(f"  Stage {step['stage']:20s} → {step['status'].upper()}{count_str}")
    _print_separator("-", 48)


def run_demo() -> dict:
    """Execute the full attack simulation through the SOC pipeline."""
    _print_separator()
    print("  Sentinel_Fusion — SOC Pipeline Demo")
    print("  Multi-Stage Cyber Attack Simulation")
    _print_separator()
    print()
    print("  Attacker IP : 185.220.101.45  (TOR exit, Russia, known malicious)")
    print("  Target DC01 : 10.0.0.5        (Windows Domain Controller)")
    print("  Target FS01 : 10.0.0.10       (Internal File Server)")
    print()
    print("  Attack Timeline:")
    print("    02:14Z  Nmap port scan (NRA)                  [nra]")
    print("    02:15Z  SSH brute force attempt #1            [winlog 4625]")
    print("    02:16Z  SSH brute force attempt #2,#3         [winlog 4625]")
    print("    02:17Z  SSH brute force attempt #4,#5         [winlog 4625]")
    print("    02:20Z  Successful login — DC01 compromised   [winlog 4624]")
    print("    02:22Z  Lateral movement DC01 → FS01          [mock]")
    print()
    _print_separator()

    orchestrator = PipelineOrchestrator()

    print("\nRunning pipeline...\n")
    try:
        result = orchestrator.run({
            "nra":    _NRA_EVENTS,
            "winlog": _WINLOG_EVENTS,
            "mock":   _MOCK_EVENTS,
        })
    except Exception as exc:
        print(f"\n[PIPELINE ERROR] {exc}")
        raise

    _print_stage_trace(result["trace"])

    # Summary stats
    print(f"\nResults:")
    print(f"  Events processed : {result['event_count']}")
    print(f"  Alerts generated : {len(result['alerts'])}")
    print(f"  Timeline entries : {len([e for e in result['timeline'] if e.get('entry_type') != 'narrative'])}")

    scores = result["scores"]
    atk    = scores.get("attack_surface") or {}
    print(f"\nAttack Surface:")
    print(f"  Expansion score  : {atk.get('expansion_score', 0):.1f} / 10  [{atk.get('expansion_label', 'unknown')}]")
    print(f"  External sources : {atk.get('unique_external_sources', 0)}")
    print(f"  Internal targets : {atk.get('unique_internal_targets', 0)}")
    print(f"  Lateral hops     : {atk.get('lateral_movement_hops', 0)}")

    host_risk = scores.get("host_risk") or {}
    if host_risk:
        print("\nHost Risk Scores:")
        for host, data in sorted(host_risk.items(), key=lambda kv: kv[1].get("risk_score", 0), reverse=True):
            print(f"  {host:15s}  {data.get('risk_score', 0):4.1f} / 10  [{data.get('risk_label', 'unknown')}]")

    print()
    _print_separator()
    print("\n  SOC REPORT — MARKDOWN\n")
    _print_separator()
    print()
    print(result["report"]["markdown"])

    # Optionally write JSON report
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    if os.path.isdir(output_dir):
        json_path = os.path.join(output_dir, "demo_report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(result["report"]["json"], fh, indent=2)
        print(f"\n[INFO] JSON report written to: {json_path}")

    return result


if __name__ == "__main__":
    run_demo()
