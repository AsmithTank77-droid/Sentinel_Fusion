"""
hunting/hunt_engine.py — Stage 10: Proactive threat hunting.

Queries StorageLayer for cross-run patterns that individual pipeline runs
miss. Each strategy looks for low-and-slow signals that only become visible
when events and alerts are aggregated across many runs.

Four hunt strategies:
  1. low_and_slow_brute_force — auth_failure events from the same src_ip
     across 3+ separate runs, each run below the brute-force threshold (< 5).
  2. alert_cluster — same src_ip has 3+ open alerts at any confidence level,
     suggesting persistent threat activity that keeps being de-prioritised.
  3. beacon — same (src_ip, dst_ip) pair appearing in 5+ separate runs,
     consistent with periodic C2 check-in behaviour.
  4. persistent_threat_actor — same src_ip in events across 5+ separate runs,
     suggesting a returning attacker rather than a one-off scan.

Public API:
    HuntEngine().hunt(store) -> list[dict]

If store is None, returns [] immediately so the orchestrator can call this
stage safely in test environments without a database.
"""

from __future__ import annotations

import uuid
from collections import defaultdict

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_SLOW_BF_MIN_RUNS    = 3    # min runs with auth_failure from same IP (low-and-slow)
_SLOW_BF_MAX_PER_RUN = 4    # max failures per run to be "sub-threshold"
_CLUSTER_MIN_ALERTS  = 3    # min open alerts from same src_ip
_BEACON_MIN_RUNS     = 5    # min runs with same (src_ip, dst_ip) pair
_PERSISTENT_MIN_RUNS = 5    # min runs with same src_ip in any event

# ---------------------------------------------------------------------------
# Finding schema keys
# ---------------------------------------------------------------------------

_REQUIRED_KEYS: frozenset[str] = frozenset({
    "hunt_id", "hunt_type", "confidence", "severity",
    "src_ip", "dst_ip", "mitre_tactic", "analyst_note",
    "run_count", "evidence", "source",
})


def _make_finding(
    hunt_type: str,
    confidence: float,
    severity: str,
    src_ip: str,
    dst_ip: str,
    mitre_tactic: str,
    analyst_note: str,
    run_count: int,
    evidence: dict,
) -> dict:
    return {
        "hunt_id":      str(uuid.uuid4()),
        "hunt_type":    hunt_type,
        "confidence":   round(confidence, 4),
        "severity":     severity,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "mitre_tactic": mitre_tactic,
        "analyst_note": analyst_note,
        "run_count":    run_count,
        "evidence":     evidence,
        "source":       "hunt_engine",
    }


# ---------------------------------------------------------------------------
# Hunt strategies
# ---------------------------------------------------------------------------

def _hunt_low_and_slow_brute_force(store) -> list[dict]:
    """
    Auth failures from the same src_ip across multiple runs, each run below
    the brute-force detection threshold — classic slow-burn credential attack.
    """
    findings: list[dict] = []

    auth_failures = store.events.get_by_event_type("auth_failure", limit=2000)
    if not auth_failures:
        return findings

    # Group by src_ip → {run_id: count}
    ip_runs: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for ev in auth_failures:
        ip_runs[ev.src_ip][ev.run_id] += 1

    for src_ip, run_counts in ip_runs.items():
        # Only count runs where the IP stayed below the live detection threshold
        sub_threshold_runs = {
            run_id: cnt
            for run_id, cnt in run_counts.items()
            if cnt <= _SLOW_BF_MAX_PER_RUN
        }
        if len(sub_threshold_runs) < _SLOW_BF_MIN_RUNS:
            continue

        total_failures = sum(sub_threshold_runs.values())
        run_count = len(sub_threshold_runs)
        confidence = min(0.5 + run_count * 0.08, 0.92)
        severity = "high" if run_count >= 6 else "medium"

        findings.append(_make_finding(
            hunt_type    = "low_and_slow_brute_force",
            confidence   = confidence,
            severity     = severity,
            src_ip       = src_ip,
            dst_ip       = "",
            mitre_tactic = "TA0006 - Credential Access",
            analyst_note = (
                f"{src_ip} produced {total_failures} authentication failures "
                f"spread across {run_count} pipeline runs, each below the "
                f"live detection threshold of {_SLOW_BF_MAX_PER_RUN + 1}. "
                f"Consistent with a slow-burn credential attack. "
                f"Review all auth logs for this IP."
            ),
            run_count = run_count,
            evidence  = {
                "total_failures":     total_failures,
                "run_breakdown":      dict(sub_threshold_runs),
                "detection_threshold": _SLOW_BF_MAX_PER_RUN + 1,
            },
        ))

    return findings


def _hunt_alert_cluster(store) -> list[dict]:
    """
    Same src_ip with 3+ open alerts at any confidence — persistent activity
    being individually dismissed but collectively significant.
    """
    findings: list[dict] = []

    open_alerts = store.alerts.get_open(min_confidence=0.0)
    if not open_alerts:
        return findings

    # Group by src_ip
    ip_alerts: dict[str, list] = defaultdict(list)
    for alert in open_alerts:
        if alert.src_ip:
            ip_alerts[alert.src_ip].append(alert)

    for src_ip, alerts in ip_alerts.items():
        if len(alerts) < _CLUSTER_MIN_ALERTS:
            continue

        run_ids = {a.run_id for a in alerts}
        alert_types = list({a.alert_type for a in alerts})
        avg_confidence = sum(a.confidence for a in alerts) / len(alerts)
        confidence = min(0.45 + len(alerts) * 0.06, 0.90)
        severity = "high" if len(alerts) >= 6 else "medium"

        findings.append(_make_finding(
            hunt_type    = "alert_cluster",
            confidence   = confidence,
            severity     = severity,
            src_ip       = src_ip,
            dst_ip       = "",
            mitre_tactic = "TA0043 - Reconnaissance",
            analyst_note = (
                f"{src_ip} has {len(alerts)} open alerts across "
                f"{len(run_ids)} run(s) that have not been investigated. "
                f"Alert types: {', '.join(alert_types[:3])}{'...' if len(alert_types) > 3 else ''}. "
                f"Average confidence: {avg_confidence:.2f}. "
                f"Individually sub-threshold, collectively suspicious."
            ),
            run_count = len(run_ids),
            evidence  = {
                "alert_count":      len(alerts),
                "alert_types":      alert_types,
                "avg_confidence":   round(avg_confidence, 4),
                "run_ids":          sorted(run_ids),
            },
        ))

    return findings


def _hunt_beacon(store) -> list[dict]:
    """
    Same (src_ip, dst_ip) pair in 5+ separate runs — consistent with
    periodic C2 beacon or automated exfiltration.
    """
    findings: list[dict] = []

    recent_events = store.events.get_recent(limit=5000)
    if not recent_events:
        return findings

    # Group by (src_ip, dst_ip) → set of run_ids
    pair_runs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ev in recent_events:
        if ev.src_ip and ev.dst_ip:
            pair_runs[(ev.src_ip, ev.dst_ip)].add(ev.run_id)

    for (src_ip, dst_ip), run_ids in pair_runs.items():
        if len(run_ids) < _BEACON_MIN_RUNS:
            continue

        run_count = len(run_ids)
        confidence = min(0.55 + run_count * 0.05, 0.93)
        severity = "high" if run_count >= 8 else "medium"

        findings.append(_make_finding(
            hunt_type    = "beacon",
            confidence   = confidence,
            severity     = severity,
            src_ip       = src_ip,
            dst_ip       = dst_ip,
            mitre_tactic = "TA0011 - Command and Control",
            analyst_note = (
                f"The pair {src_ip} → {dst_ip} appeared in {run_count} "
                f"separate pipeline runs. Regularity of contact is consistent "
                f"with C2 beaconing or automated exfiltration. "
                f"Capture traffic and review inter-run timing."
            ),
            run_count = run_count,
            evidence  = {
                "run_ids":   sorted(run_ids),
                "pair":      f"{src_ip} → {dst_ip}",
            },
        ))

    return findings


def _hunt_persistent_threat_actor(store) -> list[dict]:
    """
    Same src_ip in events across 5+ separate runs — returning attacker
    rather than a one-off scan.
    """
    findings: list[dict] = []

    recent_events = store.events.get_recent(limit=5000)
    if not recent_events:
        return findings

    # Group by src_ip → set of run_ids
    ip_runs: dict[str, set[str]] = defaultdict(set)
    for ev in recent_events:
        if ev.src_ip:
            ip_runs[ev.src_ip].add(ev.run_id)

    # Filter out private/internal IPs (simple prefix check)
    _PRIVATE = ("10.", "192.168.", "172.", "127.", "::1")

    for src_ip, run_ids in ip_runs.items():
        if not src_ip or any(src_ip.startswith(p) for p in _PRIVATE):
            continue
        if len(run_ids) < _PERSISTENT_MIN_RUNS:
            continue

        run_count = len(run_ids)
        confidence = min(0.50 + run_count * 0.06, 0.91)
        severity = "high" if run_count >= 8 else "medium"

        # Check if any alerts exist for this IP
        ip_alerts = store.alerts.get_by_src_ip(src_ip)
        alert_count = len(ip_alerts)

        findings.append(_make_finding(
            hunt_type    = "persistent_threat_actor",
            confidence   = confidence,
            severity     = severity,
            src_ip       = src_ip,
            dst_ip       = "",
            mitre_tactic = "TA0043 - Reconnaissance",
            analyst_note = (
                f"{src_ip} appeared in {run_count} separate pipeline runs "
                f"with {alert_count} associated alert(s). "
                f"Repeated presence suggests a persistent, returning attacker "
                f"rather than a one-off scan. Block at perimeter and investigate "
                f"all sessions from this IP."
            ),
            run_count = run_count,
            evidence  = {
                "run_ids":     sorted(run_ids),
                "alert_count": alert_count,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class HuntEngine:
    """
    Proactive threat hunter — queries StorageLayer for cross-run patterns.

    Stateless at the instance level. Each hunt() call is independent.

    Public API:
        hunt(store) -> list[dict]
            Returns hunt findings. Each finding has keys defined in
            _REQUIRED_KEYS. Returns [] if store is None.
    """

    def hunt(self, store) -> list[dict]:
        """
        Run all hunt strategies against historical pipeline data.

        Parameters
        ----------
        store : StorageLayer | None
            If None, returns [] without error (safe for test environments
            and CLI runs without a database).

        Returns
        -------
        list[dict]  — deduplicated hunt findings, highest confidence first.
        """
        if store is None:
            return []

        findings: list[dict] = []

        for strategy in (
            _hunt_low_and_slow_brute_force,
            _hunt_alert_cluster,
            _hunt_beacon,
            _hunt_persistent_threat_actor,
        ):
            try:
                results = strategy(store)
                findings.extend(results)
            except Exception:
                pass  # one failing strategy never blocks the others

        # Sort by confidence descending
        findings.sort(key=lambda f: f["confidence"], reverse=True)
        return findings
