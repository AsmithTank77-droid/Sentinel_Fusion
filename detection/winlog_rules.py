"""
detection/winlog_rules.py — Windows Event Log behavioral correlation rules.
Pipeline: enrich.py → detect stage (winlog_rules)

Nine stateless behavioral rules adapted from winlog-soc-analyzer/correlator.py.
Operates on enriched NormalizedEvent dicts (source_type == "winlog").
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from config.settings import settings as _settings

BRUTE_FORCE_THRESHOLD      = _settings.winlog_brute_force_threshold
BRUTE_FORCE_WINDOW         = _settings.winlog_brute_force_window
BRUTE_FORCE_SUCCESS_WINDOW = _settings.winlog_brute_force_success_window
LATERAL_MOVEMENT_WINDOW    = _settings.winlog_lateral_window
ACCOUNT_BACKDOOR_WINDOW    = _settings.winlog_account_backdoor_window
PRIVESC_WINDOW             = _settings.winlog_privesc_window

_SYSTEM_ACCOUNTS = {"", "-", "system", "local service", "network service", "anonymous logon"}


def _parse_ts(ts: str | None) -> float:
    if not ts:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f+00:00"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


def _is_system(username: str) -> bool:
    return (username or "").lower() in _SYSTEM_ACCOUNTS


def _extract(event: dict) -> dict:
    """Extract winlog-specific fields from a Sentinel_Fusion enriched event dict."""
    meta = event.get("metadata") or {}
    return {
        "event_id":        meta.get("event_id") or 0,
        "timestamp_epoch": meta.get("timestamp_epoch") or _parse_ts(event.get("timestamp")),
        "timestamp":       event.get("timestamp") or "",
        "src_ip":          event.get("src_ip") or meta.get("src_ip") or "",
        "computer":        event.get("dst_ip") or meta.get("computer") or "",
        "target_user":     meta.get("target_user") or "",
        "subject_user":    meta.get("subject_user") or "",
        "logon_type":      meta.get("logon_type"),
        "group_name":      meta.get("group_name") or "",
        "service_name":    meta.get("service_name") or "",
        "task_name":       meta.get("task_name") or "",
    }


def _make_alert(rule_id: str, title: str, confidence: float, mitre_technique: str,
                mitre_tactic: str, description: str, first_seen: str, last_seen: str,
                severity: int, context: dict | None = None) -> dict:
    return {
        "alert_type":      rule_id,
        "title":           title,
        "confidence":      round(confidence, 4),
        "mitre_technique": mitre_technique,
        "mitre_tactic":    mitre_tactic,
        "description":     description,
        "first_seen":      first_seen,
        "last_seen":       last_seen,
        "severity":        severity,
        "context":         context or {},
        "source":          "winlog_rules",
    }


def _find_worst_window(events: list[dict], window_seconds: float) -> list[dict]:
    if not events:
        return []
    ev = sorted(events, key=lambda e: e["timestamp_epoch"])
    best_start, best_count, left = 0, 1, 0
    for right in range(1, len(ev)):
        while ev[right]["timestamp_epoch"] - ev[left]["timestamp_epoch"] > window_seconds:
            left += 1
        if right - left + 1 > best_count:
            best_count = right - left + 1
            best_start = left
    return ev[best_start: best_start + best_count]


class WinlogRulesDetector:
    """
    Applies nine behavioral correlation rules against Winlog-sourced events.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
    """

    def detect(self, events: list[dict]) -> list[dict]:
        winlog_events = [_extract(e) for e in events if e.get("source_type") == "winlog"]
        if not winlog_events:
            return []

        alerts: list[dict] = []
        for rule in _RULES:
            alerts.extend(rule(winlog_events))
        return alerts


# ---------------------------------------------------------------------------
# RULE-001 — Brute Force
# ---------------------------------------------------------------------------
def _rule_brute_force(events: list[dict]) -> list[dict]:
    failed = [e for e in events if e["event_id"] == 4625 and e["src_ip"]]
    by_ip: dict[str, list] = defaultdict(list)
    for e in failed:
        by_ip[e["src_ip"]].append(e)

    alerts = []
    for ip, ip_events in by_ip.items():
        burst = _find_worst_window(ip_events, BRUTE_FORCE_WINDOW)
        if len(burst) < BRUTE_FORCE_THRESHOLD:
            continue
        duration = int(burst[-1]["timestamp_epoch"] - burst[0]["timestamp_epoch"])
        users = sorted({e["target_user"] for e in burst if e["target_user"]})
        alerts.append(_make_alert(
            rule_id="WINLOG-001",
            title="Brute Force Attack",
            confidence=min(0.60 + len(burst) * 0.02, 0.92),
            mitre_technique="T1110",
            mitre_tactic="TA0006 - Credential Access",
            description=(
                f"{len(burst)} failed logon attempts from {ip} in {duration}s"
                + (f" targeting: {', '.join(users)}" if users else "")
            ),
            first_seen=burst[0]["timestamp"],
            last_seen=burst[-1]["timestamp"],
            severity=8,
            context={"src_ip": ip, "targeted_users": users, "failure_count": len(burst)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-002 — Brute Force Followed by Successful Logon
# ---------------------------------------------------------------------------
def _rule_brute_force_success(events: list[dict]) -> list[dict]:
    failed  = [e for e in events if e["event_id"] == 4625 and e["src_ip"]]
    success = [e for e in events if e["event_id"] == 4624 and e["src_ip"]]

    by_ip_fail: dict[str, list] = defaultdict(list)
    by_ip_ok:   dict[str, list] = defaultdict(list)
    for e in failed:
        by_ip_fail[e["src_ip"]].append(e)
    for e in success:
        by_ip_ok[e["src_ip"]].append(e)

    alerts = []
    for ip, ip_failures in by_ip_fail.items():
        burst = _find_worst_window(ip_failures, BRUTE_FORCE_WINDOW)
        if len(burst) < BRUTE_FORCE_THRESHOLD:
            continue
        last_fail_epoch = burst[-1]["timestamp_epoch"]
        for s in by_ip_ok.get(ip, []):
            gap = s["timestamp_epoch"] - last_fail_epoch
            if 0 <= gap <= BRUTE_FORCE_SUCCESS_WINDOW:
                user = s["target_user"] or "unknown"
                alerts.append(_make_alert(
                    rule_id="WINLOG-002",
                    title="Brute Force Followed by Successful Logon",
                    confidence=0.96,
                    mitre_technique="T1110",
                    mitre_tactic="TA0006 - Credential Access",
                    description=(
                        f"Brute force from {ip} ({len(burst)} failures) succeeded — "
                        f"'{user}' logged on {int(gap)}s after last failure"
                    ),
                    first_seen=burst[0]["timestamp"],
                    last_seen=s["timestamp"],
                    severity=10,
                    context={"src_ip": ip, "compromised_user": user, "failure_count": len(burst)},
                ))
                break
    return alerts


# ---------------------------------------------------------------------------
# RULE-003 — New Account Added to Security Group (account backdoor)
# ---------------------------------------------------------------------------
def _rule_account_backdoor(events: list[dict]) -> list[dict]:
    created    = [e for e in events if e["event_id"] == 4720]
    group_adds = [e for e in events if e["event_id"] == 4732]

    alerts = []
    seen: set[tuple] = set()
    for c in created:
        new_user = c["target_user"]
        creator  = c["subject_user"]
        for a in group_adds:
            gap = a["timestamp_epoch"] - c["timestamp_epoch"]
            if not (0 <= gap <= ACCOUNT_BACKDOOR_WINDOW):
                continue
            key = (c["timestamp_epoch"], a["timestamp_epoch"])
            if key in seen:
                continue
            seen.add(key)
            group = a["group_name"] or "unknown group"
            alerts.append(_make_alert(
                rule_id="WINLOG-003",
                title="New Account Added to Security Group",
                confidence=0.93,
                mitre_technique="T1136.001",
                mitre_tactic="TA0003 - Persistence",
                description=(
                    f"Account '{new_user or 'unknown'}' created by '{creator or 'unknown'}'"
                    f" — group membership change to '{group}' occurred {int(gap)}s later"
                ),
                first_seen=c["timestamp"],
                last_seen=a["timestamp"],
                severity=10,
                context={"new_user": new_user, "group": group, "creator": creator},
            ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-004 — Lateral Movement (explicit credential use + network logon)
# ---------------------------------------------------------------------------
def _rule_lateral_movement(events: list[dict]) -> list[dict]:
    explicit_cred = [e for e in events if e["event_id"] == 4648]
    net_logons    = [e for e in events if e["event_id"] == 4624 and e["logon_type"] == 3]

    alerts = []
    seen: set[tuple] = set()
    for ec in explicit_cred:
        user = ec["subject_user"]
        if not user or _is_system(user):
            continue
        for nl in net_logons:
            gap = nl["timestamp_epoch"] - ec["timestamp_epoch"]
            if not (0 <= gap <= LATERAL_MOVEMENT_WINDOW):
                continue
            if (nl["subject_user"].lower() != user.lower()
                    and nl["target_user"].lower() != user.lower()):
                continue
            key = (ec["timestamp_epoch"], nl["timestamp_epoch"])
            if key in seen:
                continue
            seen.add(key)
            target = nl["target_user"] or "unknown"
            dest   = nl["computer"] or "unknown"
            alerts.append(_make_alert(
                rule_id="WINLOG-004",
                title="Lateral Movement — Explicit Credentials Followed by Network Logon",
                confidence=0.88,
                mitre_technique="T1021",
                mitre_tactic="TA0008 - Lateral Movement",
                description=(
                    f"'{user}' used explicit credentials then network-logged on as '{target}'"
                    f" on '{dest}' {int(gap)}s later"
                    + (f" from {nl['src_ip']}" if nl["src_ip"] else "")
                ),
                first_seen=ec["timestamp"],
                last_seen=nl["timestamp"],
                severity=8,
                context={"source_user": user, "target_user": target, "destination": dest,
                         "src_ip": nl["src_ip"]},
            ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-005 — Privilege Escalation (remote logon + special privileges)
# ---------------------------------------------------------------------------
def _rule_privilege_escalation(events: list[dict]) -> list[dict]:
    remote_logons = [e for e in events if e["event_id"] == 4624 and e["logon_type"] in (3, 10)]
    special_privs = [e for e in events if e["event_id"] == 4672]

    alerts = []
    seen: set[tuple] = set()
    for sp in special_privs:
        user = sp["subject_user"] or sp["target_user"]
        if _is_system(user):
            continue
        for logon in reversed(remote_logons):
            if logon["timestamp_epoch"] > sp["timestamp_epoch"]:
                continue
            gap = sp["timestamp_epoch"] - logon["timestamp_epoch"]
            if gap > PRIVESC_WINDOW:
                break
            if logon["target_user"].lower() != user.lower():
                continue
            key = (logon["timestamp_epoch"], sp["timestamp_epoch"])
            if key in seen:
                continue
            seen.add(key)
            alerts.append(_make_alert(
                rule_id="WINLOG-005",
                title="Privilege Escalation — Admin Privileges After Remote Logon",
                confidence=0.85,
                mitre_technique="T1078.002",
                mitre_tactic="TA0004 - Privilege Escalation",
                description=(
                    f"'{user}' received special privileges {int(gap)}s after remote logon"
                    + (f" from {logon['src_ip']}" if logon["src_ip"] else "")
                ),
                first_seen=logon["timestamp"],
                last_seen=sp["timestamp"],
                severity=8,
                context={"user": user, "src_ip": logon["src_ip"],
                         "logon_type": logon["logon_type"]},
            ))
            break
    return alerts


# ---------------------------------------------------------------------------
# RULE-006 — Audit Log Cleared
# ---------------------------------------------------------------------------
def _rule_log_cleared(events: list[dict]) -> list[dict]:
    alerts = []
    for e in events:
        if e["event_id"] != 1102:
            continue
        actor = e["subject_user"] or "unknown"
        alerts.append(_make_alert(
            rule_id="WINLOG-006",
            title="Audit Log Cleared",
            confidence=0.99,
            mitre_technique="T1070.001",
            mitre_tactic="TA0005 - Defense Evasion",
            description=f"Windows audit log cleared by '{actor}' at {e['timestamp']}",
            first_seen=e["timestamp"],
            last_seen=e["timestamp"],
            severity=10,
            context={"actor": actor},
        ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-007 — Audit Policy Changed
# ---------------------------------------------------------------------------
def _rule_audit_policy_changed(events: list[dict]) -> list[dict]:
    alerts = []
    for e in events:
        if e["event_id"] != 4719:
            continue
        actor = e["subject_user"] or "unknown"
        alerts.append(_make_alert(
            rule_id="WINLOG-007",
            title="Audit Policy Changed",
            confidence=0.90,
            mitre_technique="T1562.002",
            mitre_tactic="TA0005 - Defense Evasion",
            description=f"System audit policy modified by '{actor}' at {e['timestamp']}",
            first_seen=e["timestamp"],
            last_seen=e["timestamp"],
            severity=8,
            context={"actor": actor},
        ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-008 — New Service Installed
# ---------------------------------------------------------------------------
def _rule_new_service(events: list[dict]) -> list[dict]:
    alerts = []
    for e in events:
        if e["event_id"] != 7045:
            continue
        svc  = e["service_name"] or "unknown"
        actor = e["subject_user"] or "unknown"
        alerts.append(_make_alert(
            rule_id="WINLOG-008",
            title="New Service Installed",
            confidence=0.88,
            mitre_technique="T1543.003",
            mitre_tactic="TA0003 - Persistence",
            description=f"Service '{svc}' installed by '{actor}' at {e['timestamp']}",
            first_seen=e["timestamp"],
            last_seen=e["timestamp"],
            severity=8,
            context={"service_name": svc, "actor": actor},
        ))
    return alerts


# ---------------------------------------------------------------------------
# RULE-009 — Scheduled Task Persistence
# ---------------------------------------------------------------------------
def _rule_scheduled_task(events: list[dict]) -> list[dict]:
    alerts = []
    for e in events:
        if e["event_id"] not in (4698, 4702):
            continue
        action = "created" if e["event_id"] == 4698 else "modified"
        task   = e["task_name"] or "unknown"
        actor  = e["subject_user"] or "unknown"
        alerts.append(_make_alert(
            rule_id="WINLOG-009",
            title=f"Scheduled Task {action.title()}",
            confidence=0.85,
            mitre_technique="T1053.005",
            mitre_tactic="TA0003 - Persistence",
            description=f"Scheduled task '{task}' {action} by '{actor}' at {e['timestamp']}",
            first_seen=e["timestamp"],
            last_seen=e["timestamp"],
            severity=8,
            context={"task_name": task, "actor": actor, "action": action},
        ))
    return alerts


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------
_RULES = [
    _rule_brute_force,
    _rule_brute_force_success,
    _rule_account_backdoor,
    _rule_lateral_movement,
    _rule_privilege_escalation,
    _rule_log_cleared,
    _rule_audit_policy_changed,
    _rule_new_service,
    _rule_scheduled_task,
]
