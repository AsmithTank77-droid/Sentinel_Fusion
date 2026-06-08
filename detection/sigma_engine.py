"""
detection/sigma_engine.py — Stage 4: Sigma Rule Evaluation
Pipeline: enrich.py (Stage 3) → sigma_engine.py (Stage 4) → correlation_engine.py (Stage 5)

Evaluates a curated set of Sigma-compatible detection rules against enriched
event dicts. Each rule is mapped to a MITRE ATT&CK technique. Matched rules
produce alert dicts consistent with other Sentinel_Fusion detectors.

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

from detection.sigma_field_mapper import map_event

# ---------------------------------------------------------------------------
# Built-in rule definitions
# ---------------------------------------------------------------------------
# Each rule contains:
#   id                — unique identifier (SF-SIG-NNN)
#   title             — short human-readable name
#   detection         — AND-logic field conditions; key format: Field[|modifier...]
#                       Supported modifiers: contains, startswith, endswith, in, not, any
#                       List values with contains/startswith/endswith → OR across items
#   mitre_tactic      — "TANNN - Tactic Name"
#   mitre_technique   — "TNNN[.NNN] - Technique Name"
#   severity          — int 0-10
#   confidence        — float 0-1 (base; boosted by threat intel at match time)

_RULES: list[dict] = [
    {
        "id":    "SF-SIG-001",
        "title": "Signed Binary Proxy Execution (LOLBin)",
        "detection": {
            "EventID": 4688,
            "CommandLine|contains|any": [
                "certutil", "bitsadmin", "regsvr32",
                "rundll32", "mshta", "wscript", "cscript",
            ],
        },
        "mitre_tactic":    "TA0005 - Defense Evasion",
        "mitre_technique": "T1218 - Signed Binary Proxy Execution",
        "severity":   7,
        "confidence": 0.72,
    },
    {
        "id":    "SF-SIG-002",
        "title": "WMI Spawning Child Process",
        "detection": {
            "EventID":              4688,
            "ParentImage|contains": "wmiprvse.exe",
        },
        "mitre_tactic":    "TA0002 - Execution",
        "mitre_technique": "T1047 - Windows Management Instrumentation",
        "severity":   7,
        "confidence": 0.75,
    },
    {
        "id":    "SF-SIG-003",
        "title": "PowerShell Encoded Command",
        "detection": {
            "EventID":                  4688,
            "Image|contains":           "powershell",
            "CommandLine|contains|any": ["-enc", "-encodedcommand", "-e "],
        },
        "mitre_tactic":    "TA0002 - Execution",
        "mitre_technique": "T1059.001 - PowerShell",
        "severity":   8,
        "confidence": 0.82,
    },
    {
        "id":    "SF-SIG-004",
        "title": "Office Application Spawning Shell",
        "detection": {
            "EventID":                  4688,
            "Image|contains|any":       ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "ParentImage|contains|any": [
                "excel.exe", "winword.exe", "word.exe",
                "outlook.exe", "onenote.exe", "powerpnt.exe",
            ],
        },
        "mitre_tactic":    "TA0002 - Execution",
        "mitre_technique": "T1059.003 - Windows Command Shell",
        "severity":   9,
        "confidence": 0.88,
    },
    {
        "id":    "SF-SIG-005",
        "title": "Explicit Credential Logon (Pass-the-Hash Indicator)",
        "detection": {
            "EventID": 4648,
        },
        "mitre_tactic":    "TA0008 - Lateral Movement",
        "mitre_technique": "T1550.002 - Pass the Hash",
        "severity":   8,
        "confidence": 0.68,
    },
    {
        "id":    "SF-SIG-006",
        "title": "Suspicious Service Installation",
        "detection": {
            "EventID|in": [4697, 7045],
        },
        "mitre_tactic":    "TA0003 - Persistence",
        "mitre_technique": "T1543.003 - Windows Service",
        "severity":   8,
        "confidence": 0.80,
    },
    {
        "id":    "SF-SIG-007",
        "title": "Scheduled Task Created",
        "detection": {
            "EventID": 4698,
        },
        "mitre_tactic":    "TA0003 - Persistence",
        "mitre_technique": "T1053.005 - Scheduled Task",
        "severity":   7,
        "confidence": 0.75,
    },
    {
        "id":    "SF-SIG-008",
        "title": "Kerberos Pre-Authentication Failure (AS-REP Roasting)",
        "detection": {
            "EventID": 4771,
        },
        "mitre_tactic":    "TA0006 - Credential Access",
        "mitre_technique": "T1558.003 - AS-REP Roasting",
        "severity":   7,
        "confidence": 0.70,
    },
    {
        "id":    "SF-SIG-009",
        "title": "Network Logon with Machine Account",
        "detection": {
            "EventID":                 4624,
            "LogonType":               "3",
            "TargetUserName|endswith": "$",
        },
        "mitre_tactic":    "TA0008 - Lateral Movement",
        "mitre_technique": "T1078.002 - Domain Accounts",
        "severity":   6,
        "confidence": 0.65,
    },
    {
        "id":    "SF-SIG-010",
        "title": "Remote Logon from Non-RFC1918 Source",
        "detection": {
            "EventID":   4624,
            "LogonType": "3",
            "SourceIp|not|startswith|any": ["192.168.", "10.", "172.", "127.", "::1"],
        },
        "mitre_tactic":    "TA0001 - Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "severity":   7,
        "confidence": 0.70,
    },
]

_REQUIRED_ALERT_KEYS = frozenset({
    "alert_type", "rule_id", "rule_title", "confidence",
    "src_ip", "dst_ip", "event_type",
    "mitre_tactic", "mitre_technique", "severity",
    "matched_fields", "timestamp", "source",
})


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

def _match_condition(field_val: object, modifiers: list[str], pattern: object) -> bool:
    """
    Evaluate one detection condition against a resolved field value.

    Modifier semantics:
        (none)      — equality; pattern may be a single value or list (OR across list)
        in          — membership: field_val in pattern list
        contains    — substring; pattern list → OR across items (case-insensitive)
        startswith  — prefix;    pattern list → OR across items (case-insensitive)
        endswith    — suffix;    pattern list → OR across items (case-insensitive)
        not         — negate the final result
        any         — explicit OR marker (redundant with list behaviour; accepted, ignored)

    Missing/empty field values always produce False for string operations (contains,
    startswith, endswith) so rules never fire on absent data, even when negated.
    """
    negate = "not" in modifiers
    mode   = next((m for m in modifiers if m not in ("not", "any")), "eq")
    patterns = pattern if isinstance(pattern, list) else [pattern]

    # String operations require an actual value; absent field → no match
    if (field_val is None or field_val == "") and mode not in ("eq", "in"):
        return False

    if mode in ("eq", "in"):
        result = field_val in patterns
    elif mode == "contains":
        val_str = str(field_val).lower()
        result  = any(str(p).lower() in val_str for p in patterns)
    elif mode == "startswith":
        val_str = str(field_val).lower()
        result  = any(val_str.startswith(str(p).lower()) for p in patterns)
    elif mode == "endswith":
        val_str = str(field_val).lower()
        result  = any(val_str.endswith(str(p).lower()) for p in patterns)
    else:
        result = False

    return not result if negate else result


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SigmaEngine:
    """
    Evaluates _RULES against a batch of enriched event dicts.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
        Returns list of sigma_rule_match alert dicts.
    """

    def detect(self, events: list[dict]) -> list[dict]:
        """
        Evaluate each event against every built-in rule.

        Args:
            events: enriched event dicts (NormalizedEvent.to_dict()).

        Returns:
            list of alert dicts, one per (event, rule) match.
            {
                "alert_type":      "sigma_rule_match",
                "rule_id":         str,            # e.g. "SF-SIG-001"
                "rule_title":      str,
                "confidence":      float,          # base + threat-intel boost, capped at 0.99
                "src_ip":          str,
                "dst_ip":          str,
                "event_type":      str,
                "mitre_tactic":    str,
                "mitre_technique": str,
                "severity":        int,
                "matched_fields":  dict,           # Sigma field → resolved value
                "timestamp":       str,
                "source":          "sigma_engine",
            }
        """
        alerts: list[dict] = []
        for event in events:
            mapped = map_event(event)
            for rule in _RULES:
                if self._rule_matches(mapped, rule["detection"]):
                    alerts.append(self._build_alert(event, mapped, rule))
        return alerts

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_matches(mapped: dict, detection: dict) -> bool:
        """Return True only when ALL conditions in detection pass (AND logic)."""
        for key, pattern in detection.items():
            parts     = key.split("|")
            field     = parts[0]
            modifiers = parts[1:]
            if not _match_condition(mapped.get(field), modifiers, pattern):
                return False
        return True

    @staticmethod
    def _build_alert(event: dict, mapped: dict, rule: dict) -> dict:
        """Construct an alert dict for a matched rule."""
        matched_fields = {
            key.split("|")[0]: mapped.get(key.split("|")[0])
            for key in rule["detection"]
        }

        enrichment = (event.get("metadata") or {}).get("enrichment") or {}
        rep_score  = (enrichment.get("src_reputation") or {}).get("reputation_score", 0.0)
        confidence = round(min(rule["confidence"] + float(rep_score) * 0.1, 0.99), 4)

        return {
            "alert_type":      "sigma_rule_match",
            "rule_id":         rule["id"],
            "rule_title":      rule["title"],
            "confidence":      confidence,
            "src_ip":          event.get("src_ip") or "",
            "dst_ip":          event.get("dst_ip") or "",
            "event_type":      event.get("event_type") or "",
            "mitre_tactic":    rule["mitre_tactic"],
            "mitre_technique": rule["mitre_technique"],
            "severity":        rule["severity"],
            "matched_fields":  matched_fields,
            "timestamp":       event.get("timestamp") or "",
            "source":          "sigma_engine",
        }
