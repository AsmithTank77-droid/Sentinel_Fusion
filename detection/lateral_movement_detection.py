"""
detection/lateral_movement_detection.py — Detection: Lateral movement.
Pipeline: correlation_engine.py → detect stage (lateral_movement_detection)

Detects lateral movement: an external IP authenticates successfully to host A,
and subsequently host A's IP appears as src_ip connecting to a different internal
host B. Requires cross-event correlation across the full batch.

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

from core.utils.ip_utils import is_private as _is_internal, is_external as _is_external


class LateralMovementDetector:
    """
    Detects lateral movement patterns across an event batch.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
        Returns list of lateral movement alert dicts.
    """

    def detect(self, events: list[dict]) -> list[dict]:
        """
        Scan events for lateral movement patterns.

        Pattern:
            Step 1 — external src_ip logs into internal dst_ip (authentication_success)
            Step 2 — that same internal dst_ip later appears as src_ip connecting
                     to a different internal host

        Args:
            events: list of enriched event dicts (NormalizedEvent.to_dict()).

        Returns:
            list of alert dicts:
            {
                "alert_type": "lateral_movement_detected",
                "confidence": float (0-1),
                "initial_src_ip": str,      # external attacker IP
                "pivot_host": str,          # compromised internal host (Step 1 dst, Step 2 src)
                "lateral_target": str,      # new internal host reached
                "initial_login_ts": str,
                "lateral_event_ts": str,
                "mitre_tactic": "TA0008 - Lateral Movement",
                "mitre_technique": "T1021 - Remote Services",
                "severity": int,
            }
        """
        # Step 1: find external→internal successful logins
        # Maps compromised_host -> {attacker_ip, timestamp, event}
        compromised: dict[str, dict] = {}
        for event in events:
            if event.get("event_type") != "authentication_success":
                continue
            src = event.get("src_ip") or ""
            dst = event.get("dst_ip") or ""
            if _is_external(src) and _is_internal(dst):
                if dst not in compromised:
                    compromised[dst] = {
                        "attacker_ip": src,
                        "timestamp":   event.get("timestamp") or "",
                        "severity":    event.get("severity") or 0,
                    }

        if not compromised:
            return []

        # Step 2: find events where a compromised host is now the src connecting internally
        alerts: list[dict] = []
        fired: set[tuple[str, str]] = set()

        for event in events:
            src = event.get("src_ip") or ""
            dst = event.get("dst_ip") or ""
            if src not in compromised:
                continue
            if not _is_internal(dst) or dst == src:
                continue
            key = (src, dst)
            if key in fired:
                continue
            fired.add(key)

            entry      = compromised[src]
            enrichment = (event.get("metadata") or {}).get("enrichment") or {}
            rep_score  = (enrichment.get("src_reputation") or {}).get("reputation_score", 0.0)
            severity   = max(event.get("severity") or 0, entry["severity"])
            confidence = min(0.75 + rep_score * 0.10, 0.99)

            alerts.append({
                "alert_type":        "lateral_movement_detected",
                "confidence":        round(confidence, 4),
                "initial_src_ip":    entry["attacker_ip"],
                "pivot_host":        src,
                "lateral_target":    dst,
                "initial_login_ts":  entry["timestamp"],
                "lateral_event_ts":  event.get("timestamp") or "",
                "mitre_tactic":      "TA0008 - Lateral Movement",
                "mitre_technique":   "T1021 - Remote Services",
                "severity":          min(severity + 2, 10),
            })

        return alerts
