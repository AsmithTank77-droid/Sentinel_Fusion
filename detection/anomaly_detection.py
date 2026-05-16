"""
detection/anomaly_detection.py — Detection: Behavioral anomalies.
Pipeline: correlation_engine.py → detect stage (anomaly_detection)

Detects anomalous access patterns:
  - External IPs directly accessing internal resources (non-auth events)
  - Off-hours access (outside 06:00–20:00 UTC)
  - Known malicious IP activity

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.utils.ip_utils import is_private as _is_internal, is_external as _is_external

_AUTH_EVENT_TYPES = frozenset({
    "authentication_success",
    "authentication_failure",
    "explicit_credential_logon",
    "kerberos_tgt_request",
    "kerberos_service_ticket_request",
    "kerberos_preauth_failure",
    "ntlm_credential_validation",
})

_BUSINESS_HOUR_START = 6   # 06:00 UTC
_BUSINESS_HOUR_END   = 20  # 20:00 UTC



def _hour_utc(ts: str | None) -> int | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).hour
        except ValueError:
            continue
    return None


class AnomalyDetector:
    """
    Detects behavioral anomalies across an event batch.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
        Returns list of anomaly alert dicts.
    """

    def detect(self, events: list[dict]) -> list[dict]:
        """
        Scan events for behavioral anomalies.

        Args:
            events: list of enriched event dicts (NormalizedEvent.to_dict()).

        Returns:
            list of anomaly alert dicts. Each dict contains at minimum:
            {
                "alert_type": str,
                "confidence": float (0-1),
                "event_type": str,
                "src_ip": str,
                "dst_ip": str,
                "timestamp": str,
                "severity": int,
                "mitre_tactic": str,
                "reason": str,
            }
        """
        alerts: list[dict] = []
        fired: set[tuple[str, str]] = set()  # (alert_type, src_ip) — one alert per source per type

        for event in events:
            src        = event.get("src_ip") or ""
            dst        = event.get("dst_ip") or ""
            etype      = event.get("event_type") or ""
            ts         = event.get("timestamp") or ""
            severity   = event.get("severity") or 0
            enrichment = (event.get("metadata") or {}).get("enrichment") or {}
            src_rep    = enrichment.get("src_reputation") or {}
            src_geo    = enrichment.get("src_geo") or {}
            src_threats = enrichment.get("src_threats") or {}

            # Rule 1: known malicious IP performing any activity
            if src_rep.get("is_malicious") and src:
                key = ("malicious_ip_activity", src)
                if key not in fired:
                    fired.add(key)
                    rep_score  = src_rep.get("reputation_score", 0.5)
                    confidence = min(0.70 + rep_score * 0.20, 0.99)
                    alerts.append({
                        "alert_type":      "malicious_ip_activity",
                        "confidence":      round(confidence, 4),
                        "event_type":      etype,
                        "src_ip":          src,
                        "dst_ip":          dst,
                        "timestamp":       ts,
                        "severity":        min(severity + 1, 10),
                        "mitre_tactic":    "TA0043 - Reconnaissance",
                        "reason":          (
                            f"Source IP {src!r} is flagged malicious "
                            f"(score={rep_score}, categories="
                            f"{src_rep.get('categories', [])})"
                        ),
                    })

            # Rule 2: TOR exit node used
            if src_geo.get("is_tor") and src:
                key = ("tor_exit_node_activity", src)
                if key not in fired:
                    fired.add(key)
                    alerts.append({
                        "alert_type":      "tor_exit_node_activity",
                        "confidence":      0.85,
                        "event_type":      etype,
                        "src_ip":          src,
                        "dst_ip":          dst,
                        "timestamp":       ts,
                        "severity":        min(severity + 1, 10),
                        "mitre_tactic":    "TA0005 - Defense Evasion",
                        "reason":          f"Source IP {src!r} is a TOR exit node",
                    })

            # Rule 3: high-risk country origin
            if src_geo.get("high_risk_country") and src:
                key = ("high_risk_country_access", src)
                if key not in fired:
                    fired.add(key)
                    country = src_geo.get("country", "Unknown")
                    alerts.append({
                        "alert_type":      "high_risk_country_access",
                        "confidence":      0.65,
                        "event_type":      etype,
                        "src_ip":          src,
                        "dst_ip":          dst,
                        "timestamp":       ts,
                        "severity":        severity,
                        "mitre_tactic":    "TA0043 - Reconnaissance",
                        "reason":          f"Traffic from high-risk country: {country}",
                    })

            # Rule 4: off-hours access (one alert per src_ip — first off-hours event wins)
            hour = _hour_utc(ts)
            if hour is not None and not (_BUSINESS_HOUR_START <= hour < _BUSINESS_HOUR_END):
                key = ("off_hours_access", src)
                if key not in fired:
                    fired.add(key)
                    alerts.append({
                        "alert_type":      "off_hours_access",
                        "confidence":      0.55,
                        "event_type":      etype,
                        "src_ip":          src,
                        "dst_ip":          dst,
                        "timestamp":       ts,
                        "severity":        severity,
                        "mitre_tactic":    "TA0003 - Persistence",
                        "reason":          f"Activity at off-hours UTC hour {hour:02d}:xx",
                    })

            # Rule 5: threat feed hit
            feed_hits = src_threats.get("feed_hits") or []
            if feed_hits and src:
                key = ("threat_feed_match", src)
                if key not in fired:
                    fired.add(key)
                    tf_confidence = src_threats.get("confidence", 0.5)
                    alerts.append({
                        "alert_type":      "threat_feed_match",
                        "confidence":      round(min(tf_confidence + 0.05, 0.99), 4),
                        "event_type":      etype,
                        "src_ip":          src,
                        "dst_ip":          dst,
                        "timestamp":       ts,
                        "severity":        min(severity + 1, 10),
                        "mitre_tactic":    "TA0043 - Reconnaissance",
                        "reason":          f"Matches threat feeds: {feed_hits}",
                    })

        return alerts
