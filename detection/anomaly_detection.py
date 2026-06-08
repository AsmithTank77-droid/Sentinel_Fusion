"""
detection/anomaly_detection.py — Detection: Behavioral anomalies.
Pipeline: correlation_engine.py → detect stage (anomaly_detection)

Two detection modes:

  Statistical baseline (primary):
      Computes per-IP event volume and unique port spread across the full
      event batch. IPs whose Z-score exceeds 2.0 standard deviations above
      the batch mean are flagged as statistically anomalous. Confidence
      scales with Z-score magnitude (2σ → 0.60, 3σ → 0.75, 4σ+ → 0.90).
      Baselines are derived fresh from each batch — no persistent state.

  Rule-based (secondary):
      Known malicious IP, TOR exit node, high-risk country, off-hours
      access, threat feed match. These fire on individual event signals
      regardless of batch population.

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

import math
from collections import defaultdict
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

_BUSINESS_HOUR_START = 6    # 06:00 UTC
_BUSINESS_HOUR_END   = 20   # 20:00 UTC
_ZSCORE_THRESHOLD    = 2.0  # standard deviations above mean to flag
_MIN_BATCH_SIZE      = 3    # minimum distinct IPs needed for statistical detections
_MIN_PORT_SIGNAL     = 3    # minimum unique ports before port-spread Z-score applies


def _hour_utc(ts: str | None) -> int | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).hour
        except ValueError:
            continue
    return None


def _stats(values: list[float]) -> tuple[float, float]:
    """Return (mean, std_dev) for a list of values. Returns (0, 0) if fewer than 2."""
    if len(values) < 2:
        return 0.0, 0.0
    mean     = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(variance)


def _zscore(value: float, mean: float, std: float) -> float:
    """Standard Z-score. Returns 0 when std is 0 (no variation in population)."""
    return 0.0 if std == 0 else (value - mean) / std


def _confidence_from_zscore(z: float) -> float:
    """Map Z-score magnitude to alert confidence."""
    if z >= 4.0:
        return 0.90
    if z >= 3.0:
        return 0.75
    return 0.60


class AnomalyDetector:
    """
    Detects behavioral anomalies using statistical baselines and rule-based signals.

    Statistical baseline:
        Builds a per-IP profile (event volume, unique port spread) from the full
        event batch. IPs that deviate significantly from the batch mean are flagged
        using Z-score analysis. This catches threats that individually look normal
        but are statistically unusual relative to their peers — low-and-slow scans,
        beaconing, stealthy reconnaissance.

    Rule-based:
        Fires on known indicators: malicious IP reputation, TOR exit nodes,
        high-risk geolocation, off-hours access, threat feed membership.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
    """

    def detect(self, events: list[dict]) -> list[dict]:
        """
        Scan events for behavioral anomalies.

        Returns:
            list of alert dicts, each containing at minimum:
            {
                "alert_type": str,
                "confidence": float (0–1),
                "event_type": str,
                "src_ip":     str,
                "dst_ip":     str,
                "timestamp":  str,
                "severity":   int,
                "mitre_tactic": str,
                "reason":     str,
            }
            Statistical alerts also include a "details" dict with zscore,
            batch_mean, batch_std, and raw counts.
        """
        if not events:
            return []

        fired:  set[tuple[str, str]] = set()
        alerts: list[dict]           = []

        baseline = self._build_baseline(events)

        # Statistical detections — operate over IP population
        if baseline["distinct_ips"] >= _MIN_BATCH_SIZE:
            alerts.extend(self._detect_volume_anomalies(baseline, fired))
            alerts.extend(self._detect_port_spread_anomalies(baseline, fired))

        # Rule-based detections — operate per event
        for event in events:
            alerts.extend(self._detect_rules(event, fired))

        return alerts

    # ------------------------------------------------------------------
    # Baseline construction
    # ------------------------------------------------------------------

    def _build_baseline(self, events: list[dict]) -> dict:
        """
        Compute per-IP statistics from the event batch.

        Returns a baseline dict containing:
            ip_event_counts  — {ip: total events}
            ip_port_sets     — {ip: set of unique ports contacted}
            ip_first_event   — {ip: first event dict seen} for alert field population
            vol_mean/vol_std — population statistics for event volume
            port_mean/std    — population statistics for port spread
            distinct_ips     — number of unique source IPs
        """
        ip_event_counts: dict[str, int]       = defaultdict(int)
        ip_port_sets:    dict[str, set[str]]  = defaultdict(set)
        ip_first_event:  dict[str, dict]      = {}

        for event in events:
            src = event.get("src_ip") or ""
            if not src:
                continue

            ip_event_counts[src] += 1

            if src not in ip_first_event:
                ip_first_event[src] = event

            meta = event.get("metadata") or {}
            port = meta.get("port") or meta.get("dst_port")
            if port:
                ip_port_sets[src].add(str(port))

        volumes    = list(ip_event_counts.values())
        vol_mean, vol_std = _stats(volumes)

        port_counts = [len(s) for s in ip_port_sets.values()]
        port_mean, port_std = _stats(port_counts) if port_counts else (0.0, 0.0)

        return {
            "ip_event_counts": dict(ip_event_counts),
            "ip_port_sets":    {k: v for k, v in ip_port_sets.items()},
            "ip_first_event":  ip_first_event,
            "vol_mean":        vol_mean,
            "vol_std":         vol_std,
            "port_mean":       port_mean,
            "port_std":        port_std,
            "distinct_ips":    len(ip_event_counts),
        }

    # ------------------------------------------------------------------
    # Statistical detections
    # ------------------------------------------------------------------

    def _detect_volume_anomalies(self, baseline: dict, fired: set) -> list[dict]:
        """Flag IPs generating significantly more events than the batch mean."""
        alerts = []
        for ip, count in baseline["ip_event_counts"].items():
            z = _zscore(count, baseline["vol_mean"], baseline["vol_std"])
            if z < _ZSCORE_THRESHOLD:
                continue
            key = ("statistical_volume_anomaly", ip)
            if key in fired:
                continue
            fired.add(key)
            ev         = baseline["ip_first_event"].get(ip, {})
            confidence = _confidence_from_zscore(z)
            alerts.append({
                "alert_type":   "statistical_volume_anomaly",
                "confidence":   round(confidence, 4),
                "event_type":   ev.get("event_type", ""),
                "src_ip":       ip,
                "dst_ip":       ev.get("dst_ip", ""),
                "timestamp":    ev.get("timestamp", ""),
                "severity":     min((ev.get("severity") or 0) + 1, 10),
                "mitre_tactic": "TA0043 - Reconnaissance",
                "reason": (
                    f"{ip} generated {count} events — "
                    f"{z:.1f}σ above batch mean "
                    f"({baseline['vol_mean']:.1f} events/IP)"
                ),
                "details": {
                    "zscore":      round(z, 2),
                    "event_count": count,
                    "batch_mean":  round(baseline["vol_mean"], 2),
                    "batch_std":   round(baseline["vol_std"],  2),
                },
            })
        return alerts

    def _detect_port_spread_anomalies(self, baseline: dict, fired: set) -> list[dict]:
        """Flag IPs contacting significantly more unique ports than the batch mean."""
        alerts = []
        for ip, ports in baseline["ip_port_sets"].items():
            port_count = len(ports)
            if port_count < _MIN_PORT_SIGNAL:
                continue
            z = _zscore(port_count, baseline["port_mean"], baseline["port_std"])
            if z < _ZSCORE_THRESHOLD:
                continue
            key = ("statistical_port_scan_anomaly", ip)
            if key in fired:
                continue
            fired.add(key)
            ev         = baseline["ip_first_event"].get(ip, {})
            confidence = _confidence_from_zscore(z)
            alerts.append({
                "alert_type":   "statistical_port_scan_anomaly",
                "confidence":   round(confidence, 4),
                "event_type":   ev.get("event_type", ""),
                "src_ip":       ip,
                "dst_ip":       ev.get("dst_ip", ""),
                "timestamp":    ev.get("timestamp", ""),
                "severity":     min((ev.get("severity") or 0) + 2, 10),
                "mitre_tactic": "TA0043 - Reconnaissance",
                "reason": (
                    f"{ip} contacted {port_count} unique ports — "
                    f"{z:.1f}σ above batch mean "
                    f"({baseline['port_mean']:.1f} ports/IP)"
                ),
                "details": {
                    "zscore":        round(z, 2),
                    "unique_ports":  port_count,
                    "batch_mean":    round(baseline["port_mean"], 2),
                    "batch_std":     round(baseline["port_std"],  2),
                    "ports_sampled": sorted(ports)[:10],
                },
            })
        return alerts

    # ------------------------------------------------------------------
    # Rule-based detections (original logic, preserved)
    # ------------------------------------------------------------------

    def _detect_rules(self, event: dict, fired: set) -> list[dict]:
        alerts: list[dict] = []

        src        = event.get("src_ip") or ""
        dst        = event.get("dst_ip") or ""
        etype      = event.get("event_type") or ""
        ts         = event.get("timestamp") or ""
        severity   = event.get("severity") or 0
        enrichment = (event.get("metadata") or {}).get("enrichment") or {}
        src_rep    = enrichment.get("src_reputation") or {}
        src_geo    = enrichment.get("src_geo") or {}
        src_threats = enrichment.get("src_threats") or {}

        # Rule 1: known malicious IP
        if src_rep.get("is_malicious") and src:
            key = ("malicious_ip_activity", src)
            if key not in fired:
                fired.add(key)
                rep_score  = src_rep.get("reputation_score", 0.5)
                confidence = min(0.70 + rep_score * 0.20, 0.99)
                alerts.append({
                    "alert_type":   "malicious_ip_activity",
                    "confidence":   round(confidence, 4),
                    "event_type":   etype,
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "timestamp":    ts,
                    "severity":     min(severity + 1, 10),
                    "mitre_tactic": "TA0043 - Reconnaissance",
                    "reason": (
                        f"Source IP {src!r} is flagged malicious "
                        f"(score={rep_score}, categories="
                        f"{src_rep.get('categories', [])})"
                    ),
                })

        # Rule 2: TOR exit node
        if src_geo.get("is_tor") and src:
            key = ("tor_exit_node_activity", src)
            if key not in fired:
                fired.add(key)
                alerts.append({
                    "alert_type":   "tor_exit_node_activity",
                    "confidence":   0.85,
                    "event_type":   etype,
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "timestamp":    ts,
                    "severity":     min(severity + 1, 10),
                    "mitre_tactic": "TA0005 - Defense Evasion",
                    "reason":       f"Source IP {src!r} is a TOR exit node",
                })

        # Rule 3: high-risk country
        if src_geo.get("high_risk_country") and src:
            key = ("high_risk_country_access", src)
            if key not in fired:
                fired.add(key)
                country = src_geo.get("country", "Unknown")
                alerts.append({
                    "alert_type":   "high_risk_country_access",
                    "confidence":   0.65,
                    "event_type":   etype,
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "timestamp":    ts,
                    "severity":     severity,
                    "mitre_tactic": "TA0043 - Reconnaissance",
                    "reason":       f"Traffic from high-risk country: {country}",
                })

        # Rule 4: off-hours access
        hour = _hour_utc(ts)
        if hour is not None and not (_BUSINESS_HOUR_START <= hour < _BUSINESS_HOUR_END):
            key = ("off_hours_access", src)
            if key not in fired:
                fired.add(key)
                alerts.append({
                    "alert_type":   "off_hours_access",
                    "confidence":   0.55,
                    "event_type":   etype,
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "timestamp":    ts,
                    "severity":     severity,
                    "mitre_tactic": "TA0003 - Persistence",
                    "reason":       f"Activity at off-hours UTC hour {hour:02d}:xx",
                })

        # Rule 5: threat feed hit
        feed_hits = src_threats.get("feed_hits") or []
        if feed_hits and src:
            key = ("threat_feed_match", src)
            if key not in fired:
                fired.add(key)
                tf_confidence = src_threats.get("confidence", 0.5)
                alerts.append({
                    "alert_type":   "threat_feed_match",
                    "confidence":   round(min(tf_confidence + 0.05, 0.99), 4),
                    "event_type":   etype,
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "timestamp":    ts,
                    "severity":     min(severity + 1, 10),
                    "mitre_tactic": "TA0043 - Reconnaissance",
                    "reason":       f"Matches threat feeds: {feed_hits}",
                })

        return alerts
