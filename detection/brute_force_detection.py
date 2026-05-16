"""
detection/brute_force_detection.py — Detection: SSH/authentication brute force.
Pipeline: correlation_engine.py → detect stage (brute_force_detection)

Detects credential brute-force patterns: 3 or more authentication failures
from the same src_ip within a 5-minute sliding window.

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from config.settings import settings as _settings

_FAILURE_THRESHOLD = _settings.brute_force_threshold
_WINDOW_SECONDS    = _settings.brute_force_window


def _parse_ts(ts: str | None) -> float:
    """Parse ISO 8601 UTC string to UNIX epoch float. Returns 0.0 on failure."""
    if not ts:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


class BruteForceDetector:
    """
    Detects authentication brute-force attempts.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        detect(events: list[dict]) -> list[dict]
        Returns list of brute-force alert dicts.
    """

    def detect(self, events: list[dict]) -> list[dict]:
        """
        Scan events for brute-force patterns.

        A brute-force alert fires when a src_ip generates >= 3 authentication
        failures within any 5-minute window.

        Args:
            events: list of enriched event dicts (NormalizedEvent.to_dict()).

        Returns:
            list of alert dicts:
            {
                "alert_type": "brute_force_detected",
                "confidence": float (0-1),
                "src_ip": str,
                "dst_ip": str,
                "failure_count": int,
                "window_start": str,
                "window_end": str,
                "event_type": "authentication_failure",
                "mitre_tactic": "TA0006 - Credential Access",
                "mitre_technique": "T1110 - Brute Force",
                "severity": int,
            }
        """
        # Collect auth failures per (src_ip, dst_ip) pair
        failures: dict[tuple[str, str], list[dict]] = {}
        for event in events:
            if event.get("event_type") != "authentication_failure":
                continue
            src = event.get("src_ip") or ""
            dst = event.get("dst_ip") or ""
            key = (src, dst)
            if key not in failures:
                failures[key] = []
            failures[key].append(event)

        alerts: list[dict] = []
        for (src_ip, dst_ip), fail_events in failures.items():
            sorted_fails = sorted(fail_events, key=lambda e: _parse_ts(e.get("timestamp")))

            # Sliding window: find windows where >= threshold failures occur
            fired_windows: set[tuple[int, int]] = set()
            for i, anchor in enumerate(sorted_fails):
                t_start = _parse_ts(anchor.get("timestamp"))
                window  = [e for e in sorted_fails[i:]
                           if _parse_ts(e.get("timestamp")) - t_start <= _WINDOW_SECONDS]
                if len(window) < _FAILURE_THRESHOLD:
                    continue
                # Deduplicate overlapping windows by (start_idx, end_count)
                key = (i, len(window))
                if key in fired_windows:
                    continue
                fired_windows.add(key)

                failure_count = len(window)
                window_start  = window[0].get("timestamp") or ""
                window_end    = window[-1].get("timestamp") or ""
                max_severity  = max(e.get("severity") or 0 for e in window)

                # Confidence: scales with count beyond threshold and reputation
                base_conf = min(0.60 + (failure_count - _FAILURE_THRESHOLD) * 0.05, 0.85)
                enrichment = (anchor.get("metadata") or {}).get("enrichment") or {}
                rep_score  = (enrichment.get("src_reputation") or {}).get("reputation_score", 0.0)
                confidence = min(base_conf + rep_score * 0.1, 0.99)

                alerts.append({
                    "alert_type":       "brute_force_detected",
                    "confidence":       round(confidence, 4),
                    "src_ip":           src_ip,
                    "dst_ip":           dst_ip,
                    "failure_count":    failure_count,
                    "window_start":     window_start,
                    "window_end":       window_end,
                    "event_type":       "authentication_failure",
                    "mitre_tactic":     "TA0006 - Credential Access",
                    "mitre_technique":  "T1110 - Brute Force",
                    "severity":         min(max_severity + 2, 10),
                })
                break  # one alert per (src_ip, dst_ip) pair

        return alerts
