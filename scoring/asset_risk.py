"""
scoring/asset_risk.py — Scoring: Asset exposure assessment.
Pipeline: detect stage → score stage (asset_risk)

Evaluates exposure risk for observed assets (by event_type and dst_ip),
focusing on what capabilities or services have been accessed or targeted.

Stateless. No external libraries.
"""

from __future__ import annotations

from collections import defaultdict


# Event types that indicate sensitive asset exposure
_HIGH_EXPOSURE_EVENT_TYPES = frozenset({
    "authentication_success",
    "explicit_credential_logon",
    "privileged_logon",
    "service_installed",
    "scheduled_task_created",
    "account_created",
    "domain_group_member_added",
    "local_group_member_added",
    "universal_group_member_added",
    "new_service_installed",
})

_MEDIUM_EXPOSURE_EVENT_TYPES = frozenset({
    "authentication_failure",
    "kerberos_preauth_failure",
    "process_creation",
    "lateral_movement",
    "port_scan",
})


class AssetRisk:
    """
    Computes asset exposure risk from enriched events and alerts.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        score(events: list[dict], alerts: list[dict]) -> dict
        Returns asset exposure summary keyed by dst_ip.
    """

    def score(self, events: list[dict], alerts: list[dict]) -> dict:
        """
        Assess asset exposure risk for each targeted host.

        Args:
            events: list of enriched event dicts.
            alerts: list of alert dicts from detection stage.

        Returns:
            dict keyed by asset IP:
            {
                "<asset_ip>": {
                    "exposure_score": float,      # 0.0-10.0
                    "exposure_label": str,        # "low"/"medium"/"high"/"critical"
                    "high_risk_event_count": int,
                    "event_types_observed": list[str],
                    "alert_count": int,
                    "is_lateral_target": bool,
                    "factors": list[str],
                }
            }
        """
        if not events and not alerts:
            return {}

        asset_events: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            dst = event.get("dst_ip") or ""
            if dst:
                asset_events[dst].append(event)

        lateral_targets: set[str] = set()
        asset_alert_counts: dict[str, int] = defaultdict(int)
        for alert in alerts:
            if alert.get("alert_type") == "lateral_movement_detected":
                tgt = alert.get("lateral_target") or ""
                if tgt:
                    lateral_targets.add(tgt)
            for field in ("dst_ip", "pivot_host", "lateral_target"):
                host = alert.get(field) or ""
                if host:
                    asset_alert_counts[host] += 1

        all_assets = set(asset_events) | set(asset_alert_counts)
        result: dict = {}

        for asset in all_assets:
            evts   = asset_events.get(asset, [])
            factors: list[str] = []

            event_types = list(dict.fromkeys(e.get("event_type") or "" for e in evts))
            high_count  = sum(1 for et in event_types if et in _HIGH_EXPOSURE_EVENT_TYPES)
            med_count   = sum(1 for et in event_types if et in _MEDIUM_EXPOSURE_EVENT_TYPES)

            exposure_score = (high_count * 2.0) + (med_count * 1.0)

            if high_count:
                factors.append(f"{high_count} high-exposure event type(s): "
                                f"{[et for et in event_types if et in _HIGH_EXPOSURE_EVENT_TYPES]}")
            if med_count:
                factors.append(f"{med_count} medium-exposure event type(s)")

            alert_count = asset_alert_counts.get(asset, 0)
            if alert_count:
                exposure_score += min(alert_count * 0.75, 3.0)
                factors.append(f"{alert_count} alert(s) referencing this asset")

            is_lateral = asset in lateral_targets
            if is_lateral:
                exposure_score += 2.0
                factors.append("identified as lateral movement target")

            exposure_score = min(exposure_score, 10.0)

            if exposure_score >= 8.0:
                label = "critical"
            elif exposure_score >= 5.0:
                label = "high"
            elif exposure_score >= 2.0:
                label = "medium"
            else:
                label = "low"

            result[asset] = {
                "exposure_score":        round(exposure_score, 2),
                "exposure_label":        label,
                "high_risk_event_count": high_count,
                "event_types_observed":  event_types,
                "alert_count":           alert_count,
                "is_lateral_target":     is_lateral,
                "factors":               factors,
            }

        return result
