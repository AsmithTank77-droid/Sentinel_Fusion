"""
narrative/timeline_builder.py — Stage 8: Timeline Construction
Pipeline: score stage → timeline_builder → report_generator

Assembles a chronological attack timeline from enriched events, detection
alerts, and risk scores. Internally calls AttackStoryEngine to produce
the human-readable SOC narrative attached to the timeline.

Stateless. No external libraries.
"""

from __future__ import annotations

import narrative.attack_story_engine as _story_mod


class TimelineBuilder:
    """
    Builds a chronological attack timeline and narrative from pipeline outputs.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        build(events: list[dict], alerts: list[dict], scores: dict) -> list[dict]
        Returns chronologically ordered list of timeline entry dicts.
    """

    def build(
        self,
        events: list[dict],
        alerts: list[dict],
        scores: dict,
    ) -> list[dict]:
        """
        Construct a unified chronological timeline from events and alerts.

        Each timeline entry is a dict describing one moment in the attack:
        {
            "timestamp": str,
            "entry_type": "event" | "alert",
            "event_type": str,
            "src_ip": str,
            "dst_ip": str,
            "severity": int,
            "confidence": float | None,
            "description": str,
            "mitre_tactic": str | None,
            "risk_context": dict,   # relevant score snippets for this entry
        }

        After assembling entries, calls AttackStoryEngine.narrate() to produce
        a human-readable narrative stored in the final sentinel entry:
        {
            "timestamp": "__narrative__",
            "entry_type": "narrative",
            "story": str,
        }

        Args:
            events: list of enriched event dicts.
            alerts: list of detection alert dicts.
            scores: dict from scoring stage {host_risk, asset_risk, attack_surface}.

        Returns:
            Chronologically sorted list of timeline entry dicts, with a
            narrative entry appended as the last element.
        """
        entries: list[dict] = []

        # --- Convert events to timeline entries ---
        for event in events:
            ts    = event.get("timestamp") or ""
            etype = event.get("event_type") or "unknown"
            src   = event.get("src_ip") or ""
            dst   = event.get("dst_ip") or ""
            sev   = event.get("severity") or 0

            # Pull relevant risk context for this host
            host_risk_data = (scores.get("host_risk") or {}).get(dst) or {}
            asset_risk_data = (scores.get("asset_risk") or {}).get(dst) or {}

            entries.append({
                "timestamp":    ts,
                "entry_type":   "event",
                "event_type":   etype,
                "src_ip":       src,
                "dst_ip":       dst,
                "severity":     sev,
                "confidence":   None,
                "description":  self._describe_event(etype, src, dst, sev),
                "mitre_tactic": None,
                "risk_context": {
                    "host_risk_score":     host_risk_data.get("risk_score"),
                    "host_risk_label":     host_risk_data.get("risk_label"),
                    "asset_exposure":      asset_risk_data.get("exposure_score"),
                    "asset_exposure_label": asset_risk_data.get("exposure_label"),
                },
            })

        # --- Convert alerts to timeline entries ---
        for alert in alerts:
            ts    = (
                alert.get("timestamp")
                or alert.get("window_start")
                or alert.get("initial_login_ts")
                or alert.get("timestamps", [""])[0]
                or ""
            )
            atype      = alert.get("alert_type") or "unknown"
            src        = alert.get("src_ip") or alert.get("initial_src_ip") or ""
            dst        = (
                alert.get("dst_ip")
                or alert.get("pivot_host")
                or alert.get("lateral_target")
                or ""
            )
            confidence = alert.get("confidence")
            severity   = alert.get("severity") or alert.get("max_severity") or 0
            tactic     = alert.get("mitre_tactic") or (alert.get("mitre_tactics") or [None])[0]

            host_risk_data  = (scores.get("host_risk") or {}).get(dst) or {}
            asset_risk_data = (scores.get("asset_risk") or {}).get(dst) or {}

            entries.append({
                "timestamp":    ts,
                "entry_type":   "alert",
                "event_type":   atype,
                "src_ip":       src,
                "dst_ip":       dst,
                "severity":     severity,
                "confidence":   confidence,
                "description":  self._describe_alert(alert),
                "mitre_tactic": tactic,
                "risk_context": {
                    "host_risk_score":     host_risk_data.get("risk_score"),
                    "host_risk_label":     host_risk_data.get("risk_label"),
                    "asset_exposure":      asset_risk_data.get("exposure_score"),
                    "asset_exposure_label": asset_risk_data.get("exposure_label"),
                },
            })

        # Sort chronologically; entries without timestamps sort first
        entries.sort(key=lambda e: e.get("timestamp") or "")

        # --- Generate SOC narrative ---
        AttackStoryEngine = getattr(_story_mod, "AttackStoryEngine")
        story = AttackStoryEngine().narrate(
            timeline=[e for e in entries if e["entry_type"] == "event"],
            alerts=alerts,
        )
        entries.append({
            "timestamp":  "__narrative__",
            "entry_type": "narrative",
            "story":      story,
        })

        return entries

    # -----------------------------------------------------------------------
    # Description helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _describe_event(event_type: str, src: str, dst: str, severity: int) -> str:
        _TEMPLATES = {
            "port_scan":              f"Network scan from {src} targeting {dst}",
            "authentication_failure": f"Failed login attempt from {src} to {dst}",
            "authentication_success": f"Successful authentication from {src} to {dst}",
            "lateral_movement":       f"Lateral movement: {src} → {dst}",
            "privilege_escalation":   f"Privilege escalation on {dst} (src: {src})",
            "process_creation":       f"Process spawned on {dst}",
            "service_installed":      f"Service installed on {dst}",
        }
        desc = _TEMPLATES.get(event_type)
        if desc:
            return desc
        return f"{event_type.replace('_', ' ').title()} from {src} to {dst} (severity={severity})"

    @staticmethod
    def _describe_alert(alert: dict) -> str:
        atype = alert.get("alert_type") or "alert"
        conf  = alert.get("confidence")
        conf_str = f" (confidence={conf:.0%})" if conf is not None else ""

        descriptions = {
            "brute_force_detected": (
                f"Brute force attack: {alert.get('failure_count', '?')} failures "
                f"from {alert.get('src_ip')} targeting {alert.get('dst_ip')}{conf_str}"
            ),
            "lateral_movement_detected": (
                f"Lateral movement: attacker pivoted from {alert.get('pivot_host')} "
                f"to {alert.get('lateral_target')}{conf_str}"
            ),
            "correlated_attack_chain": (
                f"Multi-stage attack chain from {alert.get('src_ip')}: "
                f"{' → '.join(alert.get('event_types') or [])}{conf_str}"
            ),
            "malicious_ip_activity": (
                f"Malicious IP {alert.get('src_ip')} active: "
                f"{alert.get('reason', '')}{conf_str}"
            ),
            "tor_exit_node_activity": (
                f"TOR exit node {alert.get('src_ip')} detected{conf_str}"
            ),
            "high_risk_country_access": (
                f"Access from high-risk country: {alert.get('reason', '')}{conf_str}"
            ),
            "off_hours_access": (
                f"Off-hours access: {alert.get('reason', '')}{conf_str}"
            ),
            "threat_feed_match": (
                f"Threat feed match for {alert.get('src_ip')}: "
                f"{alert.get('reason', '')}{conf_str}"
            ),
        }
        return descriptions.get(atype, f"{atype.replace('_', ' ').title()}{conf_str}")
