"""
reporting/report_generator.py — Stage 9: SOC Report Generation
Pipeline: timeline_builder → report_generator

Produces the final structured SOC report in two formats:
  - JSON (machine-readable, complete data)
  - Markdown (human-readable, SOC analyst view)

Stateless. No external libraries. stdlib json only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from intelligence.service_intelligence import get_service_risk
from reporting.recommended_actions import generate_recommendations
from reporting.executive_summary import ExecutiveSummary


def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_to_risk_label(score: int) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Informational"


def _build_nra_scan_data(
    normalized_events: list[dict],
    host_risk: dict,
) -> list[dict]:
    """
    Build the scan_data list consumed by generate_recommendations() from
    NRA normalized events and host_risk scores.

    NRA events use dst_ip as the scanned host address (src_ip is the scanner,
    which is empty when parsed from XML). Ports live in metadata["ports"].
    """
    hosts: dict[str, list[dict]] = {}
    for event in normalized_events:
        if event.get("source_type") != "nra":
            continue
        ip    = str(event.get("dst_ip") or event.get("src_ip") or "unknown")
        ports = event.get("metadata", {}).get("ports", [])
        hosts.setdefault(ip, []).extend(ports)

    scan_data: list[dict] = []
    for ip, ports in hosts.items():
        risk_info  = host_risk.get(ip, {})
        raw_label  = str(risk_info.get("risk_label", "low"))
        risk_level = raw_label.capitalize()

        port_records: list[dict] = []
        for p in ports:
            svc   = str(p.get("service", "unknown"))
            score = get_service_risk(svc)
            port_records.append({
                "port":     p.get("port", 0),
                "protocol": p.get("protocol", "tcp"),
                "service":  svc,
                "state":    p.get("state", "open"),
                "risk":     _score_to_risk_label(score),
            })

        scan_data.append({
            "ip":         ip,
            "risk_level": risk_level,
            "ports":      port_records,
        })

    return scan_data


class ReportGenerator:
    """
    Generates a structured SOC report from pipeline outputs.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        generate(timeline: list[dict], scores: dict, alerts: list[dict])
        -> {"json": dict, "markdown": str}
    """

    def generate(
        self,
        timeline: list[dict],
        scores: dict,
        alerts: list[dict],
        normalized_events: list[dict] | None = None,
    ) -> dict:
        """
        Produce the final SOC report.

        Args:
            timeline: chronological timeline entries (from TimelineBuilder).
            scores:   scoring stage output {host_risk, asset_risk, attack_surface}.
            alerts:   all detection alerts.

        Returns:
            {
                "json":     dict  — complete structured report,
                "markdown": str   — formatted SOC analyst report,
            }
        """
        generated_at = _now_utc()

        # Extract the narrative entry if present
        narrative_entry = next(
            (e for e in timeline if e.get("entry_type") == "narrative"), None
        )
        story = narrative_entry.get("story", "") if narrative_entry else ""
        visible_timeline = [e for e in timeline if e.get("entry_type") != "narrative"]

        # Compute top-level summary stats
        event_entries = [e for e in visible_timeline if e.get("entry_type") == "event"]
        alert_entries = [e for e in visible_timeline if e.get("entry_type") == "alert"]

        host_risk    = scores.get("host_risk") or {}
        asset_risk   = scores.get("asset_risk") or {}
        atk_surface  = scores.get("attack_surface") or {}

        highest_host = max(
            host_risk.values(),
            key=lambda h: h.get("risk_score", 0.0),
            default=None,
        )
        highest_asset = max(
            asset_risk.values(),
            key=lambda a: a.get("exposure_score", 0.0),
            default=None,
        )

        nra_scan_data       = _build_nra_scan_data(normalized_events or [], host_risk)
        nra_recommendations = generate_recommendations(nra_scan_data)
        executive_summary   = ExecutiveSummary().generate(
            timeline, scores, alerts, nra_recommendations
        )

        json_report = {
            "report_type":    "sentinel_fusion_soc_report",
            "generated_at":   generated_at,
            "summary": {
                "total_events":       len(event_entries),
                "total_alerts":       len(alert_entries) + len(alerts),
                "unique_alert_types": list(dict.fromkeys(
                    a.get("alert_type") or "" for a in alerts
                )),
                "expansion_label":    atk_surface.get("expansion_label"),
                "expansion_score":    atk_surface.get("expansion_score"),
                "highest_host_risk":  {
                    "host": next(
                        (h for h, v in host_risk.items()
                         if v is highest_host), None
                    ) if highest_host else None,
                    "score": highest_host.get("risk_score") if highest_host else None,
                    "label": highest_host.get("risk_label") if highest_host else None,
                },
                "lateral_movement_hops": atk_surface.get("lateral_movement_hops", 0),
                "mitre_tactics":         atk_surface.get("mitre_tactics_observed", []),
            },
            "timeline":            visible_timeline,
            "alerts":              alerts,
            "scores":              scores,
            "narrative":           story,
            "nra_recommendations": nra_recommendations,
            "executive_summary":   executive_summary,
        }

        markdown_report = self._build_markdown(
            generated_at=generated_at,
            event_entries=event_entries,
            alerts=alerts,
            host_risk=host_risk,
            asset_risk=asset_risk,
            atk_surface=atk_surface,
            story=story,
            visible_timeline=visible_timeline,
            nra_recommendations=nra_recommendations,
            executive_summary=executive_summary,
        )

        return {
            "json":     json_report,
            "markdown": markdown_report,
        }

    # -----------------------------------------------------------------------
    # Markdown builder
    # -----------------------------------------------------------------------

    def _build_markdown(
        self,
        generated_at: str,
        event_entries: list[dict],
        alerts: list[dict],
        host_risk: dict,
        asset_risk: dict,
        atk_surface: dict,
        story: str,
        visible_timeline: list[dict],
        nra_recommendations: list[dict] | None = None,
        executive_summary: dict | None = None,
    ) -> str:
        lines: list[str] = []

        lines.append("# Sentinel_Fusion SOC Report")
        lines.append(f"**Generated:** {generated_at}  ")
        lines.append(f"**Total Events:** {len(event_entries)}  ")
        lines.append(f"**Total Alerts:** {len(alerts)}")
        lines.append("")

        # --- Executive Summary ---
        if executive_summary:
            lines.append(executive_summary["markdown"])

        # --- Attack Surface Overview ---
        lines.append("---")
        lines.append("## Attack Surface Overview")
        lines.append("")
        if atk_surface:
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Expansion Score | {atk_surface.get('expansion_score', 0):.1f} / 10 |")
            lines.append(f"| Expansion Label | **{atk_surface.get('expansion_label', 'unknown')}** |")
            lines.append(f"| External Sources | {atk_surface.get('unique_external_sources', 0)} |")
            lines.append(f"| Internal Targets | {atk_surface.get('unique_internal_targets', 0)} |")
            lines.append(f"| Lateral Movement Hops | {atk_surface.get('lateral_movement_hops', 0)} |")
            lines.append(f"| Distinct Event Types | {atk_surface.get('unique_attack_techniques', 0)} |")
            lines.append("")
            tactics = atk_surface.get("mitre_tactics_observed") or []
            if tactics:
                lines.append("**MITRE ATT&CK Tactics Observed:**")
                for t in tactics:
                    lines.append(f"- {t}")
                lines.append("")

        # --- Host Risk ---
        lines.append("---")
        lines.append("## Host Risk Scores")
        lines.append("")
        if host_risk:
            lines.append("| Host | Risk Score | Label | Alerts | Max Severity |")
            lines.append("|------|-----------|-------|--------|--------------|")
            for host, data in sorted(
                host_risk.items(),
                key=lambda kv: kv[1].get("risk_score", 0),
                reverse=True,
            ):
                lines.append(
                    f"| `{host}` | {data.get('risk_score', 0):.1f} | "
                    f"**{data.get('risk_label', 'unknown')}** | "
                    f"{data.get('alert_count', 0)} | {data.get('max_event_severity', 0)} |"
                )
            lines.append("")
        else:
            lines.append("_No host risk data._")
            lines.append("")

        # --- Asset Exposure ---
        lines.append("---")
        lines.append("## Asset Exposure")
        lines.append("")
        if asset_risk:
            lines.append("| Asset | Exposure Score | Label | Lateral Target |")
            lines.append("|-------|---------------|-------|----------------|")
            for asset, data in sorted(
                asset_risk.items(),
                key=lambda kv: kv[1].get("exposure_score", 0),
                reverse=True,
            ):
                lat = "Yes" if data.get("is_lateral_target") else "No"
                lines.append(
                    f"| `{asset}` | {data.get('exposure_score', 0):.1f} | "
                    f"**{data.get('exposure_label', 'unknown')}** | {lat} |"
                )
            lines.append("")
        else:
            lines.append("_No asset exposure data._")
            lines.append("")

        # --- Detection Alerts ---
        lines.append("---")
        lines.append("## Detection Alerts")
        lines.append("")
        if alerts:
            for alert in alerts:
                atype      = alert.get("alert_type") or "unknown"
                conf       = alert.get("confidence")
                conf_str   = f"{conf:.0%}" if conf is not None else "N/A"
                tactic     = alert.get("mitre_tactic") or ""
                lines.append(f"### {atype.replace('_', ' ').title()}")
                lines.append(f"- **Confidence:** {conf_str}")
                if tactic:
                    lines.append(f"- **MITRE:** {tactic}")
                src = alert.get("src_ip") or alert.get("initial_src_ip") or ""
                dst = alert.get("dst_ip") or alert.get("lateral_target") or ""
                if src:
                    lines.append(f"- **Source:** `{src}`")
                if dst:
                    lines.append(f"- **Target:** `{dst}`")
                reason = alert.get("reason") or ""
                if reason:
                    lines.append(f"- **Detail:** {reason}")
                lines.append("")
        else:
            lines.append("_No alerts generated._")
            lines.append("")

        # --- Attack Timeline ---
        lines.append("---")
        lines.append("## Attack Timeline")
        lines.append("")
        event_timeline = [e for e in visible_timeline if e.get("entry_type") == "event"]
        if event_timeline:
            lines.append("| Timestamp | Event Type | Src IP | Dst IP | Severity |")
            lines.append("|-----------|------------|--------|--------|----------|")
            for entry in event_timeline:
                lines.append(
                    f"| `{entry.get('timestamp', '')}` | "
                    f"{entry.get('event_type', '')} | "
                    f"`{entry.get('src_ip', '')}` | "
                    f"`{entry.get('dst_ip', '')}` | "
                    f"{entry.get('severity', 0)} |"
                )
            lines.append("")
        else:
            lines.append("_No timeline events._")
            lines.append("")

        # --- Narrative ---
        if story:
            lines.append("---")
            lines.append("")
            lines.append(story)
            lines.append("")

        # --- NRA Recommended Actions ---
        if nra_recommendations:
            lines.append("---")
            lines.append("## NRA Recommended Actions")
            lines.append("")
            for host in nra_recommendations:
                lines.append(f"### Host: `{host['ip']}` — {host['overall_risk_level']} Risk")
                lines.append("")
                lines.append(host["overall_host_summary"])
                lines.append("")
                for rec in host.get("recommendations", []):
                    lines.append(
                        f"#### Port {rec['port']}/{rec['protocol']} — "
                        f"{rec['service'].upper()} ({rec['risk_level']}, Priority {rec['priority']})"
                    )
                    lines.append(f"**Category:** {rec['category']} / {rec['subcategory']}  ")
                    lines.append(f"**Context:** {rec['service_context']}  ")
                    lines.append(f"**Rationale:** {rec['risk_rationale']}  ")
                    lines.append(f"**Action:** {rec['action_taken']}  ")
                    if rec.get("notable_cves"):
                        lines.append(f"**CVEs:** {', '.join(rec['notable_cves'])}  ")
                    lines.append("")

        lines.append("---")
        lines.append("_Report generated by Sentinel_Fusion SOC Pipeline_")

        return "\n".join(lines)
