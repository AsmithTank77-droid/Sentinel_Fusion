"""
reporting/executive_summary.py — Executive-level SOC summary.

Distils pipeline output into a CISO-facing verdict, key findings,
and immediate actions.  Consumed by report_generator.py and the
FastAPI /report endpoint.

Public API
----------
ExecutiveSummary().generate(timeline, scores, alerts, nra_recommendations) → dict

Output schema:
  {
    "verdict":           str,        # "Critical" / "High" / "Medium" / "Low" / "Clean"
    "generated_at":      str,        # ISO-8601 UTC
    "key_findings":      list[str],  # ordered, most severe first
    "immediate_actions": list[str],  # concrete SOC actions required now
    "risk_surface": {
      "critical_hosts":            int,
      "high_hosts":                int,
      "medium_hosts":              int,
      "low_hosts":                 int,
      "total_alerts":              int,
      "winlog_rules_fired":        list[str],  # e.g. ["WINLOG-002", "WINLOG-006"]
      "attack_surface_label":      str,
      "lateral_movement_detected": bool,
      "mitre_tactics":             list[str],
    },
    "markdown": str,
  }
"""
from __future__ import annotations

from datetime import datetime, timezone

from config.settings import settings as _settings


# WINLOG rule IDs whose firing always warrants an immediate action entry
_CRITICAL_WINLOG_RULES: dict[str, str] = {
    "WINLOG-002": (
        "Brute-force succeeded — force immediate credential reset for all "
        "accounts targeted on the affected host."
    ),
    "WINLOG-003": (
        "Backdoor account added to a security group — disable the account "
        "and investigate the originating session immediately."
    ),
    "WINLOG-006": (
        "Audit log cleared — treat as active evidence tampering. "
        "Engage incident response and preserve all available artefacts."
    ),
    "WINLOG-009": (
        "Scheduled task persistence detected — enumerate and remove "
        "unauthorised scheduled tasks; review the process that created them."
    ),
}

# Attack surface labels that warrant an escalation note
_ESCALATION_LABELS: frozenset[str] = frozenset({"significant", "critical"})

_LABEL_ORDER: list[str] = ["critical", "high", "medium", "low"]


def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _capitalise(label: str) -> str:
    return label.capitalize() if label else "Unknown"


class ExecutiveSummary:
    """
    Stateless executive summary generator.
    Accepts the same inputs as ReportGenerator.generate() plus nra_recommendations.
    """

    def generate(
        self,
        timeline: list[dict],
        scores: dict,
        alerts: list[dict],
        nra_recommendations: list[dict] | None = None,
    ) -> dict:
        """
        Produce an executive-level SOC summary.

        Parameters
        ----------
        timeline            : chronological timeline entries from TimelineBuilder.
        scores              : scoring stage output {host_risk, asset_risk, attack_surface}.
        alerts              : all detection alerts from the pipeline.
        nra_recommendations : output of generate_recommendations() (optional).

        Returns
        -------
        dict with keys: verdict, generated_at, key_findings,
                        immediate_actions, risk_surface, markdown.
        """
        host_risk   = scores.get("host_risk")   or {}
        atk_surface = scores.get("attack_surface") or {}
        nra_recs    = nra_recommendations or []

        # ── Risk surface counts ──────────────────────────────────────────────
        counts: dict[str, int] = {lbl: 0 for lbl in _LABEL_ORDER}
        for data in host_risk.values():
            lbl = str(data.get("risk_label", "low")).lower()
            if lbl in counts:
                counts[lbl] += 1

        lateral_detected = int(atk_surface.get("lateral_movement_hops", 0)) > 0
        atk_label        = str(atk_surface.get("expansion_label", "unknown"))
        mitre_tactics    = list(atk_surface.get("mitre_tactics_observed") or [])

        winlog_fired: list[str] = sorted({
            str(a.get("alert_type", ""))
            for a in alerts
            if str(a.get("alert_type", "")).startswith("WINLOG-")
        })

        # Alerts that meet the confidence floor — used for verdict only.
        # All alerts are still reported; only significant ones escalate the verdict.
        floor = float(_settings.verdict_confidence_floor)
        significant_alerts = [
            a for a in alerts
            if float(a.get("confidence") or 0) >= floor
        ]

        risk_surface = {
            "critical_hosts":            counts["critical"],
            "high_hosts":                counts["high"],
            "medium_hosts":              counts["medium"],
            "low_hosts":                 counts["low"],
            "total_alerts":              len(alerts),
            "significant_alerts":        len(significant_alerts),
            "verdict_confidence_floor":  floor,
            "winlog_rules_fired":        winlog_fired,
            "attack_surface_label":      atk_label,
            "lateral_movement_detected": lateral_detected,
            "mitre_tactics":             mitre_tactics,
        }

        # ── Verdict ─────────────────────────────────────────────────────────
        if counts["critical"] > 0:
            verdict = "Critical"
        elif counts["high"] > 0 or lateral_detected:
            verdict = "High"
        elif counts["medium"] > 0 or significant_alerts:
            verdict = "Medium"
        elif counts["low"] > 0:
            verdict = "Low"
        else:
            verdict = "Clean"

        # ── Key findings ────────────────────────────────────────────────────
        findings: list[str] = []

        # Highest-risk host
        if host_risk:
            top_host, top_data = max(
                host_risk.items(),
                key=lambda kv: kv[1].get("risk_score", 0.0),
            )
            top_score = top_data.get("risk_score", 0.0)
            top_label = _capitalise(str(top_data.get("risk_label", "unknown")))
            findings.append(
                f"Highest-risk host: {top_host} — {top_label} "
                f"(score {top_score:.1f}/10)."
            )

        # Host count summary
        critical_n = counts["critical"]
        high_n     = counts["high"]
        if critical_n or high_n:
            parts = []
            if critical_n:
                parts.append(f"{critical_n} Critical")
            if high_n:
                parts.append(f"{high_n} High")
            findings.append(
                f"{sum(counts.values())} host(s) assessed; "
                f"{' and '.join(parts)} risk host(s) require immediate attention."
            )

        # Lateral movement
        if lateral_detected:
            hops = int(atk_surface.get("lateral_movement_hops", 0))
            findings.append(
                f"Lateral movement detected across {hops} hop(s) — "
                "attacker has likely pivoted beyond the initial entry point."
            )

        # Attack surface
        if atk_label.lower() in _ESCALATION_LABELS:
            exp_score = atk_surface.get("expansion_score", 0.0)
            findings.append(
                f"Attack surface expansion rated '{atk_label.title()}' "
                f"(score {exp_score:.1f}/10) — "
                "multiple techniques and targets observed in this session."
            )

        # WINLOG rules
        if winlog_fired:
            rule_list = ", ".join(winlog_fired)
            findings.append(
                f"{len(winlog_fired)} Windows behavioural rule(s) fired: {rule_list}."
            )

        # NRA critical/high services
        critical_nra_services: list[str] = []
        for host in nra_recs:
            for rec in host.get("recommendations", []):
                if rec.get("priority", 5) <= 2:
                    critical_nra_services.append(
                        f"{rec['service'].upper()} on {host['ip']}:{rec['port']}"
                    )
        if critical_nra_services:
            top = critical_nra_services[:3]
            suffix = (
                f" (+{len(critical_nra_services) - 3} more)"
                if len(critical_nra_services) > 3 else ""
            )
            findings.append(
                f"Critical/High NRA service exposure: "
                f"{', '.join(top)}{suffix}."
            )

        # MITRE tactics
        if mitre_tactics:
            findings.append(
                f"MITRE ATT&CK tactics observed: {', '.join(mitre_tactics)}."
            )

        # ── Immediate actions ────────────────────────────────────────────────
        actions: list[str] = []

        # Critical hosts — isolate
        if counts["critical"] > 0:
            crit_hosts = [
                h for h, d in host_risk.items()
                if str(d.get("risk_label", "")).lower() == "critical"
            ]
            actions.append(
                f"Isolate Critical host(s) pending investigation: "
                f"{', '.join(crit_hosts)}."
            )

        # Lateral movement — IR engagement
        if lateral_detected:
            actions.append(
                "Engage incident response — lateral movement confirmed. "
                "Scope the blast radius before any remediation."
            )

        # WINLOG critical rules
        for rule_id in winlog_fired:
            if rule_id in _CRITICAL_WINLOG_RULES:
                actions.append(f"[{rule_id}] {_CRITICAL_WINLOG_RULES[rule_id]}")

        # NRA priority-1 services (Critical risk)
        p1_services: list[str] = []
        for host in nra_recs:
            for rec in host.get("recommendations", []):
                if rec.get("priority") == 1:
                    p1_services.append(
                        f"{rec['service'].upper()} ({host['ip']}:{rec['port']})"
                    )
        if p1_services:
            actions.append(
                f"Apply emergency controls for Critical-risk network service(s): "
                f"{', '.join(p1_services[:5])}."
            )

        # No findings at all
        if not findings:
            findings.append("No significant risk indicators detected in this session.")
        if not actions:
            actions.append(
                "No immediate actions required. Continue standard monitoring cadence."
            )

        # ── Markdown ─────────────────────────────────────────────────────────
        markdown = self._build_markdown(
            verdict=verdict,
            generated_at=_now_utc(),
            findings=findings,
            actions=actions,
            risk_surface=risk_surface,
        )

        return {
            "verdict":           verdict,
            "generated_at":      _now_utc(),
            "key_findings":      findings,
            "immediate_actions": actions,
            "risk_surface":      risk_surface,
            "markdown":          markdown,
        }

    # -------------------------------------------------------------------------

    def _build_markdown(
        self,
        verdict: str,
        generated_at: str,
        findings: list[str],
        actions: list[str],
        risk_surface: dict,
    ) -> str:
        lines: list[str] = []

        lines.append("## Executive Summary")
        lines.append(f"**Generated:** {generated_at}  ")
        lines.append(f"**Overall Verdict:** {verdict}")
        lines.append("")

        lines.append("### Risk Surface")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Critical Hosts | {risk_surface['critical_hosts']} |")
        lines.append(f"| High Hosts | {risk_surface['high_hosts']} |")
        lines.append(f"| Medium Hosts | {risk_surface['medium_hosts']} |")
        lines.append(f"| Low Hosts | {risk_surface['low_hosts']} |")
        lines.append(f"| Total Alerts | {risk_surface['total_alerts']} |")
        lines.append(
            f"| Significant Alerts (≥{risk_surface['verdict_confidence_floor']:.0%} confidence)"
            f" | {risk_surface['significant_alerts']} |"
        )
        lines.append(
            f"| Attack Surface | **{risk_surface['attack_surface_label'].title()}** |"
        )
        lat = "Yes" if risk_surface["lateral_movement_detected"] else "No"
        lines.append(f"| Lateral Movement | {lat} |")
        if risk_surface["winlog_rules_fired"]:
            lines.append(
                f"| WINLOG Rules Fired | {', '.join(risk_surface['winlog_rules_fired'])} |"
            )
        if risk_surface["mitre_tactics"]:
            lines.append(
                f"| MITRE Tactics | {', '.join(risk_surface['mitre_tactics'])} |"
            )
        lines.append("")

        lines.append("### Key Findings")
        lines.append("")
        for finding in findings:
            lines.append(f"- {finding}")
        lines.append("")

        lines.append("### Immediate Actions Required")
        lines.append("")
        for i, action in enumerate(actions, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

        return "\n".join(lines)
