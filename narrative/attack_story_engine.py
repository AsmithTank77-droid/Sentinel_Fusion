"""
narrative/attack_story_engine.py — Narrative: SOC attack story generator.
Pipeline: called internally by timeline_builder.py only (CLAUDE.md §8)

Converts a chronological timeline and alert set into a human-readable
SOC narrative describing the attack campaign in plain English.

Stateless. No external libraries.
"""

from __future__ import annotations


class AttackStoryEngine:
    """
    Generates a human-readable SOC narrative from timeline and alerts.
    Stateless: no state is maintained between calls.

    Contract (required by timeline_builder.py):
        narrate(timeline: list[dict], alerts: list[dict]) -> str
        Returns a multi-paragraph Markdown narrative string.
    """

    def narrate(self, timeline: list[dict], alerts: list[dict]) -> str:
        """
        Build a SOC narrative from timeline entries and detection alerts.

        Args:
            timeline: chronological list of timeline entry dicts.
            alerts:   list of detection alert dicts.

        Returns:
            Multi-paragraph Markdown string describing the attack story.
        """
        if not timeline and not alerts:
            return "No events recorded in this analysis window."

        paragraphs: list[str] = []

        # --- Introduction ---
        first_ts = timeline[0].get("timestamp") or "unknown" if timeline else "unknown"
        last_ts  = timeline[-1].get("timestamp") or "unknown" if timeline else "unknown"
        src_ips  = list(dict.fromkeys(
            e.get("src_ip") or "" for e in timeline if e.get("src_ip")
        ))
        dst_ips  = list(dict.fromkeys(
            e.get("dst_ip") or "" for e in timeline if e.get("dst_ip")
        ))

        intro = (
            f"## Attack Campaign Summary\n\n"
            f"Between **{first_ts}** and **{last_ts}**, Sentinel_Fusion detected a "
            f"coordinated multi-stage intrusion campaign. "
        )
        if src_ips:
            intro += f"The attack originated from {self._format_ips(src_ips)}. "
        if dst_ips:
            intro += f"Targeted assets include: {self._format_ips(dst_ips)}."
        paragraphs.append(intro)

        # --- Attack Phase Narrative ---
        phases = self._identify_phases(timeline)
        if phases:
            paragraphs.append("## Attack Phases\n")
            for phase_name, phase_entries in phases.items():
                ts_first = phase_entries[0].get("timestamp") or ""
                description = self._describe_phase(phase_name, phase_entries)
                paragraphs.append(f"### {phase_name}\n_{ts_first}_\n\n{description}")

        # --- Alert Summary ---
        if alerts:
            alert_types = {}
            for alert in alerts:
                atype = alert.get("alert_type") or "unknown"
                if atype not in alert_types:
                    alert_types[atype] = 0
                alert_types[atype] += 1

            alert_lines = [f"- **{k}**: {v} instance(s)" for k, v in alert_types.items()]
            paragraphs.append(
                f"## Detection Alerts\n\n"
                f"The following alert types were triggered during this campaign:\n\n"
                + "\n".join(alert_lines)
            )

        # --- MITRE ATT&CK Coverage ---
        all_tactics: list[str] = []
        for alert in alerts:
            tactic = alert.get("mitre_tactic") or ""
            if tactic and tactic not in all_tactics:
                all_tactics.append(tactic)
            for t in (alert.get("mitre_tactics") or []):
                if t and t not in all_tactics:
                    all_tactics.append(t)

        if all_tactics:
            tactic_lines = [f"- {t}" for t in all_tactics]
            paragraphs.append(
                "## MITRE ATT&CK Coverage\n\n"
                "Observed tactics mapped to ATT&CK framework:\n\n"
                + "\n".join(tactic_lines)
            )

        # --- Analyst Recommendation ---
        recommendations = self._generate_recommendations(alerts)
        if recommendations:
            rec_lines = [f"- {r}" for r in recommendations]
            paragraphs.append(
                "## Analyst Recommendations\n\n"
                + "\n".join(rec_lines)
            )

        return "\n\n".join(paragraphs)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _format_ips(ips: list[str]) -> str:
        if len(ips) == 1:
            return f"`{ips[0]}`"
        return ", ".join(f"`{ip}`" for ip in ips[:-1]) + f", and `{ips[-1]}`"

    @staticmethod
    def _identify_phases(timeline: list[dict]) -> dict[str, list[dict]]:
        _PHASE_MAP = {
            "port_scan":              "Phase 1: Reconnaissance",
            "authentication_failure": "Phase 2: Credential Attack",
            "authentication_success": "Phase 3: Initial Access",
            "lateral_movement":       "Phase 4: Lateral Movement",
            "lateral_movement_detected": "Phase 4: Lateral Movement",
            "privilege_escalation":   "Phase 5: Privilege Escalation",
        }
        phases: dict[str, list[dict]] = {}
        for entry in timeline:
            etype = entry.get("event_type") or entry.get("alert_type") or ""
            phase = _PHASE_MAP.get(etype)
            if phase:
                if phase not in phases:
                    phases[phase] = []
                phases[phase].append(entry)
        return dict(sorted(phases.items()))

    @staticmethod
    def _describe_phase(phase: str, entries: list[dict]) -> str:
        count  = len(entries)
        src_ips = list(dict.fromkeys(e.get("src_ip") or "" for e in entries if e.get("src_ip")))
        dst_ips = list(dict.fromkeys(e.get("dst_ip") or "" for e in entries if e.get("dst_ip")))

        descriptions = {
            "Phase 1: Reconnaissance": (
                f"The attacker performed network reconnaissance against "
                f"{len(dst_ips)} target(s). {count} scan event(s) observed."
            ),
            "Phase 2: Credential Attack": (
                f"{count} authentication failure(s) recorded from "
                f"{len(src_ips)} source(s) targeting {len(dst_ips)} host(s). "
                f"This pattern is consistent with automated credential brute-forcing."
            ),
            "Phase 3: Initial Access": (
                f"Authentication succeeded after credential attacks. "
                f"The attacker gained access to {', '.join(dst_ips) or 'target host(s)'}."
            ),
            "Phase 4: Lateral Movement": (
                f"Post-compromise lateral movement detected. "
                f"The attacker moved from initial foothold to {len(dst_ips)} additional host(s)."
            ),
            "Phase 5: Privilege Escalation": (
                f"Privilege escalation activity observed across {len(dst_ips)} host(s)."
            ),
        }
        return descriptions.get(phase, f"{count} event(s) in this phase.")

    @staticmethod
    def _generate_recommendations(alerts: list[dict]) -> list[str]:
        recs: list[str] = []
        types = {a.get("alert_type") for a in alerts}

        if "brute_force_detected" in types:
            recs.append("Block source IPs involved in brute force activity at the perimeter firewall.")
            recs.append("Enforce account lockout policy: lock after 5 failed attempts within 10 minutes.")
            recs.append("Enable multi-factor authentication on all externally-accessible SSH/RDP endpoints.")
        if "lateral_movement_detected" in types:
            recs.append("Isolate compromised hosts from the network pending forensic investigation.")
            recs.append("Audit internal SMB and RDP session logs for unauthorized lateral connections.")
        if "malicious_ip_activity" in types or "tor_exit_node_activity" in types:
            recs.append("Block all TOR exit node ranges at the network perimeter.")
            recs.append("Update threat intelligence blocklists and enforce geo-blocking for high-risk regions.")
        if "correlated_attack_chain" in types:
            recs.append("Initiate full incident response procedure — multi-stage attack chain confirmed.")
            recs.append("Preserve memory dumps and disk images from all affected hosts before remediation.")
        if not recs:
            recs.append("Review and archive all flagged events for future threat hunting correlation.")
        return recs
