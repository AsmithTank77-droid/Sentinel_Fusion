"""
scoring/attack_surface.py — Scoring: Attack surface expansion metrics.
Pipeline: detect stage → score stage (attack_surface)

Measures how much of the environment has been reached or exposed:
  - Unique external source IPs
  - Unique internal targets reached
  - Number of distinct attack techniques observed
  - Lateral movement depth (hops from initial entry)

Stateless. No external libraries.
"""

from __future__ import annotations

from collections import defaultdict

from core.utils.ip_utils import is_private as _is_internal, is_external as _is_external


class AttackSurface:
    """
    Measures attack surface expansion across the event batch.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        score(events: list[dict], alerts: list[dict]) -> dict
        Returns a single summary dict (not keyed by host — describes the whole batch).
    """

    def score(self, events: list[dict], alerts: list[dict]) -> dict:
        """
        Compute attack surface expansion metrics.

        Args:
            events: list of enriched event dicts.
            alerts: list of alert dicts from detection stage.

        Returns:
            {
                "expansion_score": float,           # 0.0-10.0
                "expansion_label": str,             # "contained"/"moderate"/"significant"/"critical"
                "unique_external_sources": int,
                "unique_internal_targets": int,
                "unique_attack_techniques": int,
                "lateral_movement_hops": int,
                "alert_type_breakdown": dict,       # {alert_type: count}
                "mitre_tactics_observed": list[str],
                "factors": list[str],
            }
        """
        external_sources: set[str] = set()
        internal_targets: set[str] = set()
        event_types: set[str] = set()

        for event in events:
            src = event.get("src_ip") or ""
            dst = event.get("dst_ip") or ""
            et  = event.get("event_type") or ""
            if _is_external(src):
                external_sources.add(src)
            if _is_internal(dst):
                internal_targets.add(dst)
            if et:
                event_types.add(et)

        lateral_hops    = 0
        alert_breakdown: dict[str, int] = defaultdict(int)
        mitre_tactics:  set[str] = set()

        for alert in alerts:
            atype = alert.get("alert_type") or "unknown"
            alert_breakdown[atype] += 1
            if atype == "lateral_movement_detected":
                lateral_hops += 1
            tactic = alert.get("mitre_tactic") or ""
            if tactic:
                mitre_tactics.add(tactic)
            tactics_list = alert.get("mitre_tactics") or []
            for t in tactics_list:
                mitre_tactics.add(t)

        factors: list[str] = []

        # Expansion score components
        src_score  = min(len(external_sources) * 1.0, 3.0)
        tgt_score  = min(len(internal_targets) * 1.0, 3.0)
        tech_score = min(len(event_types) * 0.5, 2.0)
        lat_score  = min(lateral_hops * 1.5, 3.0)
        expansion  = min(src_score + tgt_score + tech_score + lat_score, 10.0)

        if external_sources:
            factors.append(f"{len(external_sources)} unique external source(s)")
        if internal_targets:
            factors.append(f"{len(internal_targets)} unique internal target(s)")
        if event_types:
            factors.append(f"{len(event_types)} distinct event type(s)")
        if lateral_hops:
            factors.append(f"{lateral_hops} lateral movement hop(s) detected")

        if expansion >= 8.0:
            label = "critical"
        elif expansion >= 5.0:
            label = "significant"
        elif expansion >= 2.0:
            label = "moderate"
        else:
            label = "contained"

        return {
            "expansion_score":          round(expansion, 2),
            "expansion_label":          label,
            "unique_external_sources":  len(external_sources),
            "unique_internal_targets":  len(internal_targets),
            "unique_attack_techniques": len(event_types),
            "lateral_movement_hops":    lateral_hops,
            "alert_type_breakdown":     dict(alert_breakdown),
            "mitre_tactics_observed":   sorted(mitre_tactics),
            "factors":                  factors,
        }
