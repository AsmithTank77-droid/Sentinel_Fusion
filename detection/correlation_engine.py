"""
detection/correlation_engine.py — Stage 4: Event Correlation
Pipeline: enrich.py → correlation_engine.py → detection modules

Groups enriched normalized events into attack chains by correlating
activity from the same source IP across multiple event types. Produces
correlated chain alerts that seed the detection stage.

Stateless. No external libraries. Accepts enriched event dicts only.
"""

from __future__ import annotations

from collections import defaultdict


class CorrelationEngine:
    """
    Correlates enriched events into multi-stage attack chains.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        correlate(events: list[dict]) -> list[dict]
        Returns list of correlated chain alert dicts.
    """

    # Minimum events from a single source to constitute a correlated chain
    _CHAIN_MIN_EVENTS = 2

    # Ordered stage progression — heavier stages score higher
    _STAGE_WEIGHTS: dict[str, int] = {
        "port_scan":              1,
        "authentication_failure": 2,
        "authentication_success": 3,
        "lateral_movement":       4,
        "privilege_escalation":   5,
    }

    def correlate(self, events: list[dict]) -> list[dict]:
        """
        Correlate events into attack chains and detect multi-hop pivot paths.

        Two alert types are produced:
          correlated_attack_chain — events sharing a single src_ip.
          correlated_pivot_chain  — two chains linked by a compromised pivot
                                    host (chain_A.dst_ip == chain_B.src_ip).

        Args:
            events: list of enriched event dicts (NormalizedEvent.to_dict()).
        """
        if not events:
            return []

        chains = self._build_chains(events)
        pivots = self._detect_pivots(chains)
        return chains + pivots

    def _build_chains(self, events: list[dict]) -> list[dict]:
        """Group events by src_ip into single-source attack chains."""
        src_groups: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            src = event.get("src_ip") or ""
            if src:
                src_groups[src].append(event)

        chains: list[dict] = []
        for src_ip, group in src_groups.items():
            if len(group) < self._CHAIN_MIN_EVENTS:
                continue

            sorted_group = sorted(group, key=lambda e: e.get("timestamp") or "")
            event_types  = list(dict.fromkeys(e.get("event_type") or "" for e in sorted_group))
            dst_ips      = list(dict.fromkeys(
                e.get("dst_ip") or "" for e in sorted_group if e.get("dst_ip")
            ))
            timestamps   = [sorted_group[0].get("timestamp") or "",
                            sorted_group[-1].get("timestamp") or ""]
            max_severity = max(e.get("severity") or 0 for e in sorted_group)

            stage_score  = max(
                (self._STAGE_WEIGHTS.get(et, 0) for et in event_types),
                default=0
            )
            enrichment   = (sorted_group[0].get("metadata") or {}).get("enrichment") or {}
            src_rep      = enrichment.get("src_reputation") or {}
            malicious    = src_rep.get("is_malicious", False)
            rep_score    = src_rep.get("reputation_score", 0.0)

            base_conf    = min(0.5 + stage_score * 0.1 + len(group) * 0.03, 0.90)
            confidence   = min(base_conf + (rep_score * 0.1 if malicious else 0.0), 0.99)

            mitre_tactics = self._map_mitre(event_types)

            enrichment_summary: dict = {}
            if src_rep:
                enrichment_summary["src_reputation"] = {
                    "is_malicious": src_rep.get("is_malicious"),
                    "reputation_score": src_rep.get("reputation_score"),
                    "categories": src_rep.get("categories", []),
                }
            src_geo = enrichment.get("src_geo") or {}
            if src_geo:
                enrichment_summary["src_geo"] = {
                    "country": src_geo.get("country"),
                    "is_tor": src_geo.get("is_tor"),
                    "high_risk_country": src_geo.get("high_risk_country"),
                }
            src_threats = enrichment.get("src_threats") or {}
            if src_threats.get("feed_hits"):
                enrichment_summary["src_threat_feeds"] = src_threats.get("feed_hits")

            chains.append({
                "alert_type":         "correlated_attack_chain",
                "confidence":         round(confidence, 4),
                "src_ip":             src_ip,
                "event_count":        len(group),
                "event_types":        event_types,
                "dst_ips":            dst_ips,
                "timestamps":         timestamps,
                "max_severity":       max_severity,
                "mitre_tactics":      mitre_tactics,
                "enrichment_summary": enrichment_summary,
            })

        return chains

    def _detect_pivots(self, chains: list[dict]) -> list[dict]:
        """Detect multi-hop pivot paths across single-source chains.

        A pivot is confirmed when:
          - chain_A targeted a host that appears as chain_B's src_ip, AND
          - chain_A started before chain_B (temporal ordering enforced).

        Each pivot produces a correlated_pivot_chain alert that links the
        original attacker through the compromised intermediary to downstream
        targets. src_ip / dst_ip are set for compatibility with the dedup
        and scoring layers.
        """
        pivot_alerts: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for chain_a in chains:
            dst_ips_a   = set(chain_a.get("dst_ips") or [])
            ts_a_start  = (chain_a.get("timestamps") or [""])[0]
            initial_src = chain_a.get("src_ip", "")

            for chain_b in chains:
                if chain_a is chain_b:
                    continue
                pivot_host  = chain_b.get("src_ip", "")
                if not pivot_host or pivot_host not in dst_ips_a:
                    continue

                # Enforce temporal ordering: chain_A must precede chain_B
                ts_b_start = (chain_b.get("timestamps") or [""])[0]
                if ts_a_start and ts_b_start and ts_a_start >= ts_b_start:
                    continue

                key = (initial_src, pivot_host)
                if key in seen:
                    continue
                seen.add(key)

                # Confidence: average of both chains plus pivot bonus
                conf_a     = float(chain_a.get("confidence") or 0.5)
                conf_b     = float(chain_b.get("confidence") or 0.5)
                confidence = round(min((conf_a + conf_b) / 2 + 0.15, 0.97), 4)

                combined_tactics = list(dict.fromkeys(
                    (chain_a.get("mitre_tactics") or [])
                    + ["TA0008 - Lateral Movement"]
                    + (chain_b.get("mitre_tactics") or [])
                ))

                ts_b_end = (chain_b.get("timestamps") or ["", ""])[-1]

                pivot_alerts.append({
                    "alert_type":          "correlated_pivot_chain",
                    "confidence":          confidence,
                    "src_ip":              initial_src,
                    "dst_ip":              pivot_host,
                    "initial_src_ip":      initial_src,
                    "pivot_host":          pivot_host,
                    "final_targets":       chain_b.get("dst_ips", []),
                    "chain_a_event_types": chain_a.get("event_types", []),
                    "chain_b_event_types": chain_b.get("event_types", []),
                    "timestamps":          [ts_a_start, ts_b_end],
                    "max_severity":        max(
                        int(chain_a.get("max_severity") or 0),
                        int(chain_b.get("max_severity") or 0),
                    ),
                    "mitre_tactics":       combined_tactics,
                    "hop_count":           1,
                })

        return pivot_alerts

    @staticmethod
    def _map_mitre(event_types: list[str]) -> list[str]:
        _MAP = {
            "port_scan":              "TA0043 - Reconnaissance",
            "authentication_failure": "TA0006 - Credential Access",
            "authentication_success": "TA0001 - Initial Access",
            "lateral_movement":       "TA0008 - Lateral Movement",
            "privilege_escalation":   "TA0004 - Privilege Escalation",
            "process_creation":       "TA0002 - Execution",
            "service_installed":      "TA0003 - Persistence",
            "explicit_credential_logon": "TA0006 - Credential Access",
        }
        return list(dict.fromkeys(_MAP[et] for et in event_types if et in _MAP))
