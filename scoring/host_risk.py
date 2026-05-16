"""
scoring/host_risk.py — Scoring: Per-host risk assessment.
Pipeline: detect stage → score stage (host_risk)

Evaluates risk for each observed host (dst_ip) based on:
  - Severity of events targeting that host
  - Number and type of alerts involving that host
  - Enrichment signals (malicious src, TOR, threat feeds)

Stateless. No external libraries.
"""

from __future__ import annotations

from collections import defaultdict

from intelligence.service_intelligence import (
    SERVICE_RISK,
    HIGH_RISK_PORTS,
    DANGEROUS_COMBOS,
    DANGEROUS_SERVICES,
)

# NRA risk thresholds on the 0-100 composite scale
_NRA_THRESHOLDS: list[tuple[int, str]] = [
    (75, "critical"),
    (55, "high"),
    (35, "medium"),
    (15, "low"),
    (0,  "low"),
]

_STATE_WEIGHT: dict[str, float] = {"open": 1.0, "filtered": 0.4, "closed": 0.1}
_STANDARD_PORTS: set[int] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379}


def _nra_risk_label(score: int) -> str:
    for threshold, label in _NRA_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _score_nra_host(host_ip: str, ports: list[dict], enrichment: dict) -> dict:
    """
    4-component NRA scoring (0-100 scale) mapped onto Sentinel_Fusion's 0-10 output.

    Components: service_risk (40) + exposure_risk (25) + attack_surface (20) + threat_context (15)
    """
    open_ports = [p for p in ports if str(p.get("state", "open")).lower() == "open"]
    reasons: list[str] = []

    # Component 1 — Service Risk (max 40)
    svc_pts = 0
    if open_ports:
        scores = []
        for p in open_ports:
            base = float(SERVICE_RISK.get(p.get("service", "unknown"), SERVICE_RISK["unknown"]))
            if p.get("port", 0) in HIGH_RISK_PORTS:
                base = min(base + 1.0, 10.0)
            weight = _STATE_WEIGHT.get(str(p.get("state", "open")).lower(), 0.5)
            scores.append(base * weight)
        peak = max(scores)
        mean = sum(scores) / len(scores)
        svc_pts = min(round((peak / 10) * 24) + round((mean / 10) * 16), 40)
        reasons.append(f"Service risk: {svc_pts}/40 ({len(open_ports)} open port(s))")

    # Component 2 — Exposure Risk (max 25)
    n_open = len(open_ports)
    if   n_open == 0:  count_pts = 0
    elif n_open == 1:  count_pts = 4
    elif n_open <= 3:  count_pts = 8
    elif n_open <= 6:  count_pts = 12
    elif n_open <= 10: count_pts = 16
    else:              count_pts = 20
    nonstandard = [p for p in open_ports if p.get("port", 0) not in _STANDARD_PORTS]
    ns_pts      = min(len(nonstandard), 3)
    exp_pts     = min(count_pts + ns_pts, 25)
    if exp_pts:
        reasons.append(f"Exposure risk: {exp_pts}/25 ({n_open} open, {len(nonstandard)} non-standard)")

    # Component 3 — Attack Surface (max 20)
    service_names = {p.get("service", "").lower() for p in open_ports}
    combo_pts = min(sum(5 for req, _ in DANGEROUS_COMBOS if req.issubset(service_names)), 15)
    n_danger  = sum(1 for p in open_ports if p.get("service", "").lower() in DANGEROUS_SERVICES)
    conc_pts  = 5 if n_danger >= 3 else 0
    atk_pts   = min(combo_pts + conc_pts, 20)
    if atk_pts:
        reasons.append(f"Attack surface: {atk_pts}/20 ({combo_pts} combo pts, {conc_pts} concentration pts)")

    # Component 4 — Threat Context from enrichment (max 15)
    ctx_pts = 0
    src_rep = enrichment.get("src_reputation") or enrichment.get("dst_reputation") or {}
    if src_rep.get("is_malicious"):
        ctx_pts = min(ctx_pts + 8, 15)
        reasons.append("Known malicious IP association (+8 threat context)")
    src_geo = enrichment.get("src_geo") or enrichment.get("dst_geo") or {}
    if src_geo.get("is_tor"):
        ctx_pts = min(ctx_pts + 5, 15)
        reasons.append("TOR exit node detected (+5 threat context)")
    elif src_geo.get("high_risk_country"):
        ctx_pts = min(ctx_pts + 5, 15)
        reasons.append("High-risk country origin (+5 threat context)")

    total      = svc_pts + exp_pts + atk_pts + ctx_pts
    risk_label = _nra_risk_label(total)

    return {
        "risk_score":          round(total / 10, 2),  # 0-10 for pipeline consistency
        "risk_label":          risk_label,
        "nra_composite_score": total,                  # 0-100 native NRA scale
        "event_count":         1,
        "max_event_severity":  min(round(total / 10), 10),
        "alert_count":         0,
        "alert_types":         [],
        "factors":             reasons,
        "nra_breakdown": {
            "service_risk":   svc_pts,
            "exposure_risk":  exp_pts,
            "attack_surface": atk_pts,
            "threat_context": ctx_pts,
        },
    }


class HostRisk:
    """
    Computes per-host risk scores from enriched events and alerts.
    Stateless: no state is maintained between calls.

    Contract (required by orchestrator.py):
        score(events: list[dict], alerts: list[dict]) -> dict
        Returns {host_ip: {score, factors, alert_count, max_event_severity}}
    """

    def score(self, events: list[dict], alerts: list[dict]) -> dict:
        """
        Compute risk score for each observed destination host.

        Risk formula (0-10 scale):
            base = average severity of events targeting host
            alert_bonus = min(alert_count * 0.5, 3.0)
            malicious_bonus = 2.0 if any src_ip is malicious
            final = min(base + alert_bonus + malicious_bonus, 10)

        Args:
            events: list of enriched event dicts.
            alerts: list of alert dicts from detection stage.

        Returns:
            dict keyed by host IP:
            {
                "<host_ip>": {
                    "risk_score": float,          # 0.0-10.0
                    "risk_label": str,            # "low"/"medium"/"high"/"critical"
                    "event_count": int,
                    "max_event_severity": int,
                    "alert_count": int,
                    "alert_types": list[str],
                    "factors": list[str],         # human-readable scoring factors
                }
            }
        """
        if not events and not alerts:
            return {}

        result: dict = {}

        # NRA events carry structured port data — score with the 4-component NRA model
        for event in events:
            if event.get("source_type") != "nra":
                continue
            host = event.get("dst_ip") or ""
            if not host:
                continue
            ports      = event.get("metadata", {}).get("ports") or []
            enrichment = event.get("metadata", {}).get("enrichment") or {}
            result[host] = _score_nra_host(host, ports, enrichment)

        # Index remaining (non-NRA) events by dst_ip
        host_events: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            if event.get("source_type") == "nra":
                continue
            dst = event.get("dst_ip") or ""
            if dst:
                host_events[dst].append(event)

        # Index alerts by dst_ip (check multiple fields)
        host_alerts: dict[str, list[dict]] = defaultdict(list)
        for alert in alerts:
            for field in ("dst_ip", "pivot_host", "lateral_target"):
                host = alert.get(field) or ""
                if host:
                    host_alerts[host].append(alert)

        all_hosts = set(host_events) | set(host_alerts)

        for host in all_hosts:
            evts   = host_events.get(host, [])
            alts   = host_alerts.get(host, [])
            factors: list[str] = []

            severities  = [e.get("severity") or 0 for e in evts]
            base_score  = (sum(severities) / len(severities)) if severities else 0.0
            max_sev     = max(severities, default=0)
            alert_count = len(alts)
            alert_types = list(dict.fromkeys(a.get("alert_type") or "" for a in alts))

            if base_score > 0:
                factors.append(f"avg event severity {base_score:.1f}")

            alert_bonus = min(alert_count * 0.5, 3.0)
            if alert_bonus > 0:
                factors.append(f"{alert_count} alert(s) targeting this host (+{alert_bonus:.1f})")

            # Malicious source bonus
            malicious_bonus = 0.0
            for evt in evts:
                enrichment = (evt.get("metadata") or {}).get("enrichment") or {}
                if (enrichment.get("src_reputation") or {}).get("is_malicious"):
                    malicious_bonus = 2.0
                    factors.append("malicious source IP observed")
                    break

            risk_score = min(base_score + alert_bonus + malicious_bonus, 10.0)

            if risk_score >= 8.0:
                risk_label = "critical"
            elif risk_score >= 6.0:
                risk_label = "high"
            elif risk_score >= 3.0:
                risk_label = "medium"
            else:
                risk_label = "low"

            result[host] = {
                "risk_score":          round(risk_score, 2),
                "risk_label":          risk_label,
                "event_count":         len(evts),
                "max_event_severity":  max_sev,
                "alert_count":         alert_count,
                "alert_types":         alert_types,
                "factors":             factors,
            }

        return result
