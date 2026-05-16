"""
threat_feeds.py — Enrichment: Threat feed membership check.
Stateless. Deterministic results from internal feed table.
No external libraries or network calls.
"""

from __future__ import annotations

_FEEDS: dict[str, dict] = {
    "185.220.101.45": {
        "feed_hits": ["tor-exit-nodes", "ssh-brute-force-ips", "shodan-scanner"],
        "threat_categories": ["reconnaissance", "credential_stuffing", "scanning"],
        "confidence": 0.97,
        "first_seen": "2024-11-01",
        "last_seen": "2026-05-08",
    },
    "23.129.64.101": {
        "feed_hits": ["tor-exit-nodes"],
        "threat_categories": ["anonymization"],
        "confidence": 0.82,
        "first_seen": "2025-01-15",
        "last_seen": "2026-04-20",
    },
}


class ThreatFeeds:
    """Stateless threat feed lookup."""

    def check(self, ip: str) -> dict:
        """
        Check ip against internal threat feeds.
        Schema: {ip, feed_hits, threat_categories, confidence, first_seen, last_seen}

        confidence measures certainty of feed membership (how reliably this IP appears
        in the listed feeds). It is distinct from IpReputation.reputation_score, which
        aggregates abuse severity across all incident types. Both are 0–1 but measure
        different things and should not be compared or merged directly.
        """
        if not ip:
            return {"ip": ip, "feed_hits": [], "threat_categories": [],
                    "confidence": 0.0, "first_seen": None, "last_seen": None}
        if ip in _FEEDS:
            return {"ip": ip, **_FEEDS[ip]}
        return {"ip": ip, "feed_hits": [], "threat_categories": [],
                "confidence": 0.0, "first_seen": None, "last_seen": None}
