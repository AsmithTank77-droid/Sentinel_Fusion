"""
intelligence/threat_feeds.py — Enrichment: Threat feed membership check.

Three-tier lookup — same pattern as ip_reputation.py:
  1. Seed table   — instant, always authoritative for known IPs.
  2. Live feeds   — downloaded and cached when SENTINEL_FEEDS_ENABLED=true.
                    abuse.ch Feodo Tracker (C2 botnet IPs, updated hourly)
                    Emerging Threats compromised-ips (updated daily)
                    Both require no API key.
  3. OTX          — per-IP AlienVault OTX lookup when SENTINEL_OTX_KEY is set.
                    Free tier, requires account at otx.alienvault.com.

All network failures are caught and logged. The pipeline always continues.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from intelligence._http import IntelHttpError, get_json

# ---------------------------------------------------------------------------
# Live feed definitions
# ---------------------------------------------------------------------------

_LIVE_FEEDS: dict[str, dict] = {
    "feodo-tracker": {
        "url":              "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_hit":         "feodo-tracker",
        "threat_categories": ["c2", "botnet"],
        "confidence":       0.90,
    },
    "emerging-threats": {
        "url":              "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_hit":         "emerging-threats",
        "threat_categories": ["compromised"],
        "confidence":       0.75,
    },
}

# ---------------------------------------------------------------------------
# Seed table — always authoritative, used in tests and as demo data
# ---------------------------------------------------------------------------

_FEEDS = _SEEDS = {
    "185.220.101.45": {
        "feed_hits":          ["tor-exit-nodes", "ssh-brute-force-ips", "shodan-scanner"],
        "threat_categories":  ["reconnaissance", "credential_stuffing", "scanning"],
        "confidence":         0.97,
        "first_seen":         "2024-11-01",
        "last_seen":          "2026-05-08",
    },
    "23.129.64.101": {
        "feed_hits":          ["tor-exit-nodes"],
        "threat_categories":  ["anonymization"],
        "confidence":         0.82,
        "first_seen":         "2025-01-15",
        "last_seen":          "2026-04-20",
    },
}

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

# Live feed cache: feed_name → (set[ip], expiry_epoch)
_feed_cache: dict[str, tuple[frozenset[str], float]] = {}

# OTX per-IP cache: ip → (result_dict, expiry_epoch)
_otx_cache: dict[str, tuple[dict, float]] = {}


def _feed_cache_get(feed_name: str) -> frozenset[str] | None:
    entry = _feed_cache.get(feed_name)
    if entry is None:
        return None
    ips, expiry = entry
    if time.monotonic() < expiry:
        return ips
    del _feed_cache[feed_name]
    return None


def _feed_cache_set(feed_name: str, ips: frozenset[str], ttl: int) -> None:
    _feed_cache[feed_name] = (ips, time.monotonic() + ttl)


def _otx_cache_get(ip: str) -> dict | None:
    entry = _otx_cache.get(ip)
    if entry is None:
        return None
    result, expiry = entry
    if time.monotonic() < expiry:
        return result
    del _otx_cache[ip]
    return None


def _otx_cache_set(ip: str, result: dict, ttl: int) -> None:
    _otx_cache[ip] = (result, time.monotonic() + ttl)


# ---------------------------------------------------------------------------
# Feed fetchers
# ---------------------------------------------------------------------------

def _fetch_ip_list(url: str, timeout: int) -> frozenset[str]:
    """
    Download a plain-text IP blocklist (one IP per line, # comments ignored).
    Returns a frozenset of IP strings.
    """
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SentinelFusion/3.0 threat-feed-fetcher"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError) as exc:
        raise IntelHttpError(f"Failed to fetch feed from {url}: {exc}") from exc

    ips: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Some feeds include port: "1.2.3.4:8080" — strip it
        ip = line.split(":")[0].split()[0]
        if ip:
            ips.add(ip)
    return frozenset(ips)


def _get_live_feed_ips(feed_name: str, feed_def: dict, ttl: int, timeout: int) -> frozenset[str]:
    """Return cached (or freshly fetched) IP set for one feed."""
    cached = _feed_cache_get(feed_name)
    if cached is not None:
        return cached
    try:
        ips = _fetch_ip_list(feed_def["url"], timeout)
        _feed_cache_set(feed_name, ips, ttl)
        return ips
    except IntelHttpError:
        return frozenset()


def _otx_lookup(ip: str, api_key: str, timeout: int) -> dict | None:
    """
    AlienVault OTX per-IP reputation lookup.
    Returns enriched dict or None on any failure.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
    try:
        data = get_json(url, headers={"X-OTX-API-KEY": api_key}, timeout=timeout)
    except IntelHttpError:
        return None

    reputation = data.get("reputation") or {}
    threat_score = int(reputation.get("threat_score") or 0)
    counts       = reputation.get("counts") or {}
    malicious    = int(counts.get("malicious") or 0)
    first_seen   = reputation.get("first_seen", "")
    last_seen    = reputation.get("last_seen", "")

    if threat_score == 0 and malicious == 0:
        return None  # OTX has no signal for this IP

    # Normalise to 0–1 (OTX threat_score is 0–10 in practice)
    confidence = min(round(threat_score / 10.0, 2), 1.0) if threat_score else 0.5

    return {
        "feed_hits":          ["otx"],
        "threat_categories":  ["malicious"] if malicious > 0 else ["suspicious"],
        "confidence":         confidence,
        "first_seen":         first_seen[:10] if first_seen else None,
        "last_seen":          last_seen[:10] if last_seen else None,
    }


# ---------------------------------------------------------------------------
# ThreatFeeds
# ---------------------------------------------------------------------------

class ThreatFeeds:
    """
    Threat feed membership check — seed table, live feeds, OTX, then stub.
    Stateless at the instance level; caches are module-level.
    """

    def check(self, ip: str) -> dict:
        """
        Check ip against threat feeds.

        Returns:
            {
                ip, feed_hits, threat_categories,
                confidence (0–1), first_seen, last_seen
            }

        confidence measures certainty of feed membership for this IP.
        It is distinct from IpReputation.reputation_score (abuse severity).
        """
        if not ip:
            return self._empty(ip)

        # 1. Seed table — always wins
        if ip in _SEEDS:
            return {"ip": ip, **_SEEDS[ip]}

        # 2. Live blocklist feeds (if enabled)
        from config.settings import settings
        if settings.feeds_enabled:
            ttl     = settings.intel_cache_ttl
            timeout = settings.intel_timeout
            today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            hits:       list[str] = []
            categories: list[str] = []
            best_conf = 0.0

            for feed_name, feed_def in _LIVE_FEEDS.items():
                feed_ips = _get_live_feed_ips(feed_name, feed_def, ttl, timeout)
                if ip in feed_ips:
                    hits.append(feed_def["feed_hit"])
                    categories.extend(feed_def["threat_categories"])
                    best_conf = max(best_conf, feed_def["confidence"])

            if hits:
                return {
                    "ip":               ip,
                    "feed_hits":        hits,
                    "threat_categories": list(dict.fromkeys(categories)),
                    "confidence":       best_conf,
                    "first_seen":       today,
                    "last_seen":        today,
                }

            # 3. OTX per-IP lookup (if key configured)
            if settings.otx_key:
                cached = _otx_cache_get(ip)
                if cached is None:
                    result = _otx_lookup(ip, settings.otx_key, timeout)
                    if result:
                        _otx_cache_set(ip, result, ttl)
                        cached = result
                if cached:
                    return {"ip": ip, **cached}

        return self._empty(ip)

    @staticmethod
    def _empty(ip: str) -> dict:
        return {
            "ip":               ip,
            "feed_hits":        [],
            "threat_categories": [],
            "confidence":       0.0,
            "first_seen":       None,
            "last_seen":        None,
        }
