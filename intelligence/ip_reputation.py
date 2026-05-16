"""
intelligence/ip_reputation.py — Enrichment: IP reputation lookup.

Two-tier lookup:
  1. Local seed table (_KNOWN) — instant, always authoritative for known IPs.
  2. AbuseIPDB live API — when SENTINEL_ABUSEIPDB_KEY is set. Results are
     cached in memory (TTL = SENTINEL_INTEL_CACHE_TTL, default 1 hour).

When no API key is configured, falls back to neutral stub data for unknowns.
All API failures are caught and logged; the pipeline always continues.
"""

from __future__ import annotations

import time

from core.utils.ip_utils import is_private as _is_private
from intelligence._http import IntelHttpError, get_json

# ---------------------------------------------------------------------------
# Seed table (always authoritative — used in tests and as demo data)
# ---------------------------------------------------------------------------
_KNOWN: dict[str, dict] = {
    "185.220.101.45": {
        "is_malicious": True,
        "reputation_score": 0.97,
        "categories": ["tor_exit", "ssh_brute_force", "scanner"],
        "source": "internal_threat_feed",
        "report_count": 412,
    },
    "23.129.64.101": {
        "is_malicious": True,
        "reputation_score": 0.88,
        "categories": ["tor_exit"],
        "source": "internal_threat_feed",
        "report_count": 87,
    },
}

# AbuseIPDB usage type → local category label
_USAGE_TYPE_MAP: dict[str, str] = {
    "Data Center/Web Hosting/Transit": "hosting",
    "Fixed Line ISP":                  "isp",
    "Mobile ISP":                      "mobile",
    "Content Delivery Network":        "cdn",
    "Educational/Research":            "research",
    "Tor Exit Node":                   "tor_exit",
    "VPN":                             "vpn",
    "Search Engine Crawler":           "crawler",
}

# Module-level TTL cache: ip → (result_dict, expiry_epoch)
_cache: dict[str, tuple[dict, float]] = {}


def _cache_get(ip: str) -> dict | None:
    entry = _cache.get(ip)
    if entry is None:
        return None
    result, expiry = entry
    if time.monotonic() < expiry:
        return result
    del _cache[ip]
    return None


def _cache_set(ip: str, result: dict, ttl: int) -> None:
    _cache[ip] = (result, time.monotonic() + ttl)


def _abuseipdb_lookup(ip: str, api_key: str, timeout: int) -> dict:
    """Call AbuseIPDB /v2/check and translate to internal schema."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    data = get_json(url, headers={"Key": api_key, "Accept": "application/json"}, timeout=timeout)
    d = data.get("data") or {}

    score        = int(d.get("abuseConfidenceScore") or 0)
    total        = int(d.get("totalReports") or 0)
    whitelisted  = bool(d.get("isWhitelisted"))
    usage_type   = str(d.get("usageType") or "")
    is_tor       = "tor" in usage_type.lower()

    categories: list[str] = []
    if is_tor:
        categories.append("tor_exit")
    mapped = _USAGE_TYPE_MAP.get(usage_type)
    if mapped and mapped not in categories:
        categories.append(mapped)
    if score >= 50:
        categories.append("abusive")

    reputation_score = round(score / 100.0, 4)
    is_malicious     = (not whitelisted) and (score >= 25 or total >= 5)

    return {
        "is_malicious":     is_malicious,
        "reputation_score": reputation_score,
        "categories":       categories,
        "source":           "abuseipdb",
        "report_count":     total,
    }


class IpReputation:
    """
    IP reputation lookup — seed table, live AbuseIPDB API, then stub fallback.
    Stateless at the instance level; cache is module-level for performance.
    """

    def lookup(self, ip: str) -> dict:
        """
        Return reputation data for ip.
        Schema: {ip, is_malicious, reputation_score (0–1), categories, source, report_count}

        reputation_score measures aggregated abuse report confidence across all incident
        categories (brute force, scanning, C2, etc.). It is distinct from
        ThreatFeeds.confidence, which measures feed-match certainty for a specific
        feed membership claim. Both are 0–1 but should not be compared directly.
        """
        if not ip:
            return {"ip": ip, "is_malicious": False, "reputation_score": 0.0,
                    "categories": [], "source": "none", "report_count": 0}

        # 1. Seed table — always wins
        if ip in _KNOWN:
            return {"ip": ip, **_KNOWN[ip]}

        # 2. Private / RFC-1918 — never malicious
        if _is_private(ip):
            return {"ip": ip, "is_malicious": False, "reputation_score": 0.0,
                    "categories": ["internal"], "source": "rfc1918", "report_count": 0}

        # 3. Cache check
        cached = _cache_get(ip)
        if cached is not None:
            return {"ip": ip, **cached}

        # 4. Live AbuseIPDB lookup (only if key is configured)
        from config.settings import settings as _settings
        if _settings.abuseipdb_key:
            try:
                result = _abuseipdb_lookup(ip, _settings.abuseipdb_key, _settings.intel_timeout)
                _cache_set(ip, result, _settings.intel_cache_ttl)
                return {"ip": ip, **result}
            except IntelHttpError:
                pass  # fall through to stub

        # 5. Stub fallback for unknown IPs
        return {"ip": ip, "is_malicious": False, "reputation_score": 0.05,
                "categories": ["unknown"], "source": "none", "report_count": 0}
