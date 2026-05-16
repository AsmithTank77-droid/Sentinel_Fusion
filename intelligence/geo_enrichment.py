"""
intelligence/geo_enrichment.py — Enrichment: IP geolocation lookup.

Two-tier lookup:
  1. Local seed table (_GEO) — instant, always authoritative for known IPs.
  2. ip-api.com free API — when SENTINEL_GEO_ENABLED=true. No key required.
     Results are cached (TTL = SENTINEL_INTEL_CACHE_TTL, default 1 hour).

ip-api.com imposes a 45 req/min rate limit on the free tier. The cache
means each unique IP is only looked up once per TTL window.
Disabled by default to avoid network calls in tests and airgapped environments.
"""

from __future__ import annotations

import time

from core.utils.ip_utils import is_private as _is_private
from intelligence._http import IntelHttpError, get_json

# ---------------------------------------------------------------------------
# Seed table (always authoritative — used in tests and as demo data)
# ---------------------------------------------------------------------------
_GEO: dict[str, dict] = {
    "185.220.101.45": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "asn": "AS60068",
        "org": "Censys-Scanning",
        "is_tor": True,
        "high_risk_country": True,
    },
    "23.129.64.101": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "asn": "AS4224",
        "org": "emeraldonion.org",
        "is_tor": True,
        "high_risk_country": False,
    },
}

# Countries with elevated geopolitical risk context for SOC triage
_HIGH_RISK_COUNTRIES: frozenset[str] = frozenset({
    "RU", "CN", "KP", "IR", "SY", "BY", "CU",
})

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


def _ipapi_lookup(ip: str, timeout: int) -> dict:
    """Call ip-api.com free endpoint and translate to internal schema."""
    fields = "country,countryCode,city,as,org,proxy,hosting"
    url    = f"http://ip-api.com/json/{ip}?fields={fields}"
    data   = get_json(url, timeout=timeout)

    if data.get("status") == "fail":
        raise IntelHttpError(f"ip-api.com rejected query for {ip}: {data.get('message')}")

    country_code    = str(data.get("countryCode") or "XX")
    is_tor_or_proxy = bool(data.get("proxy")) or bool(data.get("hosting"))

    return {
        "country":          str(data.get("country") or "Unknown"),
        "country_code":     country_code,
        "city":             str(data.get("city") or "Unknown"),
        "asn":              str(data.get("as") or ""),
        "org":              str(data.get("org") or ""),
        "is_tor":           is_tor_or_proxy,
        "high_risk_country": country_code in _HIGH_RISK_COUNTRIES,
    }


class GeoEnrichment:
    """
    IP geolocation lookup — seed table, live ip-api.com, then stub fallback.
    Stateless at the instance level; cache is module-level for performance.
    """

    def lookup(self, ip: str) -> dict:
        """
        Return geolocation data for ip.
        Schema: {ip, country, country_code, city, asn, org, is_tor, high_risk_country}
        """
        if not ip:
            return {"ip": ip, "country": "Unknown", "country_code": "XX",
                    "city": "Unknown", "asn": "", "org": "", "is_tor": False,
                    "high_risk_country": False}

        # 1. Seed table — always wins
        if ip in _GEO:
            return {"ip": ip, **_GEO[ip]}

        # 2. Private / RFC-1918
        if _is_private(ip):
            return {"ip": ip, "country": "Internal", "country_code": "IN",
                    "city": "LAN", "asn": "RFC1918", "org": "internal",
                    "is_tor": False, "high_risk_country": False}

        # 3. Cache check
        cached = _cache_get(ip)
        if cached is not None:
            return {"ip": ip, **cached}

        # 4. Live ip-api.com lookup (only when geo_enabled=true)
        from config.settings import settings as _settings
        if _settings.geo_enabled:
            try:
                result = _ipapi_lookup(ip, _settings.intel_timeout)
                _cache_set(ip, result, _settings.intel_cache_ttl)
                return {"ip": ip, **result}
            except IntelHttpError:
                pass  # fall through to stub

        # 5. Stub fallback
        return {"ip": ip, "country": "Unknown", "country_code": "XX",
                "city": "Unknown", "asn": "", "org": "",
                "is_tor": False, "high_risk_country": False}
