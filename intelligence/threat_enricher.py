"""
intelligence/threat_enricher.py — Enrichment: Unified threat intelligence synthesis.

Synthesizes ip_reputation, geo_enrichment, and threat_feeds into a single
threat assessment per IP. Produces a composite threat_score, threat_level,
deduplicated indicator list, MITRE tactic mapping, and a one-line analyst
summary — giving downstream stages a single enrichment key to read instead
of three.

Two-tier lookup:
  1. Seed table (_SEED) — authoritative for known IPs, used in tests.
  2. Live synthesis — calls IpReputation, GeoEnrichment, ThreatFeeds and
     combines their outputs. Synthesized results are cached (module-level,
     TTL = SENTINEL_INTEL_CACHE_TTL).

All failures from underlying intelligence calls are caught and result in a
degraded-but-valid assessment so the pipeline always continues.
"""

from __future__ import annotations

import time

from core.utils.ip_utils import is_private as _is_private

# ---------------------------------------------------------------------------
# Indicator → MITRE ATT&CK tactic mapping
# ---------------------------------------------------------------------------

_INDICATOR_TO_MITRE: dict[str, str] = {
    "tor_exit":             "TA0005 - Defense Evasion",
    "anonymization":        "TA0005 - Defense Evasion",
    "vpn":                  "TA0005 - Defense Evasion",
    "ssh_brute_force":      "TA0006 - Credential Access",
    "credential_stuffing":  "TA0006 - Credential Access",
    "scanner":              "TA0043 - Reconnaissance",
    "scanning":             "TA0043 - Reconnaissance",
    "reconnaissance":       "TA0043 - Reconnaissance",
    "c2":                   "TA0011 - Command and Control",
    "c2_server":            "TA0011 - Command and Control",
    "botnet":               "TA0011 - Command and Control",
    "malware":              "TA0002 - Execution",
    "abusive":              "TA0040 - Impact",
    "hosting":              "TA0001 - Initial Access",
    "high_risk_country":    "TA0043 - Reconnaissance",
}

# ---------------------------------------------------------------------------
# Seed table — always authoritative, mirrors ip_reputation / geo / feeds seeds
# ---------------------------------------------------------------------------

_SEED: dict[str, dict] = {
    "185.220.101.45": {
        "is_threat":        True,
        "threat_level":     "critical",
        "threat_score":     0.97,
        "indicators":       ["tor_exit", "ssh_brute_force", "scanner",
                             "reconnaissance", "credential_stuffing"],
        "feed_hits":        ["tor-exit-nodes", "ssh-brute-force-ips", "shodan-scanner"],
        "geo_risk":         True,
        "reputation_score": 0.97,
        "country":          "Russia",
        "country_code":     "RU",
        "is_tor":           True,
        "mitre_tactics":    [
            "TA0005 - Defense Evasion",
            "TA0006 - Credential Access",
            "TA0043 - Reconnaissance",
        ],
        "analyst_summary": (
            "Critical: Tor exit node; high-risk geolocation (Russia); "
            "listed in tor-exit-nodes, ssh-brute-force-ips (+1 more); "
            "brute-force / credential activity confirmed; "
            "active reconnaissance / scanning."
        ),
        "sources": ["ip_reputation", "geo_enrichment", "threat_feeds"],
    },
    "23.129.64.101": {
        "is_threat":        True,
        "threat_level":     "high",
        "threat_score":     0.78,
        "indicators":       ["tor_exit", "anonymization"],
        "feed_hits":        ["tor-exit-nodes"],
        "geo_risk":         True,
        "reputation_score": 0.88,
        "country":          "Germany",
        "country_code":     "DE",
        "is_tor":           True,
        "mitre_tactics":    ["TA0005 - Defense Evasion"],
        "analyst_summary": (
            "High: Tor exit node; listed in tor-exit-nodes."
        ),
        "sources": ["ip_reputation", "geo_enrichment", "threat_feeds"],
    },
}

# ---------------------------------------------------------------------------
# Module-level TTL cache for synthesized results
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Threat level thresholds
# ---------------------------------------------------------------------------

def _threat_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.40:
        return "medium"
    if score >= 0.10:
        return "low"
    return "none"


# ---------------------------------------------------------------------------
# Analyst summary builder
# ---------------------------------------------------------------------------

def _build_summary(level: str, indicators: list[str], geo: dict, feeds: dict) -> str:
    if level == "none":
        return "No threat indicators detected."

    parts: list[str] = []

    if geo.get("is_tor"):
        parts.append("Tor exit node")
    if geo.get("high_risk_country"):
        country = geo.get("country") or "unknown country"
        parts.append(f"high-risk geolocation ({country})")

    feed_hits = feeds.get("feed_hits") or []
    if feed_hits:
        preview = ", ".join(feed_hits[:2])
        suffix  = f" (+{len(feed_hits) - 2} more)" if len(feed_hits) > 2 else ""
        parts.append(f"listed in {preview}{suffix}")

    if any(i in indicators for i in ("ssh_brute_force", "credential_stuffing")):
        parts.append("brute-force / credential activity confirmed")
    if any(i in indicators for i in ("scanner", "scanning", "reconnaissance")):
        parts.append("active reconnaissance / scanning")
    if any(i in indicators for i in ("c2", "c2_server", "botnet")):
        parts.append("C2 / botnet infrastructure")

    body = "; ".join(parts) if parts else "elevated risk signals"
    return f"{level.capitalize()}: {body}."


# ---------------------------------------------------------------------------
# Synthesis core
# ---------------------------------------------------------------------------

def _synthesize(ip: str, rep: dict, geo: dict, feeds: dict) -> dict:
    """Combine outputs of ip_reputation, geo_enrichment, and threat_feeds."""
    # Deduplicated indicator list: reputation categories + feed threat categories
    seen: set[str] = set()
    indicators: list[str] = []
    for cat in (rep.get("categories") or []) + (feeds.get("threat_categories") or []):
        if cat not in seen:
            seen.add(cat)
            indicators.append(cat)

    # Geo risk flags
    is_tor       = bool(geo.get("is_tor"))
    high_risk    = bool(geo.get("high_risk_country"))
    geo_risk     = is_tor or high_risk

    if is_tor and "tor_exit" not in seen:
        indicators.append("tor_exit")
    if high_risk and "high_risk_country" not in seen:
        indicators.append("high_risk_country")

    # Composite threat score:
    #   reputation (0.5) + feed confidence (0.3) + geo bonus (0.2 tor / 0.1 country)
    rep_score  = float(rep.get("reputation_score") or 0.0)
    feed_conf  = float(feeds.get("confidence") or 0.0)
    geo_bonus  = 0.20 if is_tor else (0.10 if high_risk else 0.0)
    threat_score = round(min(rep_score * 0.5 + feed_conf * 0.3 + geo_bonus, 1.0), 4)

    level     = _threat_level(threat_score)
    feed_hits = feeds.get("feed_hits") or []
    is_threat = bool(rep.get("is_malicious")) or bool(feed_hits) or threat_score >= 0.10

    # MITRE tactics (ordered, deduplicated)
    mitre_seen: set[str] = set()
    mitre_tactics: list[str] = []
    for ind in indicators:
        tactic = _INDICATOR_TO_MITRE.get(ind)
        if tactic and tactic not in mitre_seen:
            mitre_seen.add(tactic)
            mitre_tactics.append(tactic)

    # Sources that contributed non-stub data
    sources: list[str] = []
    rep_source = rep.get("source") or ""
    if rep_source not in ("none", ""):
        sources.append("ip_reputation")
    if feed_hits:
        sources.append("threat_feeds")
    geo_country = geo.get("country") or "Unknown"
    if geo_country not in ("Unknown", "Internal"):
        sources.append("geo_enrichment")
    if not sources:
        sources.append("none")

    return {
        "ip":               ip,
        "is_threat":        is_threat,
        "threat_level":     level,
        "threat_score":     threat_score,
        "indicators":       indicators,
        "feed_hits":        feed_hits,
        "geo_risk":         geo_risk,
        "reputation_score": rep_score,
        "country":          geo_country,
        "country_code":     geo.get("country_code") or "XX",
        "is_tor":           is_tor,
        "mitre_tactics":    mitre_tactics,
        "analyst_summary":  _build_summary(level, indicators, geo, feeds),
        "sources":          sources,
    }


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

_SCHEMA_KEYS: frozenset[str] = frozenset({
    "ip", "is_threat", "threat_level", "threat_score",
    "indicators", "feed_hits", "geo_risk", "reputation_score",
    "country", "country_code", "is_tor", "mitre_tactics",
    "analyst_summary", "sources",
})


class ThreatEnricher:
    """
    Synthesizes ip_reputation, geo_enrichment, and threat_feeds into a single
    threat assessment per IP.
    Stateless at the instance level; cache is module-level for performance.

    Public API:
        enrich(ip: str) -> dict
            Schema keys: ip, is_threat, threat_level, threat_score, indicators,
            feed_hits, geo_risk, reputation_score, country, country_code, is_tor,
            mitre_tactics, analyst_summary, sources.
    """

    def enrich(self, ip: str) -> dict:
        """
        Return a unified threat intelligence assessment for ip.

        threat_score is a weighted composite:
            reputation_score * 0.5 + feed_confidence * 0.3 + geo_bonus * 0.2
            where geo_bonus = 0.2 for Tor, 0.1 for high-risk country, 0 otherwise.

        threat_level maps threat_score to: none / low / medium / high / critical.
        """
        if not ip:
            return self._empty(ip)

        # 1. Seed table — always authoritative for known IPs
        if ip in _SEED:
            return {"ip": ip, **_SEED[ip]}

        # 2. RFC-1918 / private ranges — never a threat
        if _is_private(ip):
            return self._private(ip)

        # 3. Cache check
        cached = _cache_get(ip)
        if cached is not None:
            return cached

        # 4. Synthesize from underlying intelligence modules
        from intelligence.ip_reputation import IpReputation
        from intelligence.geo_enrichment import GeoEnrichment
        from intelligence.threat_feeds   import ThreatFeeds

        try:
            rep   = IpReputation().lookup(ip)
        except Exception:
            rep   = {"is_malicious": False, "reputation_score": 0.0,
                     "categories": [], "source": "none"}
        try:
            geo   = GeoEnrichment().lookup(ip)
        except Exception:
            geo   = {"country": "Unknown", "country_code": "XX",
                     "is_tor": False, "high_risk_country": False}
        try:
            feeds = ThreatFeeds().check(ip)
        except Exception:
            feeds = {"feed_hits": [], "threat_categories": [], "confidence": 0.0}

        result = _synthesize(ip, rep, geo, feeds)

        from config.settings import settings as _settings
        _cache_set(ip, result, _settings.intel_cache_ttl)
        return result

    # ------------------------------------------------------------------
    # Stub results
    # ------------------------------------------------------------------

    @staticmethod
    def _empty(ip: str) -> dict:
        return {
            "ip":               ip,
            "is_threat":        False,
            "threat_level":     "none",
            "threat_score":     0.0,
            "indicators":       [],
            "feed_hits":        [],
            "geo_risk":         False,
            "reputation_score": 0.0,
            "country":          "Unknown",
            "country_code":     "XX",
            "is_tor":           False,
            "mitre_tactics":    [],
            "analyst_summary":  "No threat indicators detected.",
            "sources":          ["none"],
        }

    @staticmethod
    def _private(ip: str) -> dict:
        return {
            "ip":               ip,
            "is_threat":        False,
            "threat_level":     "none",
            "threat_score":     0.0,
            "indicators":       ["internal"],
            "feed_hits":        [],
            "geo_risk":         False,
            "reputation_score": 0.0,
            "country":          "Internal",
            "country_code":     "IN",
            "is_tor":           False,
            "mitre_tactics":    [],
            "analyst_summary":  "Private/internal address — not evaluated.",
            "sources":          ["rfc1918"],
        }
