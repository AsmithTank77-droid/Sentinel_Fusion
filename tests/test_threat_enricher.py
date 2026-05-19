"""Tests for intelligence/threat_enricher.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from intelligence.threat_enricher import (
    ThreatEnricher,
    _synthesize,
    _build_summary,
    _threat_level,
    _INDICATOR_TO_MITRE,
    _SCHEMA_KEYS,
    _cache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KNOWN_CRITICAL = "185.220.101.45"
_KNOWN_HIGH     = "23.129.64.101"
_INTERNAL       = "192.168.1.10"
_LOOPBACK       = "127.0.0.1"
_PRIVATE_10     = "10.0.0.5"
_UNKNOWN_EXT    = "8.8.8.8"

# Minimal stubs used to drive _synthesize directly
_REP_CLEAN  = {"is_malicious": False, "reputation_score": 0.0,
               "categories": [], "source": "none"}
_GEO_CLEAN  = {"country": "Unknown", "country_code": "XX",
               "is_tor": False, "high_risk_country": False}
_FEED_CLEAN = {"feed_hits": [], "threat_categories": [], "confidence": 0.0}

_REP_HIGH   = {"is_malicious": True, "reputation_score": 0.90,
               "categories": ["tor_exit", "scanner"], "source": "abuseipdb"}
_GEO_TOR    = {"country": "Russia", "country_code": "RU",
               "is_tor": True, "high_risk_country": True}
_FEED_HIGH  = {"feed_hits": ["tor-exit-nodes", "ssh-brute-force-ips"],
               "threat_categories": ["anonymization", "credential_stuffing"],
               "confidence": 0.82}

_REP_MED    = {"is_malicious": False, "reputation_score": 0.55,
               "categories": ["hosting"], "source": "abuseipdb"}
_GEO_NORM   = {"country": "Netherlands", "country_code": "NL",
               "is_tor": False, "high_risk_country": False}
_FEED_NONE  = {"feed_hits": [], "threat_categories": [], "confidence": 0.0}

_REP_LOW    = {"is_malicious": False, "reputation_score": 0.20,
               "categories": ["unknown"], "source": "none"}
_GEO_HRISK  = {"country": "Iran", "country_code": "IR",
               "is_tor": False, "high_risk_country": True}


@pytest.fixture(autouse=True)
def clear_cache():
    """Isolate tests from module-level cache state."""
    _cache.clear()
    yield
    _cache.clear()


@pytest.fixture
def enricher():
    return ThreatEnricher()


# ---------------------------------------------------------------------------
# Schema completeness
# ---------------------------------------------------------------------------

class TestSchema:
    def test_all_schema_keys_present_for_known_critical(self, enricher):
        result = enricher.enrich(_KNOWN_CRITICAL)
        assert _SCHEMA_KEYS == set(result.keys())

    def test_all_schema_keys_present_for_internal(self, enricher):
        result = enricher.enrich(_INTERNAL)
        assert _SCHEMA_KEYS == set(result.keys())

    def test_all_schema_keys_present_for_empty(self, enricher):
        result = enricher.enrich("")
        assert _SCHEMA_KEYS == set(result.keys())

    def test_all_schema_keys_present_for_unknown_external(self, enricher):
        result = enricher.enrich(_UNKNOWN_EXT)
        assert _SCHEMA_KEYS == set(result.keys())

    def test_ip_field_matches_input(self, enricher):
        for ip in (_KNOWN_CRITICAL, _INTERNAL, _UNKNOWN_EXT, ""):
            assert enricher.enrich(ip)["ip"] == ip

    def test_indicators_is_list(self, enricher):
        assert isinstance(enricher.enrich(_KNOWN_CRITICAL)["indicators"], list)

    def test_feed_hits_is_list(self, enricher):
        assert isinstance(enricher.enrich(_KNOWN_CRITICAL)["feed_hits"], list)

    def test_mitre_tactics_is_list(self, enricher):
        assert isinstance(enricher.enrich(_KNOWN_CRITICAL)["mitre_tactics"], list)

    def test_sources_is_list(self, enricher):
        assert isinstance(enricher.enrich(_KNOWN_CRITICAL)["sources"], list)

    def test_threat_score_in_range(self, enricher):
        for ip in (_KNOWN_CRITICAL, _KNOWN_HIGH, _INTERNAL, _UNKNOWN_EXT):
            score = enricher.enrich(ip)["threat_score"]
            assert 0.0 <= score <= 1.0, f"{ip}: score {score} out of range"

    def test_threat_level_valid_values(self, enricher):
        valid = {"none", "low", "medium", "high", "critical"}
        for ip in (_KNOWN_CRITICAL, _KNOWN_HIGH, _INTERNAL, _UNKNOWN_EXT, ""):
            level = enricher.enrich(ip)["threat_level"]
            assert level in valid, f"{ip}: unexpected level {level!r}"


# ---------------------------------------------------------------------------
# Seed table — known IPs
# ---------------------------------------------------------------------------

class TestSeedTable:
    def test_known_critical_is_threat(self, enricher):
        result = enricher.enrich(_KNOWN_CRITICAL)
        assert result["is_threat"] is True

    def test_known_critical_level(self, enricher):
        assert enricher.enrich(_KNOWN_CRITICAL)["threat_level"] == "critical"

    def test_known_critical_score(self, enricher):
        assert enricher.enrich(_KNOWN_CRITICAL)["threat_score"] == 0.97

    def test_known_critical_is_tor(self, enricher):
        assert enricher.enrich(_KNOWN_CRITICAL)["is_tor"] is True

    def test_known_critical_geo_risk(self, enricher):
        assert enricher.enrich(_KNOWN_CRITICAL)["geo_risk"] is True

    def test_known_critical_country(self, enricher):
        assert enricher.enrich(_KNOWN_CRITICAL)["country"] == "Russia"

    def test_known_critical_has_feed_hits(self, enricher):
        result = enricher.enrich(_KNOWN_CRITICAL)
        assert len(result["feed_hits"]) >= 2

    def test_known_critical_mitre_includes_credential_access(self, enricher):
        tactics = enricher.enrich(_KNOWN_CRITICAL)["mitre_tactics"]
        assert "TA0006 - Credential Access" in tactics

    def test_known_critical_mitre_includes_defense_evasion(self, enricher):
        tactics = enricher.enrich(_KNOWN_CRITICAL)["mitre_tactics"]
        assert "TA0005 - Defense Evasion" in tactics

    def test_known_critical_mitre_includes_recon(self, enricher):
        tactics = enricher.enrich(_KNOWN_CRITICAL)["mitre_tactics"]
        assert "TA0043 - Reconnaissance" in tactics

    def test_known_high_level(self, enricher):
        assert enricher.enrich(_KNOWN_HIGH)["threat_level"] == "high"

    def test_known_high_is_threat(self, enricher):
        assert enricher.enrich(_KNOWN_HIGH)["is_threat"] is True

    def test_known_high_is_tor(self, enricher):
        assert enricher.enrich(_KNOWN_HIGH)["is_tor"] is True

    def test_known_high_mitre_defense_evasion(self, enricher):
        assert "TA0005 - Defense Evasion" in enricher.enrich(_KNOWN_HIGH)["mitre_tactics"]

    def test_analyst_summary_non_empty_for_threats(self, enricher):
        summary = enricher.enrich(_KNOWN_CRITICAL)["analyst_summary"]
        assert summary and "Critical" in summary


# ---------------------------------------------------------------------------
# Private / RFC-1918 ranges
# ---------------------------------------------------------------------------

class TestPrivateRanges:
    @pytest.mark.parametrize("ip", [_INTERNAL, _LOOPBACK, _PRIVATE_10, "172.16.0.1"])
    def test_private_not_threat(self, enricher, ip):
        assert enricher.enrich(ip)["is_threat"] is False

    @pytest.mark.parametrize("ip", [_INTERNAL, _LOOPBACK, _PRIVATE_10])
    def test_private_level_none(self, enricher, ip):
        assert enricher.enrich(ip)["threat_level"] == "none"

    @pytest.mark.parametrize("ip", [_INTERNAL, _LOOPBACK, _PRIVATE_10])
    def test_private_score_zero(self, enricher, ip):
        assert enricher.enrich(ip)["threat_score"] == 0.0

    def test_private_source_rfc1918(self, enricher):
        assert enricher.enrich(_INTERNAL)["sources"] == ["rfc1918"]

    def test_private_country_internal(self, enricher):
        assert enricher.enrich(_INTERNAL)["country"] == "Internal"

    def test_private_indicators_contain_internal(self, enricher):
        assert "internal" in enricher.enrich(_INTERNAL)["indicators"]

    def test_private_no_geo_risk(self, enricher):
        assert enricher.enrich(_INTERNAL)["geo_risk"] is False

    def test_private_summary_mentions_private(self, enricher):
        summary = enricher.enrich(_INTERNAL)["analyst_summary"]
        assert "internal" in summary.lower() or "private" in summary.lower()


# ---------------------------------------------------------------------------
# Empty IP
# ---------------------------------------------------------------------------

class TestEmptyIp:
    def test_empty_not_threat(self, enricher):
        assert enricher.enrich("")["is_threat"] is False

    def test_empty_level_none(self, enricher):
        assert enricher.enrich("")["threat_level"] == "none"

    def test_empty_score_zero(self, enricher):
        assert enricher.enrich("")["threat_score"] == 0.0

    def test_empty_no_indicators(self, enricher):
        assert enricher.enrich("")["indicators"] == []

    def test_empty_sources_none(self, enricher):
        assert enricher.enrich("")["sources"] == ["none"]


# ---------------------------------------------------------------------------
# Unknown external IP (synthesized path)
# ---------------------------------------------------------------------------

class TestUnknownExternal:
    def test_unknown_external_not_threat(self, enricher):
        result = enricher.enrich(_UNKNOWN_EXT)
        assert result["is_threat"] is False

    def test_unknown_external_level_none(self, enricher):
        assert enricher.enrich(_UNKNOWN_EXT)["threat_level"] == "none"

    def test_unknown_external_low_score(self, enricher):
        assert enricher.enrich(_UNKNOWN_EXT)["threat_score"] < 0.10

    def test_unknown_external_no_feed_hits(self, enricher):
        assert enricher.enrich(_UNKNOWN_EXT)["feed_hits"] == []


# ---------------------------------------------------------------------------
# _synthesize — unit tests
# ---------------------------------------------------------------------------

class TestSynthesize:
    def test_high_rep_tor_high_risk_country(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert result["is_threat"] is True
        assert result["threat_level"] in ("high", "critical")
        assert result["threat_score"] > 0.65

    def test_threat_score_formula(self):
        # rep 0.9 * 0.5 = 0.45; feed 0.82 * 0.3 = 0.246; geo_bonus 0.2 (tor) → 0.896 → capped
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        expected = round(min(0.90 * 0.5 + 0.82 * 0.3 + 0.20, 1.0), 4)
        assert result["threat_score"] == expected

    def test_medium_rep_no_geo_risk(self):
        # Need rep_score >= 0.80 to reach medium band (0.80 * 0.5 = 0.40)
        rep_hi = {**_REP_MED, "reputation_score": 0.82}
        result = _synthesize("5.6.7.8", rep_hi, _GEO_NORM, _FEED_NONE)
        assert result["threat_level"] == "medium"
        assert 0.40 <= result["threat_score"] < 0.65

    def test_low_score_high_risk_country_only(self):
        result = _synthesize("5.6.7.8", _REP_LOW, _GEO_HRISK, _FEED_NONE)
        # rep 0.2 * 0.5 = 0.10; geo_bonus 0.1 → 0.20 → low
        assert result["threat_level"] == "low"
        assert result["geo_risk"] is True

    def test_clean_result_all_none(self):
        result = _synthesize("9.9.9.9", _REP_CLEAN, _GEO_CLEAN, _FEED_NONE)
        assert result["is_threat"] is False
        assert result["threat_level"] == "none"
        assert result["threat_score"] == 0.0

    def test_indicator_deduplication(self):
        # tor_exit appears in rep.categories and would be added from geo; should appear once
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert result["indicators"].count("tor_exit") == 1

    def test_indicators_include_rep_and_feed_categories(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        inds = result["indicators"]
        assert "tor_exit" in inds
        assert "scanner" in inds
        assert "credential_stuffing" in inds

    def test_feed_hits_preserved(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert "tor-exit-nodes" in result["feed_hits"]
        assert "ssh-brute-force-ips" in result["feed_hits"]

    def test_is_tor_from_geo(self):
        result = _synthesize("1.2.3.4", _REP_CLEAN, _GEO_TOR, _FEED_NONE)
        assert result["is_tor"] is True
        assert result["geo_risk"] is True

    def test_high_risk_country_no_tor(self):
        result = _synthesize("1.2.3.4", _REP_CLEAN, _GEO_HRISK, _FEED_NONE)
        assert result["geo_risk"] is True
        assert result["is_tor"] is False

    def test_mitre_tactics_ordered_and_deduplicated(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        tactics = result["mitre_tactics"]
        assert len(tactics) == len(set(tactics)), "mitre_tactics must not contain duplicates"

    def test_sources_ip_reputation_included(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert "ip_reputation" in result["sources"]

    def test_sources_threat_feeds_included_when_hits(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert "threat_feeds" in result["sources"]

    def test_sources_geo_included_when_country_known(self):
        result = _synthesize("1.2.3.4", _REP_HIGH, _GEO_TOR, _FEED_HIGH)
        assert "geo_enrichment" in result["sources"]

    def test_sources_none_when_all_stubs(self):
        result = _synthesize("9.9.9.9", _REP_CLEAN, _GEO_CLEAN, _FEED_NONE)
        assert result["sources"] == ["none"]

    def test_reputation_score_preserved(self):
        result = _synthesize("1.2.3.4", _REP_MED, _GEO_NORM, _FEED_NONE)
        assert result["reputation_score"] == 0.55

    def test_country_and_code_from_geo(self):
        result = _synthesize("1.2.3.4", _REP_CLEAN, _GEO_TOR, _FEED_NONE)
        assert result["country"] == "Russia"
        assert result["country_code"] == "RU"


# ---------------------------------------------------------------------------
# _threat_level thresholds
# ---------------------------------------------------------------------------

class TestThreatLevel:
    @pytest.mark.parametrize("score,expected", [
        (0.0,  "none"),
        (0.09, "none"),
        (0.10, "low"),
        (0.39, "low"),
        (0.40, "medium"),
        (0.64, "medium"),
        (0.65, "high"),
        (0.84, "high"),
        (0.85, "critical"),
        (1.0,  "critical"),
    ])
    def test_threshold(self, score, expected):
        assert _threat_level(score) == expected


# ---------------------------------------------------------------------------
# _build_summary
# ---------------------------------------------------------------------------

class TestBuildSummary:
    def test_none_level_returns_no_indicators(self):
        summary = _build_summary("none", [], _GEO_CLEAN, _FEED_NONE)
        assert "No threat" in summary

    def test_tor_mentioned(self):
        summary = _build_summary("critical", ["tor_exit"], _GEO_TOR, _FEED_NONE)
        assert "Tor" in summary

    def test_high_risk_country_mentioned(self):
        summary = _build_summary("high", ["high_risk_country"], _GEO_HRISK, _FEED_NONE)
        assert "Iran" in summary or "high-risk" in summary

    def test_feed_hits_listed(self):
        summary = _build_summary("high", ["tor_exit"], _GEO_TOR, _FEED_HIGH)
        assert "tor-exit-nodes" in summary

    def test_brute_force_mentioned(self):
        summary = _build_summary("critical", ["ssh_brute_force"], _GEO_CLEAN, _FEED_NONE)
        assert "brute-force" in summary

    def test_recon_mentioned(self):
        summary = _build_summary("medium", ["scanner"], _GEO_CLEAN, _FEED_NONE)
        assert "reconnaissance" in summary or "scanning" in summary

    def test_c2_mentioned(self):
        summary = _build_summary("high", ["c2"], _GEO_CLEAN, _FEED_NONE)
        assert "C2" in summary or "botnet" in summary.lower()

    def test_starts_with_capitalised_level(self):
        for level in ("low", "medium", "high", "critical"):
            summary = _build_summary(level, ["tor_exit"], _GEO_TOR, _FEED_NONE)
            assert summary.startswith(level.capitalize())

    def test_overflow_feeds_show_plus_more(self):
        feeds_many = {"feed_hits": ["a", "b", "c"], "threat_categories": []}
        summary = _build_summary("high", [], _GEO_CLEAN, feeds_many)
        assert "+1 more" in summary


# ---------------------------------------------------------------------------
# MITRE indicator mapping catalogue
# ---------------------------------------------------------------------------

class TestIndicatorToMitre:
    def test_tor_exit_maps_defense_evasion(self):
        assert _INDICATOR_TO_MITRE["tor_exit"] == "TA0005 - Defense Evasion"

    def test_ssh_brute_force_maps_credential_access(self):
        assert _INDICATOR_TO_MITRE["ssh_brute_force"] == "TA0006 - Credential Access"

    def test_scanner_maps_recon(self):
        assert _INDICATOR_TO_MITRE["scanner"] == "TA0043 - Reconnaissance"

    def test_c2_maps_command_and_control(self):
        assert _INDICATOR_TO_MITRE["c2"] == "TA0011 - Command and Control"

    def test_all_values_start_with_ta(self):
        for indicator, tactic in _INDICATOR_TO_MITRE.items():
            assert tactic.startswith("TA"), f"{indicator} maps to non-TA tactic: {tactic}"

    def test_minimum_coverage(self):
        # Ensure at least the six core threat categories are covered
        required = {"tor_exit", "ssh_brute_force", "scanner", "c2", "botnet", "anonymization"}
        assert required.issubset(set(_INDICATOR_TO_MITRE))


# ---------------------------------------------------------------------------
# Caching behaviour
# ---------------------------------------------------------------------------

class TestCaching:
    def test_result_is_cached_after_first_call(self, enricher):
        ip = _UNKNOWN_EXT
        enricher.enrich(ip)
        assert ip in _cache

    def test_cached_result_identical_to_first(self, enricher):
        ip = _UNKNOWN_EXT
        first  = enricher.enrich(ip)
        second = enricher.enrich(ip)
        assert first == second

    def test_seed_table_bypasses_cache(self, enricher):
        # Seed IPs should never be written to cache (they short-circuit before cache_set)
        enricher.enrich(_KNOWN_CRITICAL)
        assert _KNOWN_CRITICAL not in _cache

    def test_private_bypasses_cache(self, enricher):
        enricher.enrich(_INTERNAL)
        assert _INTERNAL not in _cache
