"""
tests/test_intelligence_live.py — Tests for Fix 6: live intelligence layer.

Covers cache behaviour, API fallback, seed-table priority, and the HTTP helper.
No real network calls are made — live paths are blocked by the default empty
SENTINEL_ABUSEIPDB_KEY and SENTINEL_GEO_ENABLED=false.
"""
from __future__ import annotations

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# HTTP helper
# ===========================================================================

class TestIntelHttpError:
    def test_import(self):
        from intelligence._http import IntelHttpError, get_json
        assert callable(get_json)
        assert issubclass(IntelHttpError, Exception)

    def test_bad_url_raises_intel_http_error(self):
        from intelligence._http import IntelHttpError, get_json
        with pytest.raises(IntelHttpError):
            get_json("http://0.0.0.0:1/nonexistent", timeout=1)


# ===========================================================================
# IP Reputation — cache and fallback
# ===========================================================================

import pytest


class TestIpReputationCache:
    def setup_method(self):
        from intelligence import ip_reputation as _mod
        _mod._cache.clear()
        self.mod = _mod

    def test_seed_table_returned_immediately(self):
        from intelligence.ip_reputation import IpReputation
        result = IpReputation().lookup("185.220.101.45")
        assert result["is_malicious"] is True
        assert result["source"] == "internal_threat_feed"

    def test_private_ip_never_malicious(self):
        from intelligence.ip_reputation import IpReputation
        result = IpReputation().lookup("10.0.0.1")
        assert result["is_malicious"] is False
        assert "internal" in result["categories"]

    def test_unknown_ip_stub_without_key(self):
        import unittest.mock as mock
        import config.settings as _cfg
        from intelligence.ip_reputation import IpReputation
        stub = _cfg.settings.model_copy(update={"abuseipdb_key": ""})
        self.mod._cache.clear()
        with mock.patch.object(_cfg, "settings", stub):
            result = IpReputation().lookup("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["is_malicious"] is False
        assert result["source"] == "none"

    def test_cache_stores_result(self):
        from intelligence.ip_reputation import IpReputation, _cache_set, _cache_get
        fake = {"is_malicious": True, "reputation_score": 0.9,
                "categories": ["test"], "source": "test", "report_count": 1}
        _cache_set("9.9.9.9", fake, ttl=60)
        cached = _cache_get("9.9.9.9")
        assert cached is not None
        assert cached["source"] == "test"

    def test_cache_expiry(self):
        from intelligence.ip_reputation import _cache_set, _cache_get
        fake = {"is_malicious": False, "reputation_score": 0.0,
                "categories": [], "source": "test", "report_count": 0}
        _cache_set("8.8.8.8", fake, ttl=0)  # TTL=0 → already expired
        time.sleep(0.01)
        assert _cache_get("8.8.8.8") is None

    def test_cached_result_returned_on_second_lookup(self):
        from intelligence.ip_reputation import IpReputation, _cache_set
        fake = {"is_malicious": True, "reputation_score": 0.99,
                "categories": ["cached"], "source": "cache_test", "report_count": 99}
        _cache_set("7.7.7.7", fake, ttl=60)
        result = IpReputation().lookup("7.7.7.7")
        assert result["source"] == "cache_test"

    def test_empty_ip_returns_neutral(self):
        from intelligence.ip_reputation import IpReputation
        result = IpReputation().lookup("")
        assert result["is_malicious"] is False
        assert result["source"] == "none"

    def test_seed_table_bypasses_cache(self):
        """Seed table result is returned even when cache holds a different value."""
        from intelligence.ip_reputation import IpReputation, _cache_set
        fake = {"is_malicious": False, "reputation_score": 0.0,
                "categories": [], "source": "wrong", "report_count": 0}
        _cache_set("185.220.101.45", fake, ttl=3600)
        result = IpReputation().lookup("185.220.101.45")
        assert result["source"] == "internal_threat_feed"  # seed wins

    def test_abuseipdb_lookup_skipped_without_key(self):
        """No live call should be attempted when api key is not configured."""
        import unittest.mock as mock
        import config.settings as _cfg
        from intelligence import ip_reputation as _mod
        from intelligence.ip_reputation import IpReputation
        stub = _cfg.settings.model_copy(update={"abuseipdb_key": ""})
        self.mod._cache.clear()
        with mock.patch.object(_cfg, "settings", stub):
            with mock.patch.object(_mod, "get_json") as patched:
                IpReputation().lookup("5.5.5.5")
                patched.assert_not_called()

    def test_abuseipdb_fallback_on_error(self):
        """When live API raises IntelHttpError, stub data is returned."""
        import unittest.mock as mock
        from intelligence._http import IntelHttpError
        from intelligence import ip_reputation as _mod
        from intelligence.ip_reputation import IpReputation
        from config.settings import get_settings
        os.environ["SENTINEL_ABUSEIPDB_KEY"] = "fake-key"
        get_settings.cache_clear()
        try:
            with mock.patch.object(_mod, "get_json", side_effect=IntelHttpError("timeout")):
                result = IpReputation().lookup("6.6.6.6")
            assert result["is_malicious"] is False
            assert result["source"] == "none"
        finally:
            del os.environ["SENTINEL_ABUSEIPDB_KEY"]
            get_settings.cache_clear()
            _mod._cache.clear()


# ===========================================================================
# Geo Enrichment — cache and fallback
# ===========================================================================

class TestGeoEnrichmentCache:
    def setup_method(self):
        from intelligence import geo_enrichment as _mod
        _mod._cache.clear()

    def test_seed_table_returned_immediately(self):
        from intelligence.geo_enrichment import GeoEnrichment
        result = GeoEnrichment().lookup("185.220.101.45")
        assert result["country"] == "Russia"
        assert result["is_tor"] is True

    def test_private_ip_returns_internal(self):
        from intelligence.geo_enrichment import GeoEnrichment
        result = GeoEnrichment().lookup("192.168.1.1")
        assert result["country"] == "Internal"
        assert result["is_tor"] is False

    def test_unknown_ip_stub_without_geo_enabled(self):
        import unittest.mock as mock
        import config.settings as _cfg
        from intelligence import geo_enrichment as _geo_mod
        from intelligence.geo_enrichment import GeoEnrichment
        stub = _cfg.settings.model_copy(update={"geo_enabled": False})
        _geo_mod._cache.clear()
        with mock.patch.object(_cfg, "settings", stub):
            result = GeoEnrichment().lookup("1.2.3.4")
        assert result["country"] == "Unknown"
        assert result["country_code"] == "XX"

    def test_cache_stores_result(self):
        from intelligence.geo_enrichment import _cache_set, _cache_get
        fake = {"country": "TestLand", "country_code": "TT", "city": "Test",
                "asn": "", "org": "", "is_tor": False, "high_risk_country": False}
        _cache_set("9.9.9.9", fake, ttl=60)
        assert _cache_get("9.9.9.9")["country"] == "TestLand"

    def test_geo_lookup_skipped_without_flag(self):
        import unittest.mock as mock
        import config.settings as _cfg
        from intelligence import geo_enrichment as _mod
        from intelligence.geo_enrichment import GeoEnrichment
        stub = _cfg.settings.model_copy(update={"geo_enabled": False})
        _mod._cache.clear()
        with mock.patch.object(_cfg, "settings", stub):
            with mock.patch.object(_mod, "get_json") as patched:
                GeoEnrichment().lookup("5.5.5.5")
                patched.assert_not_called()

    def test_geo_fallback_on_error(self):
        """When live API raises IntelHttpError, stub data is returned."""
        import unittest.mock as mock
        from intelligence._http import IntelHttpError
        from intelligence import geo_enrichment as _mod
        from intelligence.geo_enrichment import GeoEnrichment
        from config.settings import get_settings
        os.environ["SENTINEL_GEO_ENABLED"] = "true"
        get_settings.cache_clear()
        try:
            with mock.patch.object(_mod, "get_json", side_effect=IntelHttpError("timeout")):
                result = GeoEnrichment().lookup("6.6.6.6")
            assert result["country"] == "Unknown"
        finally:
            del os.environ["SENTINEL_GEO_ENABLED"]
            get_settings.cache_clear()
            _mod._cache.clear()

    def test_high_risk_countries_set(self):
        from intelligence.geo_enrichment import _HIGH_RISK_COUNTRIES
        assert "RU" in _HIGH_RISK_COUNTRIES
        assert "CN" in _HIGH_RISK_COUNTRIES
        assert "US" not in _HIGH_RISK_COUNTRIES
