"""Tests for live threat feed ingestion in intelligence/threat_feeds.py."""

from __future__ import annotations

import sys
import os
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import intelligence.threat_feeds as tf_module
from intelligence.threat_feeds import ThreatFeeds, _fetch_ip_list, _otx_lookup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_caches():
    tf_module._feed_cache.clear()
    tf_module._otx_cache.clear()


FEODO_RESPONSE = b"""# Feodo Tracker - IP Blocklist
# Generated: 2026-06-08
1.2.3.4
5.6.7.8
10.20.30.40
"""

ET_RESPONSE = b"""# Emerging Threats - Compromised IPs
9.9.9.9
1.2.3.4
"""

OTX_HIT_RESPONSE = {
    "reputation": {
        "threat_score": 7,
        "counts": {"malicious": 3, "benign": 0},
        "first_seen": "2025-01-01T00:00:00",
        "last_seen":  "2026-06-01T00:00:00",
    }
}

OTX_CLEAN_RESPONSE = {
    "reputation": {
        "threat_score": 0,
        "counts": {"malicious": 0, "benign": 0},
    }
}


# ---------------------------------------------------------------------------
# _fetch_ip_list
# ---------------------------------------------------------------------------

def test_fetch_ip_list_parses_ips_and_skips_comments():
    resp = mock.MagicMock()
    resp.read.return_value = FEODO_RESPONSE
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        result = _fetch_ip_list("http://fake-feed.example/ips.txt", timeout=5)

    assert "1.2.3.4" in result
    assert "5.6.7.8" in result
    assert "10.20.30.40" in result
    assert not any(ip.startswith("#") for ip in result)


def test_fetch_ip_list_strips_port_suffix():
    resp = mock.MagicMock()
    resp.read.return_value = b"1.2.3.4:8080\n5.6.7.8\n"
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        result = _fetch_ip_list("http://fake.example/ips.txt", timeout=5)

    assert "1.2.3.4" in result
    assert "1.2.3.4:8080" not in result


def test_fetch_ip_list_raises_on_network_error():
    import urllib.error
    with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        try:
            _fetch_ip_list("http://unreachable.example/ips.txt", timeout=1)
            assert False, "should raise"
        except Exception as exc:
            assert "Failed to fetch feed" in str(exc) or "timeout" in str(exc)


# ---------------------------------------------------------------------------
# ThreatFeeds.check() — seed table still works
# ---------------------------------------------------------------------------

def test_seed_table_still_works_with_feeds_enabled():
    _clear_caches()
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        feeds = ThreatFeeds()
        result = feeds.check("185.220.101.45")

    assert result["confidence"] == 0.97
    assert "tor-exit-nodes" in result["feed_hits"]


def test_seed_table_wins_over_live_feeds():
    _clear_caches()
    # Even if live feeds are enabled, seed table is checked first — no HTTP calls made
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen") as mock_url:
            result = ThreatFeeds().check("185.220.101.45")
            mock_url.assert_not_called()

    assert result["confidence"] == 0.97


# ---------------------------------------------------------------------------
# ThreatFeeds.check() — live feed hits
# ---------------------------------------------------------------------------

def _make_urlopen_side_effect(responses: dict[str, bytes]):
    """Return a urlopen side effect that serves different bytes per URL."""
    def side_effect(req, timeout=5):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for pattern, body in responses.items():
            if pattern in url:
                resp = mock.MagicMock()
                resp.read.return_value = body
                resp.__enter__ = lambda s: s
                resp.__exit__ = mock.MagicMock(return_value=False)
                return resp
        raise Exception(f"No mock for URL: {url}")
    return side_effect


def test_ip_in_feodo_feed_returns_feed_hit():
    _clear_caches()
    side_effect = _make_urlopen_side_effect({
        "feodotracker": FEODO_RESPONSE,
        "emergingthreats": b"# empty\n",
    })
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            result = ThreatFeeds().check("1.2.3.4")

    assert "feodo-tracker" in result["feed_hits"]
    assert "c2" in result["threat_categories"]
    assert result["confidence"] == 0.90


def test_ip_in_emerging_threats_returns_feed_hit():
    _clear_caches()
    side_effect = _make_urlopen_side_effect({
        "feodotracker": b"# empty\n",
        "emergingthreats": ET_RESPONSE,
    })
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            result = ThreatFeeds().check("9.9.9.9")

    assert "emerging-threats" in result["feed_hits"]
    assert "compromised" in result["threat_categories"]
    assert result["confidence"] == 0.75


def test_ip_in_both_feeds_returns_both_hits():
    _clear_caches()
    side_effect = _make_urlopen_side_effect({
        "feodotracker": FEODO_RESPONSE,
        "emergingthreats": ET_RESPONSE,
    })
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            result = ThreatFeeds().check("1.2.3.4")

    assert "feodo-tracker" in result["feed_hits"]
    assert "emerging-threats" in result["feed_hits"]
    assert result["confidence"] == 0.90  # max of both


def test_ip_not_in_any_feed_returns_empty():
    _clear_caches()
    side_effect = _make_urlopen_side_effect({
        "feodotracker": FEODO_RESPONSE,
        "emergingthreats": ET_RESPONSE,
    })
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            result = ThreatFeeds().check("8.8.8.8")

    assert result["feed_hits"] == []
    assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# ThreatFeeds.check() — feeds disabled
# ---------------------------------------------------------------------------

def test_feeds_disabled_returns_empty_for_unknown_ip():
    _clear_caches()
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = False
        result = ThreatFeeds().check("1.2.3.4")

    assert result["feed_hits"] == []
    assert result["confidence"] == 0.0


def test_feeds_disabled_no_http_calls():
    _clear_caches()
    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = False
        with mock.patch("urllib.request.urlopen") as mock_url:
            ThreatFeeds().check("1.2.3.4")
            mock_url.assert_not_called()


# ---------------------------------------------------------------------------
# Live feed cache
# ---------------------------------------------------------------------------

def test_feed_is_cached_after_first_fetch():
    _clear_caches()
    call_count = {"n": 0}

    def counting_urlopen(req, timeout=5):
        call_count["n"] += 1
        resp = mock.MagicMock()
        resp.read.return_value = FEODO_RESPONSE
        resp.__enter__ = lambda s: s
        resp.__exit__ = mock.MagicMock(return_value=False)
        return resp

    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=counting_urlopen):
            ThreatFeeds().check("1.2.3.4")
            ThreatFeeds().check("5.6.7.8")

    # feodo + ET = 2 fetches, not 4
    assert call_count["n"] == 2


def test_failed_feed_fetch_returns_empty_gracefully():
    _clear_caches()
    import urllib.error

    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = ""
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = ThreatFeeds().check("1.2.3.4")

    assert result["feed_hits"] == []


# ---------------------------------------------------------------------------
# _otx_lookup
# ---------------------------------------------------------------------------

def test_otx_lookup_returns_enriched_result_on_hit():
    with mock.patch("intelligence.threat_feeds.get_json", return_value=OTX_HIT_RESPONSE):
        result = _otx_lookup("1.2.3.4", api_key="test-key", timeout=5)

    assert result is not None
    assert "otx" in result["feed_hits"]
    assert result["confidence"] == 0.7
    assert result["first_seen"] == "2025-01-01"


def test_otx_lookup_returns_none_on_clean_ip():
    with mock.patch("intelligence.threat_feeds.get_json", return_value=OTX_CLEAN_RESPONSE):
        result = _otx_lookup("8.8.8.8", api_key="test-key", timeout=5)

    assert result is None


def test_otx_lookup_returns_none_on_api_error():
    from intelligence._http import IntelHttpError
    with mock.patch("intelligence.threat_feeds.get_json", side_effect=IntelHttpError("timeout")):
        result = _otx_lookup("1.2.3.4", api_key="test-key", timeout=5)

    assert result is None


def test_otx_result_is_cached():
    _clear_caches()
    call_count = {"n": 0}

    def counting_get_json(url, headers=None, timeout=5):
        call_count["n"] += 1
        return OTX_HIT_RESPONSE

    with mock.patch("config.settings.settings") as s:
        s.feeds_enabled = True
        s.intel_cache_ttl = 3600
        s.intel_timeout = 5
        s.otx_key = "test-key"

        side_effect = _make_urlopen_side_effect({
            "feodotracker": b"# empty\n",
            "emergingthreats": b"# empty\n",
        })
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            with mock.patch("intelligence.threat_feeds.get_json", side_effect=counting_get_json):
                ThreatFeeds().check("1.2.3.4")
                ThreatFeeds().check("1.2.3.4")

    assert call_count["n"] == 1
