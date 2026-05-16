"""Tests for intelligence/ip_reputation.py, geo_enrichment.py, threat_feeds.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.ip_reputation import IpReputation
from intelligence.geo_enrichment import GeoEnrichment
from intelligence.threat_feeds import ThreatFeeds


# ---------------------------------------------------------------------------
# IpReputation
# ---------------------------------------------------------------------------

class TestIpReputation:
    def setup_method(self):
        self.rep = IpReputation()

    def test_known_malicious_ip(self):
        result = self.rep.lookup("185.220.101.45")
        assert result["is_malicious"] is True
        assert result["reputation_score"] == 0.97
        assert "tor_exit" in result["categories"]
        assert result["report_count"] > 0

    def test_known_tor_exit_ip(self):
        result = self.rep.lookup("23.129.64.101")
        assert result["is_malicious"] is True
        assert "tor_exit" in result["categories"]

    def test_private_ip_not_malicious(self):
        result = self.rep.lookup("10.0.0.5")
        assert result["is_malicious"] is False
        assert result["reputation_score"] == 0.0
        assert "internal" in result["categories"]

    def test_private_192_168(self):
        result = self.rep.lookup("192.168.1.100")
        assert result["is_malicious"] is False
        assert result["source"] == "rfc1918"

    def test_private_127(self):
        result = self.rep.lookup("127.0.0.1")
        assert result["is_malicious"] is False

    def test_unknown_external_ip_neutral(self):
        result = self.rep.lookup("8.8.8.8")
        assert result["is_malicious"] is False
        assert result["reputation_score"] == 0.05
        assert "unknown" in result["categories"]

    def test_empty_string_returns_neutral(self):
        result = self.rep.lookup("")
        assert result["is_malicious"] is False
        assert result["reputation_score"] == 0.0

    def test_schema_keys_always_present(self):
        for ip in ("185.220.101.45", "10.0.0.1", "8.8.8.8", ""):
            result = self.rep.lookup(ip)
            assert set(result.keys()) == {
                "ip", "is_malicious", "reputation_score",
                "categories", "source", "report_count"
            }

    def test_ip_field_echoes_input(self):
        assert self.rep.lookup("185.220.101.45")["ip"] == "185.220.101.45"
        assert self.rep.lookup("10.0.0.1")["ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# GeoEnrichment
# ---------------------------------------------------------------------------

class TestGeoEnrichment:
    def setup_method(self):
        self.geo = GeoEnrichment()

    def test_known_russian_tor_exit(self):
        result = self.geo.lookup("185.220.101.45")
        assert result["country"] == "Russia"
        assert result["country_code"] == "RU"
        assert result["is_tor"] is True
        assert result["high_risk_country"] is True

    def test_known_german_tor_exit(self):
        result = self.geo.lookup("23.129.64.101")
        assert result["country"] == "Germany"
        assert result["is_tor"] is True
        assert result["high_risk_country"] is False

    def test_private_ip_returns_internal(self):
        result = self.geo.lookup("10.0.0.5")
        assert result["country"] == "Internal"
        assert result["country_code"] == "IN"
        assert result["is_tor"] is False
        assert result["high_risk_country"] is False

    def test_private_172_range(self):
        result = self.geo.lookup("172.16.0.1")
        assert result["country"] == "Internal"

    def test_unknown_ip_returns_defaults(self):
        result = self.geo.lookup("8.8.8.8")
        assert result["country"] == "Unknown"
        assert result["country_code"] == "XX"
        assert result["is_tor"] is False

    def test_empty_string_returns_defaults(self):
        result = self.geo.lookup("")
        assert result["country"] == "Unknown"
        assert result["is_tor"] is False

    def test_schema_keys_always_present(self):
        for ip in ("185.220.101.45", "10.0.0.1", "8.8.8.8", ""):
            result = self.geo.lookup(ip)
            assert set(result.keys()) == {
                "ip", "country", "country_code", "city",
                "asn", "org", "is_tor", "high_risk_country"
            }

    def test_ip_field_echoes_input(self):
        assert self.geo.lookup("185.220.101.45")["ip"] == "185.220.101.45"


# ---------------------------------------------------------------------------
# ThreatFeeds
# ---------------------------------------------------------------------------

class TestThreatFeeds:
    def setup_method(self):
        self.feeds = ThreatFeeds()

    def test_known_high_confidence_ip(self):
        result = self.feeds.check("185.220.101.45")
        assert "tor-exit-nodes" in result["feed_hits"]
        assert "ssh-brute-force-ips" in result["feed_hits"]
        assert "shodan-scanner" in result["feed_hits"]
        assert result["confidence"] == 0.97
        assert "reconnaissance" in result["threat_categories"]

    def test_known_tor_only_ip(self):
        result = self.feeds.check("23.129.64.101")
        assert "tor-exit-nodes" in result["feed_hits"]
        assert result["confidence"] == 0.82

    def test_unknown_ip_returns_empty_hits(self):
        result = self.feeds.check("8.8.8.8")
        assert result["feed_hits"] == []
        assert result["threat_categories"] == []
        assert result["confidence"] == 0.0

    def test_empty_string_returns_empty_hits(self):
        result = self.feeds.check("")
        assert result["feed_hits"] == []
        assert result["confidence"] == 0.0

    def test_schema_keys_always_present(self):
        for ip in ("185.220.101.45", "8.8.8.8", ""):
            result = self.feeds.check(ip)
            assert set(result.keys()) == {
                "ip", "feed_hits", "threat_categories",
                "confidence", "first_seen", "last_seen"
            }

    def test_ip_field_echoes_input(self):
        assert self.feeds.check("185.220.101.45")["ip"] == "185.220.101.45"
        assert self.feeds.check("8.8.8.8")["ip"] == "8.8.8.8"

    def test_known_ip_has_dates(self):
        result = self.feeds.check("185.220.101.45")
        assert result["first_seen"] is not None
        assert result["last_seen"] is not None

    def test_unknown_ip_dates_are_none(self):
        result = self.feeds.check("8.8.8.8")
        assert result["first_seen"] is None
        assert result["last_seen"] is None
