"""
Cross-validation tests: assert that ip_reputation, geo_enrichment, and
threat_feeds return mutually consistent results for every known IP in
their static tables.

If an IP is flagged malicious in one module it must be represented
consistently across the others. These tests catch table edits that
update one module but forget the others.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.ip_reputation import IpReputation, _KNOWN as _REP_KNOWN
from intelligence.geo_enrichment import GeoEnrichment, _GEO as _GEO_KNOWN
from intelligence.threat_feeds import ThreatFeeds, _FEEDS as _FEEDS_KNOWN


_rep   = IpReputation()
_geo   = GeoEnrichment()
_feeds = ThreatFeeds()

# Every IP that appears in any table
_ALL_KNOWN_IPS = sorted(set(_REP_KNOWN) | set(_GEO_KNOWN) | set(_FEEDS_KNOWN))


class TestCrossModuleCoverage:
    def test_all_known_ips_present_in_all_three_tables(self):
        """Every IP in any one table must appear in all three."""
        for ip in _ALL_KNOWN_IPS:
            assert ip in _REP_KNOWN,   f"{ip} missing from ip_reputation._KNOWN"
            assert ip in _GEO_KNOWN,   f"{ip} missing from geo_enrichment._GEO"
            assert ip in _FEEDS_KNOWN, f"{ip} missing from threat_feeds._FEEDS"

    def test_malicious_ips_have_feed_hits(self):
        """Every IP flagged is_malicious in ip_reputation must have feed_hits in threat_feeds."""
        for ip, data in _REP_KNOWN.items():
            if data["is_malicious"]:
                feeds_result = _feeds.check(ip)
                assert feeds_result["feed_hits"], (
                    f"{ip} is_malicious=True in ip_reputation "
                    f"but has no feed_hits in threat_feeds"
                )

    def test_malicious_ips_have_nonzero_feed_confidence(self):
        """Every is_malicious IP must have threat_feeds.confidence > 0."""
        for ip, data in _REP_KNOWN.items():
            if data["is_malicious"]:
                feeds_result = _feeds.check(ip)
                assert feeds_result["confidence"] > 0.0, (
                    f"{ip} is_malicious=True but threat_feeds.confidence == 0"
                )

    def test_tor_ips_consistent_across_geo_and_feeds(self):
        """Every IP with is_tor=True in geo must have 'tor-exit-nodes' in threat_feeds."""
        for ip, data in _GEO_KNOWN.items():
            if data.get("is_tor"):
                feeds_result = _feeds.check(ip)
                assert "tor-exit-nodes" in feeds_result["feed_hits"], (
                    f"{ip} is_tor=True in geo_enrichment "
                    f"but 'tor-exit-nodes' not in threat_feeds.feed_hits"
                )

    def test_tor_ips_flagged_malicious_in_reputation(self):
        """Every IP with is_tor=True in geo must be is_malicious=True in ip_reputation."""
        for ip, data in _GEO_KNOWN.items():
            if data.get("is_tor"):
                rep_result = _rep.lookup(ip)
                assert rep_result["is_malicious"] is True, (
                    f"{ip} is_tor=True in geo_enrichment "
                    f"but is_malicious=False in ip_reputation"
                )

    def test_high_risk_country_ips_have_elevated_reputation(self):
        """Every IP with high_risk_country=True should have reputation_score >= 0.7."""
        for ip, data in _GEO_KNOWN.items():
            if data.get("high_risk_country"):
                rep_result = _rep.lookup(ip)
                assert rep_result["reputation_score"] >= 0.7, (
                    f"{ip} high_risk_country=True but reputation_score="
                    f"{rep_result['reputation_score']} (expected >= 0.7)"
                )

    def test_reputation_score_and_feed_confidence_both_nonzero_for_known(self):
        """For every known malicious IP, both scores must be > 0."""
        for ip in _ALL_KNOWN_IPS:
            rep    = _rep.lookup(ip)
            feeds  = _feeds.check(ip)
            assert rep["reputation_score"] > 0.0, \
                f"{ip} reputation_score == 0"
            assert feeds["confidence"] > 0.0, \
                f"{ip} threat_feeds.confidence == 0"


class TestIpUtilsShared:
    """Verify all modules use the shared ip_utils and agree on private classification."""

    _PRIVATE_SAMPLES = [
        "10.0.0.1", "10.255.255.255",
        "192.168.0.1", "192.168.255.254",
        "172.16.0.1", "172.31.255.255",
        "127.0.0.1",
    ]
    _EXTERNAL_SAMPLES = ["185.220.101.45", "23.129.64.101", "8.8.8.8", "1.1.1.1"]

    def test_private_ips_not_malicious_in_reputation(self):
        for ip in self._PRIVATE_SAMPLES:
            assert _rep.lookup(ip)["is_malicious"] is False, \
                f"{ip} wrongly flagged malicious"

    def test_private_ips_internal_in_geo(self):
        for ip in self._PRIVATE_SAMPLES:
            assert _geo.lookup(ip)["country"] == "Internal", \
                f"{ip} not classified Internal in geo"

    def test_private_ips_no_feed_hits(self):
        for ip in self._PRIVATE_SAMPLES:
            assert _feeds.check(ip)["feed_hits"] == [], \
                f"{ip} has unexpected feed_hits"

    def test_external_classification_consistent(self):
        """External IPs must not be returned as Internal in geo."""
        for ip in self._EXTERNAL_SAMPLES:
            assert _geo.lookup(ip)["country"] != "Internal", \
                f"{ip} wrongly classified as Internal"
