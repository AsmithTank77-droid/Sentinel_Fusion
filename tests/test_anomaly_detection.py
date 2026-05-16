"""Tests for detection/anomaly_detection.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.anomaly_detection import AnomalyDetector


def _ev(src="185.220.101.45", dst="10.0.0.5", etype="port_scan",
        ts="2026-05-09T02:14:00Z", severity=5, enrichment=None):
    return {
        "src_ip": src, "dst_ip": dst, "event_type": etype,
        "severity": severity, "timestamp": ts,
        "metadata": {"enrichment": enrichment or {}},
    }


_MALICIOUS_ENRICHMENT = {
    "src_reputation": {"is_malicious": True, "reputation_score": 0.97,
                       "categories": ["tor_exit"]},
    "src_geo": {"country": "Russia", "is_tor": True, "high_risk_country": True},
    "src_threats": {"feed_hits": ["tor-exit-nodes"], "confidence": 0.97},
}


class TestAnomalyDetector:
    def setup_method(self):
        self.detector = AnomalyDetector()

    def test_empty_returns_empty(self):
        assert self.detector.detect([]) == []

    def test_clean_event_no_alerts(self):
        event = _ev(src="10.0.0.1", dst="10.0.0.5",
                    ts="2026-05-09T10:00:00Z", enrichment={})
        result = self.detector.detect([event])
        # off-hours rule won't fire at 10:00 UTC; no other signals
        assert result == []

    def test_malicious_ip_fires(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "malicious_ip_activity" in types

    def test_tor_exit_fires(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "tor_exit_node_activity" in types

    def test_high_risk_country_fires(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "high_risk_country_access" in types

    def test_off_hours_fires_at_02z(self):
        event = _ev(ts="2026-05-09T02:14:00Z", enrichment={})
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "off_hours_access" in types

    def test_business_hours_no_off_hours_alert(self):
        event = _ev(ts="2026-05-09T10:00:00Z", enrichment={})
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "off_hours_access" not in types

    def test_threat_feed_fires(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        types = {r["alert_type"] for r in result}
        assert "threat_feed_match" in types

    def test_deduplication_same_src_fires_once_per_type(self):
        events = [
            _ev(ts="2026-05-09T02:14:00Z", enrichment=_MALICIOUS_ENRICHMENT),
            _ev(ts="2026-05-09T02:15:00Z", enrichment=_MALICIOUS_ENRICHMENT),
        ]
        result = self.detector.detect(events)
        mal_alerts = [r for r in result if r["alert_type"] == "malicious_ip_activity"]
        assert len(mal_alerts) == 1

    def test_confidence_between_0_and_1(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        for alert in result:
            assert 0.0 <= alert["confidence"] <= 1.0

    def test_all_alert_dicts_have_required_keys(self):
        event = _ev(enrichment=_MALICIOUS_ENRICHMENT)
        result = self.detector.detect([event])
        required = {"alert_type", "confidence", "event_type",
                    "src_ip", "dst_ip", "timestamp", "severity", "mitre_tactic"}
        for alert in result:
            assert required.issubset(set(alert.keys()))
