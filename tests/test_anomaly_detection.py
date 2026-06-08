"""Tests for detection/anomaly_detection.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.anomaly_detection import AnomalyDetector, _stats, _zscore, _confidence_from_zscore


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


# ---------------------------------------------------------------------------
# Statistical helper unit tests
# ---------------------------------------------------------------------------

class TestStatHelpers:
    def test_stats_returns_mean_and_std(self):
        mean, std = _stats([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
        assert abs(mean - 5.0) < 0.001
        assert abs(std - 2.0) < 0.001

    def test_stats_single_value_returns_zeros(self):
        mean, std = _stats([5.0])
        assert mean == 0.0
        assert std == 0.0

    def test_stats_empty_returns_zeros(self):
        mean, std = _stats([])
        assert mean == 0.0
        assert std == 0.0

    def test_zscore_above_mean(self):
        z = _zscore(10.0, mean=5.0, std=2.5)
        assert z == 2.0

    def test_zscore_zero_std_returns_zero(self):
        assert _zscore(99.0, mean=5.0, std=0.0) == 0.0

    def test_confidence_scales_with_zscore(self):
        assert _confidence_from_zscore(2.0) == 0.60
        assert _confidence_from_zscore(3.0) == 0.75
        assert _confidence_from_zscore(4.0) == 0.90
        assert _confidence_from_zscore(5.0) == 0.90


# ---------------------------------------------------------------------------
# Statistical volume anomaly
# ---------------------------------------------------------------------------

def _make_volume_batch():
    """
    One IP with 20 events, eight others with 1 each.
    With 9 IPs the outlier Z-score is ~2.8 — above the 2.0 threshold.
    (With only 3–4 noise IPs the max possible Z-score is ~1.7, below threshold.)
    """
    outlier = [
        _ev(src="1.2.3.4", dst="10.0.0.1", ts="2026-06-08T10:00:00Z")
        for _ in range(20)
    ]
    noise = [
        _ev(src=f"10.0.0.{i}", dst="10.0.0.99", ts="2026-06-08T10:01:00Z")
        for i in range(1, 9)
    ]
    return outlier + noise


class TestStatisticalVolumeAnomaly:
    def test_high_volume_ip_flagged(self):
        events = _make_volume_batch()
        alerts = AnomalyDetector().detect(events)
        types  = {a["alert_type"] for a in alerts}
        assert "statistical_volume_anomaly" in types

    def test_flagged_ip_is_correct(self):
        events = _make_volume_batch()
        alerts = AnomalyDetector().detect(events)
        vol    = [a for a in alerts if a["alert_type"] == "statistical_volume_anomaly"]
        assert vol[0]["src_ip"] == "1.2.3.4"

    def test_alert_has_details_block(self):
        events = _make_volume_batch()
        alerts = AnomalyDetector().detect(events)
        vol    = [a for a in alerts if a["alert_type"] == "statistical_volume_anomaly"]
        assert "details" in vol[0]
        d = vol[0]["details"]
        assert "zscore"      in d
        assert "event_count" in d
        assert "batch_mean"  in d
        assert "batch_std"   in d

    def test_zscore_above_threshold(self):
        events = _make_volume_batch()
        alerts = AnomalyDetector().detect(events)
        vol    = [a for a in alerts if a["alert_type"] == "statistical_volume_anomaly"]
        assert vol[0]["details"]["zscore"] >= 2.0

    def test_normal_volume_not_flagged(self):
        events = [
            _ev(src="1.1.1.1", ts="2026-06-08T10:00:00Z"),
            _ev(src="2.2.2.2", ts="2026-06-08T10:01:00Z"),
            _ev(src="3.3.3.3", ts="2026-06-08T10:02:00Z"),
            _ev(src="4.4.4.4", ts="2026-06-08T10:03:00Z"),
        ]
        alerts = AnomalyDetector().detect(events)
        types  = {a["alert_type"] for a in alerts}
        assert "statistical_volume_anomaly" not in types

    def test_skipped_when_fewer_than_3_distinct_ips(self):
        events = [
            _ev(src="1.1.1.1", ts="2026-06-08T10:00:00Z"),
            _ev(src="1.1.1.1", ts="2026-06-08T10:01:00Z"),
        ]
        alerts = AnomalyDetector().detect(events)
        types  = {a["alert_type"] for a in alerts}
        assert "statistical_volume_anomaly" not in types


# ---------------------------------------------------------------------------
# Statistical port scan anomaly
# ---------------------------------------------------------------------------

def _ev_with_port(src, port, ts="2026-06-08T10:00:00Z"):
    return {
        "src_ip":    src,
        "dst_ip":    "10.0.0.1",
        "event_type": "port_scan",
        "severity":  3,
        "timestamp": ts,
        "metadata":  {"port": port, "enrichment": {}},
    }


def _make_port_batch():
    """
    One scanner hitting 15 unique ports, eight others hitting 1 each.
    With 9 IPs the scanner Z-score is ~2.8 — above the 2.0 threshold.
    """
    scanner = [_ev_with_port("1.2.3.4", port=p) for p in range(1, 16)]
    noise   = [
        _ev_with_port(f"10.0.0.{i}", port=80)
        for i in range(1, 9)
    ]
    return scanner + noise


class TestStatisticalPortScanAnomaly:
    def test_port_scanner_flagged(self):
        events = _make_port_batch()
        alerts = AnomalyDetector().detect(events)
        types  = {a["alert_type"] for a in alerts}
        assert "statistical_port_scan_anomaly" in types

    def test_flagged_ip_is_scanner(self):
        events = _make_port_batch()
        alerts = AnomalyDetector().detect(events)
        port   = [a for a in alerts if a["alert_type"] == "statistical_port_scan_anomaly"]
        assert port[0]["src_ip"] == "1.2.3.4"

    def test_alert_has_details_block(self):
        events = _make_port_batch()
        alerts = AnomalyDetector().detect(events)
        port   = [a for a in alerts if a["alert_type"] == "statistical_port_scan_anomaly"]
        d = port[0]["details"]
        assert "zscore"       in d
        assert "unique_ports" in d
        assert "ports_sampled" in d

    def test_below_min_port_signal_not_flagged(self):
        events = [
            _ev_with_port("1.2.3.4", port=80),
            _ev_with_port("1.2.3.4", port=443),   # only 2 unique ports — below threshold
            _ev_with_port("5.5.5.5", port=22),
            _ev_with_port("6.6.6.6", port=3306),
            _ev_with_port("7.7.7.7", port=8080),
        ]
        alerts = AnomalyDetector().detect(events)
        types  = {a["alert_type"] for a in alerts}
        assert "statistical_port_scan_anomaly" not in types

    def test_deduplication_port_scan_fires_once_per_ip(self):
        events = _make_port_batch() + _make_port_batch()
        alerts = AnomalyDetector().detect(events)
        port   = [a for a in alerts if a["alert_type"] == "statistical_port_scan_anomaly"]
        scanner_alerts = [a for a in port if a["src_ip"] == "1.2.3.4"]
        assert len(scanner_alerts) == 1
