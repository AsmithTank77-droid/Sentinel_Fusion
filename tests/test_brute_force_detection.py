"""Tests for detection/brute_force_detection.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.brute_force_detection import BruteForceDetector


def _fail(src="185.220.101.45", dst="10.0.0.5", ts="2026-05-09T02:15:00Z"):
    return {
        "src_ip": src, "dst_ip": dst,
        "event_type": "authentication_failure",
        "severity": 5, "timestamp": ts,
        "metadata": {},
    }


def _success(src="185.220.101.45", dst="10.0.0.5", ts="2026-05-09T02:20:00Z"):
    return {
        "src_ip": src, "dst_ip": dst,
        "event_type": "authentication_success",
        "severity": 2, "timestamp": ts,
        "metadata": {},
    }


class TestBruteForceDetector:
    def setup_method(self):
        self.detector = BruteForceDetector()

    def test_empty_returns_empty(self):
        assert self.detector.detect([]) == []

    def test_below_threshold_no_alert(self):
        events = [
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
        ]
        assert self.detector.detect(events) == []

    def test_threshold_met_fires_alert(self):
        events = [
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
            _fail(ts="2026-05-09T02:17:00Z"),
        ]
        result = self.detector.detect(events)
        assert len(result) == 1
        assert result[0]["alert_type"] == "brute_force_detected"
        assert result[0]["failure_count"] == 3
        assert result[0]["src_ip"] == "185.220.101.45"
        assert result[0]["dst_ip"] == "10.0.0.5"

    def test_five_failures_fires_once_per_pair(self):
        events = [
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
            _fail(ts="2026-05-09T02:16:30Z"),
            _fail(ts="2026-05-09T02:17:00Z"),
            _fail(ts="2026-05-09T02:17:45Z"),
        ]
        result = self.detector.detect(events)
        assert len(result) == 1

    def test_outside_window_no_alert(self):
        events = [
            _fail(ts="2026-05-09T02:00:00Z"),
            _fail(ts="2026-05-09T02:05:00Z"),
            _fail(ts="2026-05-09T02:10:00Z"),
        ]
        # 10 minutes apart — outside 5-min window
        assert self.detector.detect(events) == []

    def test_non_failure_events_ignored(self):
        events = [
            _success(),
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
        ]
        assert self.detector.detect(events) == []

    def test_different_src_dst_pairs_independent(self):
        events = [
            _fail(src="1.1.1.1", dst="10.0.0.5", ts="2026-05-09T02:15:00Z"),
            _fail(src="1.1.1.1", dst="10.0.0.5", ts="2026-05-09T02:16:00Z"),
            _fail(src="1.1.1.1", dst="10.0.0.5", ts="2026-05-09T02:17:00Z"),
            _fail(src="2.2.2.2", dst="10.0.0.5", ts="2026-05-09T02:15:00Z"),
            _fail(src="2.2.2.2", dst="10.0.0.5", ts="2026-05-09T02:16:00Z"),
            _fail(src="2.2.2.2", dst="10.0.0.5", ts="2026-05-09T02:17:00Z"),
        ]
        result = self.detector.detect(events)
        assert len(result) == 2
        srcs = {r["src_ip"] for r in result}
        assert srcs == {"1.1.1.1", "2.2.2.2"}

    def test_alert_has_mitre_fields(self):
        events = [
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
            _fail(ts="2026-05-09T02:17:00Z"),
        ]
        result = self.detector.detect(events)
        assert result[0]["mitre_tactic"] == "TA0006 - Credential Access"
        assert result[0]["mitre_technique"] == "T1110 - Brute Force"

    def test_confidence_between_0_and_1(self):
        events = [
            _fail(ts="2026-05-09T02:15:00Z"),
            _fail(ts="2026-05-09T02:16:00Z"),
            _fail(ts="2026-05-09T02:17:00Z"),
        ]
        result = self.detector.detect(events)
        assert 0.0 <= result[0]["confidence"] <= 1.0
