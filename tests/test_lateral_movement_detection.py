"""Tests for detection/lateral_movement_detection.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.lateral_movement_detection import LateralMovementDetector


def _ev(src, dst, etype, ts="2026-05-09T02:20:00Z", severity=5):
    return {
        "src_ip": src, "dst_ip": dst, "event_type": etype,
        "severity": severity, "timestamp": ts, "metadata": {},
    }


class TestLateralMovementDetector:
    def setup_method(self):
        self.detector = LateralMovementDetector()

    def test_empty_returns_empty(self):
        assert self.detector.detect([]) == []

    def test_no_auth_success_no_alert(self):
        events = [
            _ev("185.220.101.45", "10.0.0.5", "authentication_failure"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement"),
        ]
        assert self.detector.detect(events) == []

    def test_external_login_then_pivot_fires(self):
        events = [
            _ev("185.220.101.45", "10.0.0.5",  "authentication_success", ts="2026-05-09T02:20:00Z"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement",       ts="2026-05-09T02:22:00Z"),
        ]
        result = self.detector.detect(events)
        assert len(result) == 1
        alert = result[0]
        assert alert["alert_type"] == "lateral_movement_detected"
        assert alert["initial_src_ip"] == "185.220.101.45"
        assert alert["pivot_host"] == "10.0.0.5"
        assert alert["lateral_target"] == "10.0.0.10"

    def test_internal_to_internal_without_prior_compromise_no_alert(self):
        events = [
            _ev("10.0.0.5", "10.0.0.10", "lateral_movement"),
        ]
        assert self.detector.detect(events) == []

    def test_external_login_to_external_not_lateral(self):
        events = [
            _ev("185.220.101.45", "8.8.8.8", "authentication_success"),
            _ev("8.8.8.8",        "1.1.1.1", "lateral_movement"),
        ]
        # dst of login is external, so not flagged as compromised internal
        assert self.detector.detect(events) == []

    def test_deduplication_same_pivot_target(self):
        events = [
            _ev("185.220.101.45", "10.0.0.5",  "authentication_success"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement", ts="2026-05-09T02:22:00Z"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement", ts="2026-05-09T02:23:00Z"),
        ]
        result = self.detector.detect(events)
        assert len(result) == 1

    def test_confidence_between_0_and_1(self):
        events = [
            _ev("185.220.101.45", "10.0.0.5",  "authentication_success"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement"),
        ]
        result = self.detector.detect(events)
        assert 0.0 <= result[0]["confidence"] <= 1.0

    def test_mitre_fields(self):
        events = [
            _ev("185.220.101.45", "10.0.0.5",  "authentication_success"),
            _ev("10.0.0.5",       "10.0.0.10", "lateral_movement"),
        ]
        result = self.detector.detect(events)
        assert result[0]["mitre_tactic"] == "TA0008 - Lateral Movement"
        assert result[0]["mitre_technique"] == "T1021 - Remote Services"
