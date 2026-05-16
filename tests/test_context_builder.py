"""Tests for core/pipeline/context_builder.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline.context_builder import ContextBuilder


def _ev(src="", dst="", etype="port_scan", severity=5, ts="2026-05-09T02:00:00Z"):
    return {"src_ip": src, "dst_ip": dst, "event_type": etype,
            "severity": severity, "timestamp": ts}


class TestContextBuilder:
    def setup_method(self):
        self.cb = ContextBuilder()

    def test_empty_input_returns_empty(self):
        assert self.cb.build([]) == []

    def test_single_event_no_peers(self):
        result = self.cb.build([_ev(src="1.2.3.4")])
        assert len(result) == 1
        assert result[0]["same_src_event_count"] == 0
        assert result[0]["batch_size"] == 1

    def test_two_events_same_src_see_each_other(self):
        events = [
            _ev(src="1.2.3.4", dst="10.0.0.5", etype="port_scan"),
            _ev(src="1.2.3.4", dst="10.0.0.5", etype="authentication_failure"),
        ]
        result = self.cb.build(events)
        assert result[0]["same_src_event_count"] == 1
        assert result[1]["same_src_event_count"] == 1
        assert "authentication_failure" in result[0]["same_src_event_types"]
        assert "port_scan" in result[1]["same_src_event_types"]

    def test_different_srcs_isolated(self):
        events = [
            _ev(src="1.1.1.1", dst="10.0.0.5"),
            _ev(src="2.2.2.2", dst="10.0.0.5"),
        ]
        result = self.cb.build(events)
        assert result[0]["same_src_event_count"] == 0
        assert result[1]["same_src_event_count"] == 0

    def test_output_length_matches_input(self):
        events = [_ev(src="1.2.3.4") for _ in range(5)]
        result = self.cb.build(events)
        assert len(result) == 5

    def test_severity_max_computed(self):
        events = [
            _ev(src="1.2.3.4", severity=3),
            _ev(src="1.2.3.4", severity=8),
            _ev(src="1.2.3.4", severity=5),
        ]
        result = self.cb.build(events)
        # Peer max for first event = max of the other two
        assert result[0]["same_src_severity_max"] == 8

    def test_event_with_no_src_ip_gets_empty_context(self):
        events = [_ev(src=""), _ev(src="1.2.3.4")]
        result = self.cb.build(events)
        assert result[0]["same_src_event_count"] == 0

    def test_dst_ips_collected(self):
        events = [
            _ev(src="1.2.3.4", dst="10.0.0.5"),
            _ev(src="1.2.3.4", dst="10.0.0.10"),
        ]
        result = self.cb.build(events)
        assert "10.0.0.10" in result[0]["same_src_dst_ips"]
        assert "10.0.0.5" in result[1]["same_src_dst_ips"]
