"""Tests for detection/correlation_engine.py — Stage 4: Correlation."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.correlation_engine import CorrelationEngine


def _ev(src="185.220.101.45", dst="10.0.0.5", etype="port_scan",
        severity=5, ts="2026-05-09T02:14:00Z", meta=None):
    return {
        "src_ip": src, "dst_ip": dst, "event_type": etype,
        "severity": severity, "timestamp": ts,
        "metadata": meta or {},
    }


class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_empty_returns_empty(self):
        assert self.engine.correlate([]) == []

    def test_single_event_no_chain(self):
        result = self.engine.correlate([_ev()])
        assert result == []

    def test_two_events_same_src_creates_chain(self):
        events = [
            _ev(etype="port_scan",              ts="2026-05-09T02:14:00Z"),
            _ev(etype="authentication_failure", ts="2026-05-09T02:15:00Z"),
        ]
        result = self.engine.correlate(events)
        assert len(result) == 1
        chain = result[0]
        assert chain["alert_type"] == "correlated_attack_chain"
        assert chain["src_ip"] == "185.220.101.45"
        assert chain["event_count"] == 2
        assert "port_scan" in chain["event_types"]
        assert "authentication_failure" in chain["event_types"]

    def test_different_srcs_produce_separate_chains(self):
        events = [
            _ev(src="1.1.1.1", etype="port_scan",              ts="2026-05-09T02:14:00Z"),
            _ev(src="1.1.1.1", etype="authentication_failure", ts="2026-05-09T02:15:00Z"),
            _ev(src="2.2.2.2", etype="port_scan",              ts="2026-05-09T02:14:00Z"),
            _ev(src="2.2.2.2", etype="authentication_failure", ts="2026-05-09T02:15:00Z"),
        ]
        result = self.engine.correlate(events)
        assert len(result) == 2
        srcs = {c["src_ip"] for c in result}
        assert srcs == {"1.1.1.1", "2.2.2.2"}

    def test_chain_confidence_is_float_between_0_and_1(self):
        events = [
            _ev(etype="port_scan",              ts="2026-05-09T02:14:00Z"),
            _ev(etype="authentication_failure", ts="2026-05-09T02:15:00Z"),
            _ev(etype="authentication_success", ts="2026-05-09T02:20:00Z"),
        ]
        result = self.engine.correlate(events)
        conf = result[0]["confidence"]
        assert 0.0 <= conf <= 1.0

    def test_mitre_tactics_populated(self):
        events = [
            _ev(etype="port_scan",              ts="2026-05-09T02:14:00Z"),
            _ev(etype="authentication_failure", ts="2026-05-09T02:15:00Z"),
        ]
        result = self.engine.correlate(events)
        assert any("Reconnaissance" in t for t in result[0]["mitre_tactics"])

    def test_no_src_ip_events_not_chained(self):
        events = [
            {"src_ip": "", "dst_ip": "10.0.0.5", "event_type": "port_scan",
             "severity": 5, "timestamp": "2026-05-09T02:14:00Z", "metadata": {}},
            {"src_ip": "", "dst_ip": "10.0.0.5", "event_type": "authentication_failure",
             "severity": 5, "timestamp": "2026-05-09T02:15:00Z", "metadata": {}},
        ]
        result = self.engine.correlate(events)
        assert result == []

    def test_max_severity_captured(self):
        events = [
            _ev(etype="port_scan",              severity=8, ts="2026-05-09T02:14:00Z"),
            _ev(etype="authentication_failure", severity=5, ts="2026-05-09T02:15:00Z"),
        ]
        result = self.engine.correlate(events)
        assert result[0]["max_severity"] == 8

    def test_enrichment_summary_from_metadata(self):
        meta = {"enrichment": {
            "src_reputation": {"is_malicious": True, "reputation_score": 0.97,
                               "categories": ["tor_exit"]},
            "src_geo": {"country": "Russia", "is_tor": True, "high_risk_country": True},
            "src_threats": {"feed_hits": ["tor-exit-nodes"]},
        }}
        events = [
            _ev(etype="port_scan",              ts="2026-05-09T02:14:00Z", meta=meta),
            _ev(etype="authentication_failure", ts="2026-05-09T02:15:00Z", meta=meta),
        ]
        result = self.engine.correlate(events)
        summary = result[0]["enrichment_summary"]
        assert summary["src_reputation"]["is_malicious"] is True
        assert summary["src_geo"]["is_tor"] is True
        assert "tor-exit-nodes" in summary["src_threat_feeds"]


class TestPivotChainDetection:
    """Tests for _detect_pivots — multi-hop lateral movement correlation."""

    def setup_method(self):
        self.engine = CorrelationEngine()

    def _pivot_events(self):
        """Two-hop scenario: attacker → victim_A → victim_B."""
        return [
            # Chain A: external attacker targets 10.0.0.10
            _ev(src="185.0.0.1", dst="10.0.0.10", etype="port_scan",              ts="2026-05-09T02:00:00Z"),
            _ev(src="185.0.0.1", dst="10.0.0.10", etype="authentication_failure", ts="2026-05-09T02:01:00Z"),
            _ev(src="185.0.0.1", dst="10.0.0.10", etype="authentication_success", ts="2026-05-09T02:02:00Z"),
            # Chain B: compromised host pivots to 10.0.0.11
            _ev(src="10.0.0.10", dst="10.0.0.11", etype="authentication_failure", ts="2026-05-09T02:05:00Z"),
            _ev(src="10.0.0.10", dst="10.0.0.11", etype="lateral_movement",       ts="2026-05-09T02:06:00Z"),
        ]

    def test_pivot_chain_detected(self):
        result = self.engine.correlate(self._pivot_events())
        pivots = [r for r in result if r["alert_type"] == "correlated_pivot_chain"]
        assert len(pivots) == 1

    def test_pivot_chain_fields(self):
        result = self.engine.correlate(self._pivot_events())
        pivot = next(r for r in result if r["alert_type"] == "correlated_pivot_chain")
        assert pivot["initial_src_ip"] == "185.0.0.1"
        assert pivot["pivot_host"]     == "10.0.0.10"
        assert "10.0.0.11" in pivot["final_targets"]
        assert pivot["hop_count"] == 1
        assert pivot["src_ip"]    == "185.0.0.1"
        assert pivot["dst_ip"]    == "10.0.0.10"

    def test_pivot_confidence_is_elevated(self):
        result = self.engine.correlate(self._pivot_events())
        pivot = next(r for r in result if r["alert_type"] == "correlated_pivot_chain")
        # Pivot bonus pushes confidence above either individual chain
        chains = [r for r in result if r["alert_type"] == "correlated_attack_chain"]
        chain_confs = [c["confidence"] for c in chains]
        assert pivot["confidence"] >= min(chain_confs)
        assert 0.0 < pivot["confidence"] <= 1.0

    def test_pivot_includes_lateral_movement_tactic(self):
        result = self.engine.correlate(self._pivot_events())
        pivot = next(r for r in result if r["alert_type"] == "correlated_pivot_chain")
        assert any("Lateral Movement" in t for t in pivot["mitre_tactics"])

    def test_no_pivot_when_temporal_order_reversed(self):
        """chain_B starting before chain_A means no confirmed pivot."""
        events = [
            # Chain B happens first
            _ev(src="10.0.0.10", dst="10.0.0.11", etype="authentication_failure", ts="2026-05-09T02:00:00Z"),
            _ev(src="10.0.0.10", dst="10.0.0.11", etype="lateral_movement",       ts="2026-05-09T02:01:00Z"),
            # Chain A happens after — 10.0.0.10 is NOT a pivot in this order
            _ev(src="185.0.0.1", dst="10.0.0.10", etype="port_scan",              ts="2026-05-09T02:10:00Z"),
            _ev(src="185.0.0.1", dst="10.0.0.10", etype="authentication_success", ts="2026-05-09T02:11:00Z"),
        ]
        result = self.engine.correlate(events)
        pivots = [r for r in result if r["alert_type"] == "correlated_pivot_chain"]
        assert pivots == []

    def test_no_pivot_when_chains_unrelated(self):
        """Two chains with no dst/src overlap produce no pivot."""
        events = [
            _ev(src="1.1.1.1", dst="10.0.0.10", etype="port_scan",              ts="2026-05-09T02:00:00Z"),
            _ev(src="1.1.1.1", dst="10.0.0.10", etype="authentication_failure", ts="2026-05-09T02:01:00Z"),
            _ev(src="2.2.2.2", dst="10.0.0.20", etype="port_scan",              ts="2026-05-09T02:05:00Z"),
            _ev(src="2.2.2.2", dst="10.0.0.20", etype="authentication_failure", ts="2026-05-09T02:06:00Z"),
        ]
        result = self.engine.correlate(events)
        pivots = [r for r in result if r["alert_type"] == "correlated_pivot_chain"]
        assert pivots == []

    def test_original_chains_still_present(self):
        """Pivot detection must not remove the underlying single-source chains."""
        result = self.engine.correlate(self._pivot_events())
        chains = [r for r in result if r["alert_type"] == "correlated_attack_chain"]
        assert len(chains) == 2
        src_ips = {c["src_ip"] for c in chains}
        assert "185.0.0.1" in src_ips
        assert "10.0.0.10" in src_ips

    def test_pivot_dedup_single_pivot_per_pair(self):
        """Same attacker→pivot pair produces exactly one pivot alert."""
        events = self._pivot_events() + [
            # Extra event in chain B — should not produce a second pivot alert
            _ev(src="10.0.0.10", dst="10.0.0.12", etype="lateral_movement", ts="2026-05-09T02:07:00Z"),
        ]
        result = self.engine.correlate(events)
        pivots = [r for r in result if r["alert_type"] == "correlated_pivot_chain"]
        assert len(pivots) == 1
