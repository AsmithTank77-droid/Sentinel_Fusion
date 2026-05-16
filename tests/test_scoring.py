"""Tests for scoring/host_risk.py, asset_risk.py, attack_surface.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scoring.host_risk import HostRisk
from scoring.asset_risk import AssetRisk
from scoring.attack_surface import AttackSurface


def _ev(src="185.220.101.45", dst="10.0.0.5", etype="port_scan",
        severity=8, enrichment=None):
    return {
        "src_ip": src, "dst_ip": dst, "event_type": etype,
        "severity": severity, "timestamp": "2026-05-09T02:14:00Z",
        "metadata": {"enrichment": enrichment or {}},
    }


def _alert(atype="brute_force_detected", src="185.220.101.45", dst="10.0.0.5",
           conf=0.8, severity=7):
    return {
        "alert_type": atype, "src_ip": src, "dst_ip": dst,
        "confidence": conf, "severity": severity,
        "mitre_tactic": "TA0006 - Credential Access",
    }


# ---------------------------------------------------------------------------
# HostRisk
# ---------------------------------------------------------------------------

class TestHostRisk:
    def setup_method(self):
        self.scorer = HostRisk()

    def test_empty_returns_empty(self):
        assert self.scorer.score([], []) == {}

    def test_basic_host_scored(self):
        result = self.scorer.score([_ev()], [])
        assert "10.0.0.5" in result
        data = result["10.0.0.5"]
        assert "risk_score" in data
        assert "risk_label" in data
        assert data["event_count"] == 1

    def test_malicious_src_adds_bonus(self):
        clean_ev   = _ev(enrichment={})
        malicious  = _ev(enrichment={"src_reputation": {"is_malicious": True,
                                                         "reputation_score": 0.97}})
        clean_result    = self.scorer.score([clean_ev], [])
        malicious_result = self.scorer.score([malicious], [])
        assert malicious_result["10.0.0.5"]["risk_score"] > \
               clean_result["10.0.0.5"]["risk_score"]

    def test_alert_increases_score(self):
        no_alert = self.scorer.score([_ev()], [])
        with_alert = self.scorer.score([_ev()], [_alert()])
        assert with_alert["10.0.0.5"]["risk_score"] >= \
               no_alert["10.0.0.5"]["risk_score"]

    def test_critical_label_for_max_score(self):
        events = [_ev(severity=10) for _ in range(5)]
        alerts = [_alert() for _ in range(5)]
        result = self.scorer.score(events, alerts)
        assert result["10.0.0.5"]["risk_label"] == "critical"

    def test_score_capped_at_10(self):
        events = [_ev(severity=10) for _ in range(20)]
        alerts = [_alert() for _ in range(20)]
        result = self.scorer.score(events, alerts)
        assert result["10.0.0.5"]["risk_score"] <= 10.0

    def test_score_non_negative(self):
        result = self.scorer.score([_ev(severity=0)], [])
        assert result["10.0.0.5"]["risk_score"] >= 0.0


# ---------------------------------------------------------------------------
# AssetRisk
# ---------------------------------------------------------------------------

class TestAssetRisk:
    def setup_method(self):
        self.scorer = AssetRisk()

    def test_empty_returns_empty(self):
        assert self.scorer.score([], []) == {}

    def test_auth_success_is_high_exposure(self):
        ev = _ev(etype="authentication_success")
        result = self.scorer.score([ev], [])
        assert "10.0.0.5" in result
        assert result["10.0.0.5"]["high_risk_event_count"] >= 1

    def test_lateral_target_flagged(self):
        lat_alert = {
            "alert_type": "lateral_movement_detected",
            "initial_src_ip": "185.220.101.45",
            "pivot_host": "10.0.0.5",
            "lateral_target": "10.0.0.10",
            "confidence": 0.75, "severity": 8,
        }
        result = self.scorer.score([], [lat_alert])
        assert result.get("10.0.0.10", {}).get("is_lateral_target") is True

    def test_exposure_score_bounded(self):
        events = [_ev(etype="authentication_success") for _ in range(20)]
        result = self.scorer.score(events, [])
        assert result["10.0.0.5"]["exposure_score"] <= 10.0

    def test_exposure_label_present(self):
        ev = _ev(etype="authentication_success")
        result = self.scorer.score([ev], [])
        assert result["10.0.0.5"]["exposure_label"] in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# AttackSurface
# ---------------------------------------------------------------------------

class TestAttackSurface:
    def setup_method(self):
        self.scorer = AttackSurface()

    def test_empty_returns_dict_with_zero_score(self):
        result = self.scorer.score([], [])
        assert result["expansion_score"] == 0.0
        assert result["unique_external_sources"] == 0
        assert result["unique_internal_targets"] == 0

    def test_external_source_counted(self):
        result = self.scorer.score([_ev(src="185.220.101.45", dst="10.0.0.5")], [])
        assert result["unique_external_sources"] == 1

    def test_internal_source_not_counted_as_external(self):
        result = self.scorer.score([_ev(src="10.0.0.5", dst="10.0.0.10")], [])
        assert result["unique_external_sources"] == 0
        assert result["unique_internal_targets"] == 1

    def test_lateral_hop_counted(self):
        lat_alert = {
            "alert_type": "lateral_movement_detected",
            "lateral_target": "10.0.0.10",
            "pivot_host": "10.0.0.5",
            "confidence": 0.75,
            "mitre_tactic": "TA0008 - Lateral Movement",
        }
        result = self.scorer.score([], [lat_alert])
        assert result["lateral_movement_hops"] == 1

    def test_expansion_score_bounded(self):
        events = [_ev() for _ in range(100)]
        alerts = [_alert() for _ in range(100)]
        result = self.scorer.score(events, alerts)
        assert result["expansion_score"] <= 10.0

    def test_expansion_label_present(self):
        result = self.scorer.score([_ev()], [])
        assert result["expansion_label"] in ("contained", "moderate", "significant", "critical")

    def test_mitre_tactics_collected(self):
        alerts = [
            _alert(atype="brute_force_detected"),
            {"alert_type": "lateral_movement_detected",
             "mitre_tactic": "TA0008 - Lateral Movement",
             "confidence": 0.75},
        ]
        result = self.scorer.score([], alerts)
        assert any("Lateral" in t for t in result["mitre_tactics_observed"])

    def test_alert_type_breakdown_populated(self):
        alerts = [_alert(), _alert(), _alert(atype="lateral_movement_detected")]
        result = self.scorer.score([], alerts)
        assert result["alert_type_breakdown"]["brute_force_detected"] == 2
