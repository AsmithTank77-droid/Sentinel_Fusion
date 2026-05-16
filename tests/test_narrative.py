"""Tests for narrative/attack_story_engine.py and narrative/timeline_builder.py."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from narrative.attack_story_engine import AttackStoryEngine
from narrative.timeline_builder import TimelineBuilder


def _ev(src="185.220.101.45", dst="10.0.0.5", etype="port_scan",
        severity=5, ts="2026-05-09T02:14:00Z"):
    return {"src_ip": src, "dst_ip": dst, "event_type": etype,
            "severity": severity, "timestamp": ts, "metadata": {}}


def _alert(atype="brute_force_detected", src="185.220.101.45", dst="10.0.0.5",
           conf=0.8, severity=7, tactic="TA0006 - Credential Access"):
    return {"alert_type": atype, "src_ip": src, "dst_ip": dst,
            "confidence": conf, "severity": severity, "mitre_tactic": tactic}


# ---------------------------------------------------------------------------
# AttackStoryEngine
# ---------------------------------------------------------------------------

class TestAttackStoryEngine:
    def setup_method(self):
        self.engine = AttackStoryEngine()

    def test_empty_returns_fallback_string(self):
        result = self.engine.narrate([], [])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_string(self):
        result = self.engine.narrate([_ev()], [_alert()])
        assert isinstance(result, str)

    def test_contains_timestamps(self):
        events = [_ev(ts="2026-05-09T02:14:00Z"), _ev(ts="2026-05-09T02:22:00Z")]
        result = self.engine.narrate(events, [])
        assert "2026-05-09T02:14:00Z" in result

    def test_contains_src_ip(self):
        result = self.engine.narrate([_ev()], [])
        assert "185.220.101.45" in result

    def test_phase_recon_present_for_port_scan(self):
        result = self.engine.narrate([_ev(etype="port_scan")], [])
        assert "Reconnaissance" in result

    def test_recommendations_generated_for_brute_force(self):
        result = self.engine.narrate([], [_alert(atype="brute_force_detected")])
        assert "brute force" in result.lower() or "lockout" in result.lower()

    def test_lateral_movement_recommendations(self):
        alert = _alert(atype="lateral_movement_detected", tactic="TA0008 - Lateral Movement")
        result = self.engine.narrate([], [alert])
        assert "Isolate" in result or "lateral" in result.lower()

    def test_mitre_tactics_section(self):
        result = self.engine.narrate([], [_alert()])
        assert "TA0006" in result or "Credential" in result


# ---------------------------------------------------------------------------
# TimelineBuilder
# ---------------------------------------------------------------------------

class TestTimelineBuilder:
    def setup_method(self):
        self.builder = TimelineBuilder()
        self.scores = {
            "host_risk": {"10.0.0.5": {"risk_score": 8.0, "risk_label": "critical"}},
            "asset_risk": {"10.0.0.5": {"exposure_score": 6.0, "exposure_label": "high"}},
            "attack_surface": {"expansion_score": 6.5},
        }

    def test_empty_inputs_returns_narrative_only(self):
        result = self.builder.build([], [], {})
        assert len(result) == 1
        assert result[0]["entry_type"] == "narrative"

    def test_events_become_entries(self):
        result = self.builder.build([_ev()], [], self.scores)
        event_entries = [e for e in result if e["entry_type"] == "event"]
        assert len(event_entries) == 1
        assert event_entries[0]["event_type"] == "port_scan"

    def test_alerts_become_entries(self):
        result = self.builder.build([], [_alert()], self.scores)
        alert_entries = [e for e in result if e["entry_type"] == "alert"]
        assert len(alert_entries) == 1
        assert alert_entries[0]["event_type"] == "brute_force_detected"

    def test_narrative_entry_appended_last(self):
        result = self.builder.build([_ev()], [_alert()], self.scores)
        assert result[-1]["entry_type"] == "narrative"
        assert isinstance(result[-1]["story"], str)
        assert len(result[-1]["story"]) > 0

    def test_chronological_order(self):
        events = [
            _ev(ts="2026-05-09T02:20:00Z", etype="authentication_success"),
            _ev(ts="2026-05-09T02:14:00Z", etype="port_scan"),
        ]
        result = self.builder.build(events, [], self.scores)
        visible = [e for e in result if e["entry_type"] != "narrative"]
        assert visible[0]["timestamp"] < visible[1]["timestamp"]

    def test_risk_context_attached(self):
        result = self.builder.build([_ev()], [], self.scores)
        event_entry = next(e for e in result if e["entry_type"] == "event")
        assert "risk_context" in event_entry
        assert event_entry["risk_context"]["host_risk_score"] == 8.0

    def test_all_event_entries_have_required_keys(self):
        result = self.builder.build([_ev()], [], self.scores)
        required = {"timestamp", "entry_type", "event_type", "src_ip",
                    "dst_ip", "severity", "confidence", "description",
                    "mitre_tactic", "risk_context"}
        for entry in result:
            if entry["entry_type"] == "event":
                assert required.issubset(set(entry.keys()))
