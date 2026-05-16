"""Tests for reporting/report_generator.py — Stage 8."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.report_generator import ReportGenerator


def _timeline_entry(ts="2026-05-09T02:14:00Z", etype="port_scan",
                    src="185.220.101.45", dst="10.0.0.5", severity=8):
    return {"timestamp": ts, "entry_type": "event", "event_type": etype,
            "src_ip": src, "dst_ip": dst, "severity": severity,
            "confidence": None, "description": "test", "mitre_tactic": None,
            "risk_context": {}}


def _alert(atype="brute_force_detected", src="185.220.101.45", dst="10.0.0.5", conf=0.8):
    return {"alert_type": atype, "src_ip": src, "dst_ip": dst,
            "confidence": conf, "severity": 7,
            "mitre_tactic": "TA0006 - Credential Access"}


_SCORES = {
    "host_risk": {
        "10.0.0.5": {"risk_score": 9.5, "risk_label": "critical",
                     "event_count": 7, "max_event_severity": 8,
                     "alert_count": 3, "alert_types": ["brute_force_detected"],
                     "factors": ["avg severity 6.5"]},
    },
    "asset_risk": {
        "10.0.0.5": {"exposure_score": 7.0, "exposure_label": "high",
                     "high_risk_event_count": 2, "event_types_observed": ["authentication_success"],
                     "alert_count": 1, "is_lateral_target": False, "factors": []},
    },
    "attack_surface": {
        "expansion_score": 6.5, "expansion_label": "significant",
        "unique_external_sources": 1, "unique_internal_targets": 2,
        "unique_attack_techniques": 4, "lateral_movement_hops": 1,
        "alert_type_breakdown": {"brute_force_detected": 1},
        "mitre_tactics_observed": ["TA0006 - Credential Access"],
        "factors": ["1 external source"],
    },
}


class TestReportGenerator:
    def setup_method(self):
        self.gen = ReportGenerator()

    def test_returns_dict_with_json_and_markdown(self):
        result = self.gen.generate(
            timeline=[_timeline_entry()],
            scores=_SCORES,
            alerts=[_alert()],
        )
        assert isinstance(result, dict)
        assert "json" in result
        assert "markdown" in result

    def test_json_report_has_required_keys(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        jr = result["json"]
        required = {"report_type", "generated_at", "summary",
                    "timeline", "alerts", "scores", "narrative"}
        assert required.issubset(set(jr.keys()))

    def test_json_summary_has_event_and_alert_counts(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        s = result["json"]["summary"]
        assert s["total_events"] == 1
        assert s["total_alerts"] == 1

    def test_markdown_is_string(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        assert isinstance(result["markdown"], str)

    def test_markdown_contains_soc_report_header(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        assert "Sentinel_Fusion SOC Report" in result["markdown"]

    def test_markdown_contains_host_ip(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        assert "10.0.0.5" in result["markdown"]

    def test_markdown_contains_alert_type(self):
        result = self.gen.generate([_timeline_entry()], _SCORES, [_alert()])
        assert "Brute Force Detected" in result["markdown"]

    def test_empty_inputs_still_returns_report(self):
        result = self.gen.generate([], {}, [])
        assert "json" in result
        assert "markdown" in result

    def test_narrative_entry_excluded_from_visible_timeline(self):
        narrative = {"timestamp": "__narrative__", "entry_type": "narrative",
                     "story": "test story"}
        timeline = [_timeline_entry(), narrative]
        result = self.gen.generate(timeline, _SCORES, [])
        # JSON timeline should not include the narrative entry
        for entry in result["json"]["timeline"]:
            assert entry.get("entry_type") != "narrative"

    def test_json_narrative_field_populated_from_story(self):
        narrative = {"timestamp": "__narrative__", "entry_type": "narrative",
                     "story": "The attacker did bad things."}
        result = self.gen.generate([narrative], {}, [])
        assert result["json"]["narrative"] == "The attacker did bad things."
