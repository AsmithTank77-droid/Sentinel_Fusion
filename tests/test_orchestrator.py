"""Integration tests for core/pipeline/orchestrator.py — full pipeline."""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline.orchestrator import PipelineOrchestrator, PipelineStageError


_NRA = [{"scanner_ip": "185.220.101.45", "host": "10.0.0.5",
          "scan_time": "2026-05-09T02:14:00Z", "risk_level": "high"}]

_WINLOG_FAIL = {
    "EventID": 4625, "TimeCreated": "2026-05-09T02:15:00Z",
    "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5",
    "EventData": {"IpAddress": "185.220.101.45", "TargetIpAddress": "10.0.0.5"},
}

_WINLOG_SUCCESS = {
    "EventID": 4624, "TimeCreated": "2026-05-09T02:20:00Z",
    "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5",
    "EventData": {"IpAddress": "185.220.101.45", "TargetIpAddress": "10.0.0.5"},
}

_MOCK = [{"timestamp": "2026-05-09T02:22:00Z", "src_ip": "10.0.0.5",
          "dst_ip": "10.0.0.10", "event_type": "lateral_movement", "severity": "high"}]


class TestPipelineOrchestratorValidation:
    def setup_method(self):
        self.orch = PipelineOrchestrator()

    def test_inputs_must_be_dict(self):
        with pytest.raises(ValueError, match="inputs must be a dict"):
            self.orch.run([])

    def test_unknown_source_type_raises(self):
        with pytest.raises(ValueError, match="Unknown source type"):
            self.orch.run({"syslog": []})

    def test_source_value_must_be_list(self):
        with pytest.raises(ValueError, match="must be a list"):
            self.orch.run({"nra": "not-a-list"})

    def test_empty_inputs_runs_cleanly(self):
        result = self.orch.run({})
        assert result["event_count"] == 0
        assert result["alerts"] == []


class TestPipelineOrchestratorFullRun:
    def setup_method(self):
        self.orch = PipelineOrchestrator()

    def _run_demo(self):
        return self.orch.run({
            "nra":    _NRA,
            "winlog": [_WINLOG_FAIL, _WINLOG_FAIL, _WINLOG_FAIL, _WINLOG_SUCCESS],
            "mock":   _MOCK,
        })

    def test_run_returns_all_expected_keys(self):
        result = self._run_demo()
        expected = {"event_count", "normalized_events", "alerts",
                    "scores", "timeline", "report", "trace"}
        assert expected == set(result.keys())

    def test_event_count_correct(self):
        result = self._run_demo()
        # 1 NRA + 4 Winlog + 1 Mock = 6
        assert result["event_count"] == 6

    def test_normalized_events_are_dicts(self):
        result = self._run_demo()
        for ev in result["normalized_events"]:
            assert isinstance(ev, dict)
            assert "timestamp" in ev
            assert "src_ip" in ev

    def test_alerts_is_list(self):
        result = self._run_demo()
        assert isinstance(result["alerts"], list)

    def test_brute_force_alert_generated(self):
        result = self._run_demo()
        types = {a["alert_type"] for a in result["alerts"]}
        assert "brute_force_detected" in types

    def test_lateral_movement_alert_generated(self):
        result = self._run_demo()
        types = {a["alert_type"] for a in result["alerts"]}
        assert "lateral_movement_detected" in types

    def test_scores_has_three_keys(self):
        result = self._run_demo()
        assert set(result["scores"].keys()) == {"host_risk", "asset_risk", "attack_surface"}

    def test_timeline_is_list_with_entries(self):
        result = self._run_demo()
        assert isinstance(result["timeline"], list)
        assert len(result["timeline"]) > 0

    def test_report_has_json_and_markdown(self):
        result = self._run_demo()
        assert "json" in result["report"]
        assert "markdown" in result["report"]
        assert isinstance(result["report"]["markdown"], str)

    def test_trace_has_nine_stages(self):
        result = self._run_demo()
        assert len(result["trace"]) == 9

    def test_all_trace_stages_ok(self):
        result = self._run_demo()
        for step in result["trace"]:
            assert step["status"] == "ok", f"Stage {step['stage']} failed"

    def test_trace_stage_names(self):
        result = self._run_demo()
        names = [s["stage"] for s in result["trace"]]
        assert names == ["ingest", "normalize", "enrich", "sigma",
                         "correlate", "detect", "score", "timeline", "report"]

    def test_sigma_stage_in_trace(self):
        result = self._run_demo()
        sigma_trace = next((s for s in result["trace"] if s["stage"] == "sigma"), None)
        assert sigma_trace is not None
        assert sigma_trace["status"] == "ok"
        assert "count" in sigma_trace

    def test_sigma_alerts_flow_into_alert_pool(self):
        # Feed a process-creation event that triggers SF-SIG-001 (certutil LOLBin)
        winlog_proc = {
            "EventID": 4688, "TimeCreated": "2026-05-09T02:16:00Z",
            "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5",
            "event_id": 4688,
            "command_line": "certutil -decode encoded.txt output.exe",
            "image": "C:\\Windows\\System32\\certutil.exe",
        }
        result = self.orch.run({"winlog": [winlog_proc]})
        types = {a["alert_type"] for a in result["alerts"]}
        assert "sigma_rule_match" in types

    def test_nra_only_run(self):
        result = self.orch.run({"nra": _NRA})
        assert result["event_count"] == 1
        assert result["normalized_events"][0]["event_type"] == "port_scan"

    def test_winlog_only_run(self):
        result = self.orch.run({"winlog": [_WINLOG_SUCCESS]})
        assert result["event_count"] == 1
        assert result["normalized_events"][0]["event_type"] == "authentication_success"

    def test_mock_only_run(self):
        result = self.orch.run({"mock": _MOCK})
        assert result["event_count"] == 1
        assert result["normalized_events"][0]["event_type"] == "lateral_movement"


class TestPipelineStageError:
    def test_stage_attribute_set(self):
        err = PipelineStageError("normalize", ValueError("bad input"))
        assert err.stage == "normalize"

    def test_str_includes_stage_and_cause(self):
        err = PipelineStageError("enrich", RuntimeError("module missing"))
        assert "enrich" in str(err)
        assert "module missing" in str(err)
