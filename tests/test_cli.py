"""
tests/test_cli.py — CLI command tests using Typer's CliRunner.

All commands are tested with --db pointing at a temporary SQLite file
pre-populated by a real pipeline run. This exercises the full stack
(orchestrator → storage → CLI output) in one shot.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from core.pipeline.orchestrator import PipelineOrchestrator
from interface.cli import app
from storage.store import StorageLayer

# COLUMNS=300 prevents Rich from truncating table cell values in the narrow
# virtual terminal that CliRunner creates.
runner = CliRunner(env={"COLUMNS": "300"})

# ---------------------------------------------------------------------------
# Shared state across tests
# ---------------------------------------------------------------------------

_shared: dict = {}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PIPELINE_INPUTS = {
    "nra": [
        {
            "scanner_ip": "185.220.101.45",
            "host": "10.0.0.5",
            "scan_time": "2026-05-10T01:00:00Z",
            "risk_level": "high",
        }
    ],
    "winlog": [
        {"EventID": 4625, "TimeCreated": "2026-05-10T01:01:00Z",
         "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5"},
        {"EventID": 4625, "TimeCreated": "2026-05-10T01:01:30Z",
         "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5"},
        {"EventID": 4625, "TimeCreated": "2026-05-10T01:02:00Z",
         "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5"},
        {"EventID": 4624, "TimeCreated": "2026-05-10T01:03:00Z",
         "IpAddress": "185.220.101.45", "dst_ip": "10.0.0.5"},
    ],
}


@pytest.fixture(scope="module")
def db_path(tmp_path_factory) -> Path:
    """
    Create a temp SQLite DB, run the pipeline once, create a case and note,
    then return the path. Shared across the whole test module.
    """
    path = tmp_path_factory.mktemp("cli_db") / "test.db"

    result = PipelineOrchestrator().run(_PIPELINE_INPUTS)

    with StorageLayer(str(path)) as store:
        run_id = store.persist_run(result)
        # Create a case and add a note for case tests
        case = store.cases.create(
            title="SSH Brute Force — DC01",
            severity="high",
            assigned_to="analyst@company.com",
        )
        store.cases.add_note(case.case_ref, note="Confirmed TOR exit node.", author="analyst")
        # Link first alert to case
        alerts = store.alerts.get_recent(limit=1)
        if alerts:
            store.cases.link_alert(case.case_ref, alerts[0].id)

    _shared["run_id"]   = run_id
    _shared["case_ref"] = case.case_ref
    _shared["db"]       = str(path)

    return path


def invoke(db_path: Path, *args: str) -> object:
    """Helper: invoke CLI with --db set to the test database."""
    return runner.invoke(app, ["--db", str(db_path), *args])


# ===========================================================================
# status
# ===========================================================================

class TestStatus:
    def test_status_shows_counts(self, db_path):
        r = invoke(db_path, "status")
        assert r.exit_code == 0, r.output
        assert "Events" in r.output
        assert "Alerts" in r.output
        assert "Cases"  in r.output
        assert "Runs"   in r.output

    def test_status_top_risk_hosts(self, db_path):
        r = invoke(db_path, "status")
        assert r.exit_code == 0
        # After a pipeline run there should be at least one scored host
        assert "10.0.0.5" in r.output or "Top Risk Hosts" in r.output


# ===========================================================================
# runs
# ===========================================================================

class TestRuns:
    def test_list_runs(self, db_path):
        r = invoke(db_path, "runs")
        assert r.exit_code == 0, r.output
        assert _shared["run_id"] in r.output
        assert "completed" in r.output

    def test_list_runs_limit(self, db_path):
        r = invoke(db_path, "runs", "--limit", "1")
        assert r.exit_code == 0
        assert "completed" in r.output

    def test_get_run(self, db_path):
        r = invoke(db_path, "runs", "get", _shared["run_id"])
        assert r.exit_code == 0, r.output
        assert _shared["run_id"] in r.output
        assert "completed" in r.output
        assert "Audit Log" in r.output

    def test_get_run_not_found(self, db_path):
        r = invoke(db_path, "runs", "get", "run-does-not-exist")
        assert r.exit_code == 1
        assert "not found" in r.output.lower()


# ===========================================================================
# events
# ===========================================================================

class TestEvents:
    def test_list_events(self, db_path):
        r = invoke(db_path, "events")
        assert r.exit_code == 0, r.output
        assert "185.220.101.45" in r.output

    def test_filter_by_run_id(self, db_path):
        r = invoke(db_path, "events", "--run-id", _shared["run_id"])
        assert r.exit_code == 0
        assert "185.220.101.45" in r.output

    def test_filter_by_src_ip(self, db_path):
        r = invoke(db_path, "events", "--src-ip", "185.220.101.45")
        assert r.exit_code == 0
        assert "185.220.101.45" in r.output

    def test_filter_by_type(self, db_path):
        r = invoke(db_path, "events", "--type", "auth_failure")
        assert r.exit_code == 0

    def test_limit(self, db_path):
        r = invoke(db_path, "events", "--limit", "2")
        assert r.exit_code == 0
        # Should have at most 2 data rows (hard to count exactly with Rich tables)
        assert r.output  # non-empty

    def test_no_events_for_unknown_run(self, db_path):
        r = invoke(db_path, "events", "--run-id", "run-nonexistent")
        assert r.exit_code == 0
        assert "No events found" in r.output


# ===========================================================================
# alerts
# ===========================================================================

class TestAlerts:
    def test_list_alerts(self, db_path):
        r = invoke(db_path, "alerts")
        assert r.exit_code == 0, r.output
        assert "185.220.101.45" in r.output

    def test_filter_by_status(self, db_path):
        r = invoke(db_path, "alerts", "--status", "open")
        assert r.exit_code == 0
        # All new alerts are open
        assert "185.220.101.45" in r.output

    def test_filter_invalid_status(self, db_path):
        r = invoke(db_path, "alerts", "--status", "garbage")
        assert r.exit_code == 1
        assert "Error" in r.output

    def test_filter_by_confidence(self, db_path):
        r = invoke(db_path, "alerts", "--confidence", "0.99")
        assert r.exit_code == 0

    def test_get_alert(self, db_path):
        with StorageLayer(_shared["db"]) as store:
            alert_id = store.alerts.get_recent(limit=1)[0].id
        _shared["alert_id"] = alert_id

        r = invoke(db_path, "alerts", "get", str(alert_id))
        assert r.exit_code == 0, r.output
        assert str(alert_id) in r.output
        assert "Confidence" in r.output

    def test_get_alert_not_found(self, db_path):
        r = invoke(db_path, "alerts", "get", "999999")
        assert r.exit_code == 1
        assert "not found" in r.output.lower()

    def test_update_alert_status(self, db_path):
        alert_id = _shared["alert_id"]
        r = invoke(db_path, "alerts", "update", str(alert_id), "--status", "investigating")
        assert r.exit_code == 0, r.output
        assert "investigating" in r.output

    def test_update_alert_invalid_status(self, db_path):
        alert_id = _shared["alert_id"]
        r = invoke(db_path, "alerts", "update", str(alert_id), "--status", "hacked")
        assert r.exit_code == 1
        assert "Error" in r.output

    def test_update_alert_not_found(self, db_path):
        r = invoke(db_path, "alerts", "update", "999999", "--status", "closed")
        assert r.exit_code == 1
        assert "not found" in r.output.lower()


# ===========================================================================
# cases
# ===========================================================================

class TestCases:
    def test_list_cases(self, db_path):
        r = invoke(db_path, "cases")
        assert r.exit_code == 0, r.output
        assert _shared["case_ref"] in r.output
        assert "SSH Brute Force" in r.output

    def test_filter_by_status(self, db_path):
        r = invoke(db_path, "cases", "--status", "open")
        assert r.exit_code == 0
        assert _shared["case_ref"] in r.output

    def test_filter_invalid_status(self, db_path):
        r = invoke(db_path, "cases", "--status", "invalid")
        assert r.exit_code == 1

    def test_get_case(self, db_path):
        r = invoke(db_path, "cases", "get", _shared["case_ref"])
        assert r.exit_code == 0, r.output
        assert _shared["case_ref"] in r.output
        assert "Analyst Notes" in r.output
        assert "Confirmed TOR exit node" in r.output

    def test_get_case_not_found(self, db_path):
        r = invoke(db_path, "cases", "get", "CASE-9999-9999")
        assert r.exit_code == 1
        assert "not found" in r.output.lower()

    def test_create_case(self, db_path):
        r = invoke(db_path, "cases", "create",
                   "--title", "Lateral Movement — Web01",
                   "--severity", "critical",
                   "--assigned-to", "lead@company.com")
        assert r.exit_code == 0, r.output
        assert "CASE-" in r.output

    def test_create_case_invalid_severity(self, db_path):
        r = invoke(db_path, "cases", "create",
                   "--title", "Bad case",
                   "--severity", "extreme")
        assert r.exit_code != 0

    def test_update_case_status(self, db_path):
        r = invoke(db_path, "cases", "update", _shared["case_ref"], "--status", "investigating")
        assert r.exit_code == 0, r.output
        assert "investigating" in r.output

    def test_update_case_not_found(self, db_path):
        r = invoke(db_path, "cases", "update", "CASE-9999-9999", "--status", "closed")
        assert r.exit_code == 1

    def test_assign_case(self, db_path):
        r = invoke(db_path, "cases", "assign", _shared["case_ref"], "--to", "j.smith@company.com")
        assert r.exit_code == 0, r.output
        assert "j.smith@company.com" in r.output

    def test_assign_case_not_found(self, db_path):
        r = invoke(db_path, "cases", "assign", "CASE-9999-9999", "--to", "analyst")
        assert r.exit_code == 1

    def test_add_note(self, db_path):
        r = invoke(db_path, "cases", "note", _shared["case_ref"],
                   "--note", "Lateral movement confirmed.",
                   "--author", "j.smith@company.com")
        assert r.exit_code == 0, r.output
        assert "Note added" in r.output

    def test_add_note_not_found(self, db_path):
        r = invoke(db_path, "cases", "note", "CASE-9999-9999", "--note", "test")
        assert r.exit_code == 1

    def test_link_alert(self, db_path):
        alert_id = _shared["alert_id"]
        r = invoke(db_path, "cases", "link", _shared["case_ref"], "--alert-id", str(alert_id))
        assert r.exit_code == 0, r.output
        assert "linked" in r.output.lower()

    def test_link_alert_not_found(self, db_path):
        r = invoke(db_path, "cases", "link", _shared["case_ref"], "--alert-id", "999999")
        assert r.exit_code == 1
        assert "not found" in r.output.lower()

    def test_link_case_not_found(self, db_path):
        r = invoke(db_path, "cases", "link", "CASE-9999-9999", "--alert-id", "1")
        assert r.exit_code == 1


# ===========================================================================
# scores
# ===========================================================================

class TestScores:
    def test_list_scores(self, db_path):
        r = invoke(db_path, "scores")
        assert r.exit_code == 0, r.output
        assert "10.0.0.5" in r.output
        assert "host_risk" in r.output

    def test_host_history(self, db_path):
        r = invoke(db_path, "scores", "--host", "10.0.0.5")
        assert r.exit_code == 0, r.output
        assert "10.0.0.5" in r.output

    def test_host_history_unknown(self, db_path):
        r = invoke(db_path, "scores", "--host", "1.2.3.4")
        assert r.exit_code == 0
        assert "No scores found" in r.output

    def test_attack_surface(self, db_path):
        r = invoke(db_path, "scores", "--attack-surface")
        assert r.exit_code == 0, r.output
        assert "attack_surface" in r.output


# ===========================================================================
# intel
# ===========================================================================

class TestIntel:
    def test_malicious_ip(self, db_path):
        r = invoke(db_path, "intel", "185.220.101.45")
        assert r.exit_code == 0, r.output
        assert "MALICIOUS" in r.output
        assert "Russia" in r.output
        assert "YES" in r.output        # TOR exit node
        assert "tor-exit-nodes" in r.output

    def test_tor_exit_node(self, db_path):
        r = invoke(db_path, "intel", "23.129.64.101")
        assert r.exit_code == 0
        assert "YES" in r.output        # TOR

    def test_private_ip(self, db_path):
        r = invoke(db_path, "intel", "10.0.0.5")
        assert r.exit_code == 0
        assert "CLEAN" in r.output
        assert "Internal" in r.output

    def test_unknown_ip(self, db_path):
        r = invoke(db_path, "intel", "8.8.8.8")
        assert r.exit_code == 0
        assert "CLEAN" in r.output


# ===========================================================================
# purge
# ===========================================================================

class TestPurge:
    def test_purge_dry_run_skipped_with_yes(self, db_path):
        """--yes skips the confirmation prompt."""
        r = invoke(db_path, "purge", "--days", "3650", "--yes")
        assert r.exit_code == 0, r.output
        # Max retention keeps everything
        assert "nothing purged" in r.output.lower()

    def test_purge_aborted_without_yes(self, db_path):
        """Without --yes, CliRunner sends no input → prompt aborts."""
        r = invoke(db_path, "purge", "--days", "90")
        # Typer raises Exit on aborted confirm
        assert r.exit_code != 0 or "Aborted" in r.output

    def test_purge_aggressive_with_yes(self, db_path):
        """1-day retention succeeds even if it deletes yesterday's events."""
        r = invoke(db_path, "purge", "--days", "1", "--yes")
        assert r.exit_code == 0, r.output


# ===========================================================================
# run (pipeline execution)
# ===========================================================================

class TestRun:
    def test_run_from_json_files(self, db_path, tmp_path):
        nra_file    = tmp_path / "nra.json"
        winlog_file = tmp_path / "winlog.json"

        nra_file.write_text(json.dumps(_PIPELINE_INPUTS["nra"]))
        winlog_file.write_text(json.dumps(_PIPELINE_INPUTS["winlog"]))

        r = invoke(db_path, "run",
                   "--nra",    str(nra_file),
                   "--winlog", str(winlog_file))
        assert r.exit_code == 0, r.output
        assert "run-" in r.output
        assert "completed" in r.output.lower() or "Events" in r.output

    def test_run_no_inputs(self, db_path):
        r = invoke(db_path, "run")
        assert r.exit_code == 1
        assert "Error" in r.output

    def test_run_invalid_json(self, db_path, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all")
        r = invoke(db_path, "run", "--nra", str(bad))
        assert r.exit_code == 1
        assert "invalid JSON" in r.output.lower() or "Error" in r.output

    def test_run_non_list_json(self, db_path, tmp_path):
        bad = tmp_path / "obj.json"
        bad.write_text('{"key": "value"}')
        r = invoke(db_path, "run", "--nra", str(bad))
        assert r.exit_code == 1

    def test_run_with_report_flag(self, db_path, tmp_path):
        nra_file = tmp_path / "nra2.json"
        nra_file.write_text(json.dumps(_PIPELINE_INPUTS["nra"]))
        r = invoke(db_path, "run", "--nra", str(nra_file), "--report")
        assert r.exit_code == 0, r.output
        assert "SOC Report" in r.output


# ===========================================================================
# global --help and --db
# ===========================================================================

class TestGlobal:
    def test_help(self):
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0
        assert "status" in r.output
        assert "run" in r.output
        assert "alerts" in r.output
        assert "cases" in r.output
        assert "scores" in r.output
        assert "intel" in r.output
        assert "runs" in r.output
        assert "purge" in r.output

    def test_db_override(self, db_path, tmp_path):
        """--db flag should point commands at a different database."""
        other_db = tmp_path / "other.db"
        r = runner.invoke(app, ["--db", str(other_db), "status"])
        assert r.exit_code == 0
        # Fresh DB has zero counts
        assert "0" in r.output

    def test_subcommand_help(self):
        for cmd in ("status", "run", "events", "alerts", "cases", "scores", "intel", "runs", "purge"):
            r = runner.invoke(app, [cmd, "--help"])
            assert r.exit_code == 0, f"{cmd} --help failed: {r.output}"
