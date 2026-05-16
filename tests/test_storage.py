"""
Tests for the storage layer — database, repositories, and StorageLayer facade.
All tests use an in-memory SQLite database (:memory:) so nothing touches disk.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import Database, DatabaseError
from storage.store import StorageLayer
from storage.models import ALERT_STATUSES, CASE_STATUSES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    with Database(":memory:") as database:
        yield database


@pytest.fixture
def store():
    with StorageLayer(":memory:") as s:
        yield s


# Minimal pipeline result matching orchestrator.run() output
_PIPELINE_RESULT = {
    "event_count": 2,
    "normalized_events": [
        {
            "timestamp":   "2026-05-09T02:14:00Z",
            "source_type": "nra",
            "src_ip":      "185.220.101.45",
            "dst_ip":      "10.0.0.5",
            "event_type":  "port_scan",
            "severity":    8,
            "metadata":    {},
        },
        {
            "timestamp":   "2026-05-09T02:15:00Z",
            "source_type": "winlog",
            "src_ip":      "185.220.101.45",
            "dst_ip":      "10.0.0.5",
            "event_type":  "authentication_failure",
            "severity":    5,
            "metadata":    {},
        },
    ],
    "alerts": [
        {
            "alert_type":      "brute_force_detected",
            "confidence":      0.80,
            "src_ip":          "185.220.101.45",
            "dst_ip":          "10.0.0.5",
            "failure_count":   3,
            "window_start":    "2026-05-09T02:15:00Z",
            "window_end":      "2026-05-09T02:17:00Z",
            "severity":        7,
            "mitre_tactic":    "TA0006 - Credential Access",
            "mitre_technique": "T1110 - Brute Force",
        },
        {
            "alert_type":   "lateral_movement_detected",
            "confidence":   0.75,
            "initial_src_ip": "185.220.101.45",
            "pivot_host":   "10.0.0.5",
            "lateral_target": "10.0.0.10",
            "severity":     9,
            "mitre_tactic": "TA0008 - Lateral Movement",
        },
    ],
    "scores": {
        "host_risk": {
            "10.0.0.5": {
                "risk_score": 9.5, "risk_label": "critical",
                "event_count": 2, "alert_count": 1,
                "max_event_severity": 8, "alert_types": [], "factors": [],
            },
        },
        "asset_risk": {
            "10.0.0.5": {
                "exposure_score": 7.0, "exposure_label": "high",
                "high_risk_event_count": 1, "event_types_observed": [],
                "alert_count": 1, "is_lateral_target": False, "factors": [],
            },
        },
        "attack_surface": {
            "expansion_score": 6.5, "expansion_label": "significant",
            "unique_external_sources": 1, "unique_internal_targets": 1,
            "unique_attack_techniques": 2, "lateral_movement_hops": 1,
            "alert_type_breakdown": {}, "mitre_tactics_observed": [], "factors": [],
        },
    },
    "timeline":  [],
    "report":    {"json": {}, "markdown": ""},
    "trace": [
        {"stage": "ingest",     "status": "ok", "count": 2},
        {"stage": "normalize",  "status": "ok", "count": 2},
        {"stage": "enrich",     "status": "ok", "count": 2},
        {"stage": "correlate",  "status": "ok", "count": 1},
        {"stage": "detect",     "status": "ok", "count": 2},
        {"stage": "score",      "status": "ok"},
        {"stage": "timeline",   "status": "ok", "count": 3},
        {"stage": "report",     "status": "ok"},
    ],
}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class TestDatabase:
    def test_connect_and_close(self):
        db = Database(":memory:")
        db.connect()
        assert db.schema_version == 1
        db.close()

    def test_context_manager(self):
        with Database(":memory:") as db:
            assert db.schema_version == 1

    def test_query_before_connect_raises(self):
        db = Database(":memory:")
        with pytest.raises(DatabaseError, match="not connected"):
            db.query("SELECT 1")

    def test_write_context_manager_commits(self, db):
        db.execute(
            "CREATE TABLE IF NOT EXISTS _test (val TEXT)"
        )
        with db.write() as conn:
            conn.execute("INSERT INTO _test VALUES (?)", ("hello",))
        rows = db.query("SELECT val FROM _test")
        assert rows[0]["val"] == "hello"

    def test_write_context_manager_rolls_back_on_error(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS _test2 (val TEXT NOT NULL)")
        try:
            with db.write() as conn:
                conn.execute("INSERT INTO _test2 VALUES (?)", ("ok",))
                conn.execute("INSERT INTO _test2 VALUES (?)", (None,))
        except Exception:
            pass
        rows = db.query("SELECT COUNT(*) FROM _test2")
        assert rows[0][0] == 0

    def test_schema_version_after_migration(self, db):
        assert db.schema_version == 1

    def test_migrations_idempotent(self):
        with Database(":memory:") as db1:
            v1 = db1.schema_version
        with Database(":memory:") as db2:
            v2 = db2.schema_version
        assert v1 == v2 == 1


# ---------------------------------------------------------------------------
# EventRepository
# ---------------------------------------------------------------------------

class TestEventRepository:
    def test_store_and_retrieve(self, store):
        ev = _PIPELINE_RESULT["normalized_events"][0]
        store.events.store(ev, "run-001")
        results = store.events.get_by_run("run-001")
        assert len(results) == 1
        assert results[0].src_ip == "185.220.101.45"
        assert results[0].event_type == "port_scan"

    def test_store_batch(self, store):
        count = store.events.store_batch(
            _PIPELINE_RESULT["normalized_events"], "run-001"
        )
        assert count == 2

    def test_deduplication(self, store):
        ev = _PIPELINE_RESULT["normalized_events"][0]
        first  = store.events.store(ev, "run-001")
        second = store.events.store(ev, "run-001")
        assert first  is not None
        assert second is None  # duplicate silently skipped
        assert store.events.count() == 1

    def test_get_by_src_ip(self, store):
        store.events.store_batch(_PIPELINE_RESULT["normalized_events"], "run-001")
        results = store.events.get_by_src_ip("185.220.101.45")
        assert len(results) == 2

    def test_get_by_event_type(self, store):
        store.events.store_batch(_PIPELINE_RESULT["normalized_events"], "run-001")
        results = store.events.get_by_event_type("port_scan")
        assert len(results) == 1

    def test_get_recent(self, store):
        store.events.store_batch(_PIPELINE_RESULT["normalized_events"], "run-001")
        recent = store.events.get_recent(limit=10)
        assert len(recent) == 2

    def test_count(self, store):
        assert store.events.count() == 0
        store.events.store_batch(_PIPELINE_RESULT["normalized_events"], "run-001")
        assert store.events.count() == 2

    def test_purge_before_removes_old_events(self, store):
        ev = {
            **_PIPELINE_RESULT["normalized_events"][0],
            "timestamp": "2020-01-01T00:00:00Z",
        }
        store.events.store(ev, "run-old")
        assert store.events.count() == 1
        deleted = store.events.purge_before(days=1)
        assert deleted == 1
        assert store.events.count() == 0

    def test_purge_before_preserves_recent(self, store):
        from datetime import datetime, timezone
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev1 = {**_PIPELINE_RESULT["normalized_events"][0], "timestamp": now,
               "src_ip": "1.2.3.4"}
        ev2 = {**_PIPELINE_RESULT["normalized_events"][1], "timestamp": now,
               "src_ip": "1.2.3.5"}
        store.events.store(ev1, "run-recent")
        store.events.store(ev2, "run-recent")
        before = store.events.count()
        deleted = store.events.purge_before(days=1)
        assert deleted == 0
        assert store.events.count() == before

    def test_metadata_serialized_and_deserialized(self, store):
        ev = {**_PIPELINE_RESULT["normalized_events"][0],
              "metadata": {"enrichment": {"src_geo": {"country": "Russia"}}}}
        store.events.store(ev, "run-001")
        result = store.events.get_by_run("run-001")[0]
        assert result.metadata["enrichment"]["src_geo"]["country"] == "Russia"


# ---------------------------------------------------------------------------
# AlertRepository
# ---------------------------------------------------------------------------

class TestAlertRepository:
    def test_store_and_retrieve(self, store):
        alert = _PIPELINE_RESULT["alerts"][0]
        store.alerts.store(alert, "run-001")
        results = store.alerts.get_by_run("run-001")
        assert len(results) == 1
        assert results[0].alert_type == "brute_force_detected"
        assert results[0].status == "open"

    def test_store_batch(self, store):
        count = store.alerts.store_batch(_PIPELINE_RESULT["alerts"], "run-001")
        assert count == 2

    def test_deduplication(self, store):
        alert  = _PIPELINE_RESULT["alerts"][0]
        first  = store.alerts.store(alert, "run-001")
        second = store.alerts.store(alert, "run-001")
        assert first  is not None
        assert second is None

    def test_get_open(self, store):
        store.alerts.store_batch(_PIPELINE_RESULT["alerts"], "run-001")
        open_alerts = store.alerts.get_open()
        assert len(open_alerts) == 2

    def test_update_status(self, store):
        store.alerts.store(_PIPELINE_RESULT["alerts"][0], "run-001")
        stored = store.alerts.get_by_run("run-001")[0]
        store.alerts.update_status(stored.id, "investigating")
        updated = store.alerts.get_by_id(stored.id)
        assert updated.status == "investigating"

    def test_invalid_status_raises(self, store):
        store.alerts.store(_PIPELINE_RESULT["alerts"][0], "run-001")
        stored = store.alerts.get_by_run("run-001")[0]
        with pytest.raises(ValueError, match="Invalid status"):
            store.alerts.update_status(stored.id, "unknown_status")

    def test_get_by_src_ip(self, store):
        store.alerts.store_batch(_PIPELINE_RESULT["alerts"], "run-001")
        results = store.alerts.get_by_src_ip("185.220.101.45")
        assert len(results) >= 1

    def test_count_by_status(self, store):
        store.alerts.store_batch(_PIPELINE_RESULT["alerts"], "run-001")
        counts = store.alerts.count_by_status()
        assert counts.get("open", 0) == 2

    def test_count_by_type(self, store):
        store.alerts.store_batch(_PIPELINE_RESULT["alerts"], "run-001")
        counts = store.alerts.count_by_type()
        assert counts["brute_force_detected"] == 1
        assert counts["lateral_movement_detected"] == 1

    def test_details_preserved(self, store):
        alert = _PIPELINE_RESULT["alerts"][0]
        store.alerts.store(alert, "run-001")
        result = store.alerts.get_by_run("run-001")[0]
        assert result.details["failure_count"] == 3


# ---------------------------------------------------------------------------
# CaseRepository
# ---------------------------------------------------------------------------

class TestCaseRepository:
    def test_create_case(self, store):
        case = store.cases.create("SSH Brute Force - DC01", severity="high")
        assert case.case_ref.startswith("CASE-")
        assert case.status == "open"
        assert case.severity == "high"

    def test_case_ref_sequential(self, store):
        case1 = store.cases.create("Case One")
        case2 = store.cases.create("Case Two")
        assert case1.case_ref != case2.case_ref

    def test_update_status(self, store):
        case = store.cases.create("Test Case")
        store.cases.update_status(case.case_ref, "investigating")
        retrieved = store.cases.get(case.case_ref)
        assert retrieved.status == "investigating"

    def test_invalid_status_raises(self, store):
        case = store.cases.create("Test Case")
        with pytest.raises(ValueError, match="Invalid status"):
            store.cases.update_status(case.case_ref, "deleted")

    def test_invalid_severity_raises(self, store):
        with pytest.raises(ValueError, match="Invalid severity"):
            store.cases.create("Bad Case", severity="extreme")

    def test_assign(self, store):
        case = store.cases.create("Test Case")
        store.cases.assign(case.case_ref, "analyst@company.com")
        retrieved = store.cases.get(case.case_ref)
        assert retrieved.assigned_to == "analyst@company.com"

    def test_link_alert(self, store):
        case  = store.cases.create("Test Case")
        store.alerts.store(_PIPELINE_RESULT["alerts"][0], "run-001")
        alert = store.alerts.get_by_run("run-001")[0]
        result = store.cases.link_alert(case.case_ref, alert.id)
        assert result is True
        ids = store.cases.get_alert_ids(case.case_ref)
        assert alert.id in ids

    def test_link_alert_idempotent(self, store):
        case  = store.cases.create("Test Case")
        store.alerts.store(_PIPELINE_RESULT["alerts"][0], "run-001")
        alert = store.alerts.get_by_run("run-001")[0]
        store.cases.link_alert(case.case_ref, alert.id)
        result = store.cases.link_alert(case.case_ref, alert.id)
        assert result is False  # already linked

    def test_add_note(self, store):
        case = store.cases.create("Test Case")
        note = store.cases.add_note(case.case_ref, "Confirmed brute force from TOR exit node.")
        assert note.note == "Confirmed brute force from TOR exit node."

    def test_get_notes(self, store):
        case = store.cases.create("Test Case")
        store.cases.add_note(case.case_ref, "Note 1")
        store.cases.add_note(case.case_ref, "Note 2")
        notes = store.cases.get_notes(case.case_ref)
        assert len(notes) == 2

    def test_get_all_filtered_by_status(self, store):
        store.cases.create("Open Case")
        closed = store.cases.create("Closed Case")
        store.cases.update_status(closed.case_ref, "closed")
        open_cases = store.cases.get_all(status="open")
        assert len(open_cases) == 1
        assert open_cases[0].title == "Open Case"

    def test_count_by_status(self, store):
        store.cases.create("Case 1")
        c2 = store.cases.create("Case 2")
        store.cases.update_status(c2.case_ref, "closed")
        counts = store.cases.count_by_status()
        assert counts.get("open", 0) == 1
        assert counts.get("closed", 0) == 1


# ---------------------------------------------------------------------------
# ScoreRepository
# ---------------------------------------------------------------------------

class TestScoreRepository:
    def test_store_run_scores(self, store):
        count = store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        assert count == 3  # 1 host_risk + 1 asset_risk + 1 attack_surface

    def test_get_latest_host_scores(self, store):
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        results = store.scores.get_latest_host_scores()
        assert len(results) == 1
        assert results[0].target == "10.0.0.5"
        assert results[0].score == 9.5
        assert results[0].label == "critical"

    def test_get_highest_risk_hosts(self, store):
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        results = store.scores.get_highest_risk_hosts(limit=5)
        assert results[0].score == 9.5

    def test_get_by_run(self, store):
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        results = store.scores.get_by_run("run-001")
        assert len(results) == 3

    def test_host_history_multiple_runs(self, store):
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-002")
        history = store.scores.get_host_history("10.0.0.5", limit=10)
        assert len(history) == 2

    def test_attack_surface_stored_as_global(self, store):
        store.scores.store_run_scores(_PIPELINE_RESULT["scores"], "run-001")
        history = store.scores.get_attack_surface_history()
        assert len(history) == 1
        assert history[0].target == "__global__"
        assert history[0].score == 6.5


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------

class TestAuditRepository:
    def test_start_and_complete_run(self, store):
        run = store.audit.start_run("run-001")
        assert run.run_id == "run-001"
        assert run.status == "running"
        store.audit.complete_run("run-001", event_count=5, alert_count=3)
        retrieved = store.audit.get_run("run-001")
        assert retrieved.status == "completed"
        assert retrieved.event_count == 5
        assert retrieved.alert_count == 3

    def test_log_entry(self, store):
        store.audit.start_run("run-001")
        entry = store.audit.log("run-001", "ingest", "ok", "count=5")
        assert entry.stage == "ingest"
        assert entry.action == "ok"

    def test_log_trace(self, store):
        store.audit.start_run("run-001")
        store.audit.log_trace("run-001", _PIPELINE_RESULT["trace"])
        log = store.audit.get_run_log("run-001")
        stages = [e.stage for e in log]
        assert "ingest" in stages
        assert "report" in stages

    def test_get_recent_runs(self, store):
        store.audit.start_run("run-001")
        store.audit.start_run("run-002")
        runs = store.audit.get_recent_runs(limit=10)
        assert len(runs) == 2

    def test_invalid_run_status_raises(self, store):
        store.audit.start_run("run-001")
        with pytest.raises(ValueError, match="Invalid run status"):
            store.audit.complete_run("run-001", 0, 0, status="unknown")

    def test_run_count(self, store):
        assert store.audit.get_run_count() == 0
        store.audit.start_run("run-001")
        assert store.audit.get_run_count() == 1


# ---------------------------------------------------------------------------
# StorageLayer facade
# ---------------------------------------------------------------------------

class TestStorageLayer:
    def test_persist_run_returns_run_id(self, store):
        run_id = store.persist_run(_PIPELINE_RESULT)
        assert run_id.startswith("run-")

    def test_persist_run_stores_events(self, store):
        store.persist_run(_PIPELINE_RESULT)
        assert store.events.count() == 2

    def test_persist_run_stores_alerts(self, store):
        store.persist_run(_PIPELINE_RESULT)
        total = sum(store.alerts.count_by_status().values())
        assert total == 2

    def test_persist_run_stores_scores(self, store):
        run_id = store.persist_run(_PIPELINE_RESULT)
        scores = store.scores.get_by_run(run_id)
        assert len(scores) == 3

    def test_persist_run_records_audit_trace(self, store):
        run_id = store.persist_run(_PIPELINE_RESULT)
        log = store.audit.get_run_log(run_id)
        assert len(log) == 8  # 8 pipeline stages

    def test_persist_run_marks_run_completed(self, store):
        run_id = store.persist_run(_PIPELINE_RESULT)
        run    = store.audit.get_run(run_id)
        assert run.status == "completed"

    def test_persist_run_idempotent_for_events(self, store):
        store.persist_run(_PIPELINE_RESULT)
        store.persist_run(_PIPELINE_RESULT)
        # Events deduplicated — still only 2 unique events
        assert store.events.count() == 2

    def test_custom_run_id(self, store):
        run_id = store.persist_run(_PIPELINE_RESULT, run_id="custom-run-abc")
        assert run_id == "custom-run-abc"
        assert store.audit.get_run("custom-run-abc") is not None

    def test_summary(self, store):
        store.persist_run(_PIPELINE_RESULT)
        s = store.summary()
        assert s["total_events"] == 2
        assert s["total_alerts"] == 2
        assert s["schema_version"] == 1
        assert "alerts_by_status" in s
        assert "top_risk_hosts" in s

    def test_purge_retention(self, store):
        old_ev = {
            **_PIPELINE_RESULT["normalized_events"][0],
            "timestamp": "2020-01-01T00:00:00Z",
        }
        store.events.store(old_ev, "run-old")
        result = store.purge(days=30)
        assert result["events"] == 1

    def test_purge_invalid_days_raises(self, store):
        with pytest.raises(ValueError, match="Retention period"):
            store.purge(days=0)
