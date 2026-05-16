"""
tests/test_api.py — REST API endpoint tests.

Uses FastAPI's TestClient backed by an in-memory SQLite database.
Tests run in module scope — the pipeline run is executed once and its
run_id is shared across subsequent tests that query events, alerts, etc.
"""

from __future__ import annotations

import os
import pytest

os.environ["SENTINEL_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402 — env must be set first

import api.dependencies as _deps  # noqa: E402
from api.app import create_app    # noqa: E402


# ---------------------------------------------------------------------------
# Shared payload: realistic NRA + Winlog brute-force attack simulation
# ---------------------------------------------------------------------------

_PIPELINE_PAYLOAD = {
    "nra": [
        {
            "scanner_ip": "185.220.101.45",
            "host": "10.0.0.5",
            "scan_time": "2026-05-09T02:14:00Z",
            "risk_level": "high",
        }
    ],
    "winlog": [
        {
            "EventID": 4625,
            "TimeCreated": "2026-05-09T02:15:00Z",
            "IpAddress": "185.220.101.45",
            "dst_ip": "10.0.0.5",
        },
        {
            "EventID": 4625,
            "TimeCreated": "2026-05-09T02:15:30Z",
            "IpAddress": "185.220.101.45",
            "dst_ip": "10.0.0.5",
        },
        {
            "EventID": 4625,
            "TimeCreated": "2026-05-09T02:16:00Z",
            "IpAddress": "185.220.101.45",
            "dst_ip": "10.0.0.5",
        },
        {
            "EventID": 4624,
            "TimeCreated": "2026-05-09T02:17:00Z",
            "IpAddress": "185.220.101.45",
            "dst_ip": "10.0.0.5",
        },
    ],
}

# Captured across tests via this shared state dict
_shared: dict = {}


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """TestClient wired to an in-memory SQLite store via SENTINEL_DB env var."""
    with TestClient(create_app()) as c:
        yield c


# ===========================================================================
# Health
# ===========================================================================

class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["version"] == "1.0.0"
        assert body["schema_version"] >= 1
        for key in ("total_events", "total_alerts", "total_cases", "total_runs"):
            assert isinstance(body[key], int)

    def test_status_ok(self, client):
        r = client.get("/api/v1/status")
        assert r.status_code == 200
        body = r.json()
        assert "alerts_by_status" in body
        assert "cases_by_status" in body
        assert "top_risk_hosts" in body
        assert isinstance(body["top_risk_hosts"], list)


# ===========================================================================
# Pipeline run
# ===========================================================================

class TestPipelineRun:
    def test_run_success(self, client):
        r = client.post("/api/v1/pipeline/run", json=_PIPELINE_PAYLOAD)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "completed"
        assert body["event_count"] >= 5
        assert body["alert_count"] >= 1
        assert body["run_id"].startswith("run-")
        assert isinstance(body["trace"], list)
        assert len(body["trace"]) == 8          # 8 pipeline stages
        assert isinstance(body["scores"], dict)
        assert "host_risk" in body["scores"]
        assert isinstance(body["top_alerts"], list)
        assert "report" in body
        assert "json" in body["report"]
        assert "markdown" in body["report"]
        # Save run_id for downstream tests
        _shared["run_id"] = body["run_id"]
        _shared["alert_count"] = body["alert_count"]

    def test_run_empty_payload_rejected(self, client):
        r = client.post("/api/v1/pipeline/run", json={"nra": [], "winlog": [], "mock": []})
        assert r.status_code == 400

    def test_run_bad_event_type(self, client):
        """Unknown source key in payload body passes schema validation but orchestrator rejects it."""
        # PipelineRunRequest only allows nra/winlog/mock — extra fields are ignored by Pydantic
        r = client.post("/api/v1/pipeline/run", json={"nra": [{"x": 1}]})
        # Should succeed — NRA event dict with minimal fields
        assert r.status_code in (200, 422)

    def test_list_runs(self, client):
        r = client.get("/api/v1/pipeline/runs")
        assert r.status_code == 200
        runs = r.json()
        assert isinstance(runs, list)
        assert len(runs) >= 1
        run = runs[0]
        assert "run_id" in run
        assert run["status"] == "completed"

    def test_get_run_by_id(self, client):
        run_id = _shared["run_id"]
        r = client.get(f"/api/v1/pipeline/runs/{run_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["run_id"] == run_id
        assert body["status"] == "completed"

    def test_get_run_not_found(self, client):
        r = client.get("/api/v1/pipeline/runs/run-does-not-exist")
        assert r.status_code == 404


# ===========================================================================
# Events
# ===========================================================================

class TestEvents:
    def test_list_events_recent(self, client):
        r = client.get("/api/v1/events")
        assert r.status_code == 200
        events = r.json()
        assert isinstance(events, list)
        assert len(events) >= 5
        e = events[0]
        for key in ("id", "event_hash", "run_id", "timestamp", "source_type",
                     "src_ip", "dst_ip", "event_type", "severity", "ingested_at"):
            assert key in e, f"Missing key: {key}"

    def test_filter_by_run_id(self, client):
        run_id = _shared["run_id"]
        r = client.get(f"/api/v1/events?run_id={run_id}")
        assert r.status_code == 200
        events = r.json()
        assert len(events) >= 5
        assert all(e["run_id"] == run_id for e in events)

    def test_filter_by_src_ip(self, client):
        r = client.get("/api/v1/events?src_ip=185.220.101.45")
        assert r.status_code == 200
        events = r.json()
        assert len(events) >= 1
        assert all(e["src_ip"] == "185.220.101.45" for e in events)

    def test_filter_by_event_type(self, client):
        r = client.get("/api/v1/events?event_type=auth_failure")
        assert r.status_code == 200
        events = r.json()
        assert isinstance(events, list)

    def test_limit_respected(self, client):
        r = client.get("/api/v1/events?limit=2")
        assert r.status_code == 200
        assert len(r.json()) <= 2


# ===========================================================================
# Alerts
# ===========================================================================

class TestAlerts:
    def test_list_alerts(self, client):
        r = client.get("/api/v1/alerts")
        assert r.status_code == 200
        alerts = r.json()
        assert isinstance(alerts, list)
        assert len(alerts) >= 1
        a = alerts[0]
        for key in ("id", "alert_hash", "run_id", "alert_type", "confidence",
                     "src_ip", "dst_ip", "severity", "mitre_tactic",
                     "status", "details", "created_at", "updated_at"):
            assert key in a, f"Missing alert key: {key}"
        # Save first alert ID for downstream tests
        _shared["alert_id"] = a["id"]

    def test_filter_by_status(self, client):
        r = client.get("/api/v1/alerts?status=open")
        assert r.status_code == 200
        alerts = r.json()
        assert all(a["status"] == "open" for a in alerts)

    def test_filter_invalid_status(self, client):
        r = client.get("/api/v1/alerts?status=nonexistent")
        assert r.status_code == 400

    def test_filter_by_confidence(self, client):
        r = client.get("/api/v1/alerts?min_confidence=0.9")
        assert r.status_code == 200
        for a in r.json():
            assert a["confidence"] >= 0.9

    def test_get_alert_by_id(self, client):
        alert_id = _shared["alert_id"]
        r = client.get(f"/api/v1/alerts/{alert_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == alert_id

    def test_get_alert_not_found(self, client):
        r = client.get("/api/v1/alerts/999999")
        assert r.status_code == 404

    def test_update_alert_status(self, client):
        alert_id = _shared["alert_id"]
        r = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "investigating"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "investigating"

    def test_update_alert_status_invalid(self, client):
        alert_id = _shared["alert_id"]
        r = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "hacked"},
        )
        assert r.status_code == 422  # Pydantic validator

    def test_update_alert_status_not_found(self, client):
        r = client.patch("/api/v1/alerts/999999/status", json={"status": "closed"})
        assert r.status_code == 404


# ===========================================================================
# Cases
# ===========================================================================

class TestCases:
    def test_list_cases_empty(self, client):
        r = client.get("/api/v1/cases")
        assert r.status_code == 200
        assert r.json() == []

    def test_create_case(self, client):
        r = client.post(
            "/api/v1/cases",
            json={
                "title": "SSH Brute Force — DC01",
                "severity": "high",
                "assigned_to": "analyst@company.com",
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "open"
        assert body["severity"] == "high"
        assert body["title"] == "SSH Brute Force — DC01"
        assert body["case_ref"].startswith("CASE-")
        _shared["case_ref"] = body["case_ref"]

    def test_list_cases_after_create(self, client):
        r = client.get("/api/v1/cases")
        assert r.status_code == 200
        cases = r.json()
        assert len(cases) == 1
        assert cases[0]["case_ref"] == _shared["case_ref"]

    def test_get_case(self, client):
        case_ref = _shared["case_ref"]
        r = client.get(f"/api/v1/cases/{case_ref}")
        assert r.status_code == 200
        assert r.json()["case_ref"] == case_ref

    def test_get_case_not_found(self, client):
        r = client.get("/api/v1/cases/CASE-9999-0001")
        assert r.status_code == 404

    def test_update_case_status(self, client):
        case_ref = _shared["case_ref"]
        r = client.patch(
            f"/api/v1/cases/{case_ref}/status",
            json={"status": "investigating"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "investigating"

    def test_update_case_status_invalid(self, client):
        case_ref = _shared["case_ref"]
        r = client.patch(
            f"/api/v1/cases/{case_ref}/status",
            json={"status": "deleted"},
        )
        assert r.status_code == 422

    def test_assign_case(self, client):
        case_ref = _shared["case_ref"]
        r = client.patch(
            f"/api/v1/cases/{case_ref}/assign",
            json={"assigned_to": "j.smith@company.com"},
        )
        assert r.status_code == 200
        assert r.json()["assigned_to"] == "j.smith@company.com"

    def test_add_note(self, client):
        case_ref = _shared["case_ref"]
        r = client.post(
            f"/api/v1/cases/{case_ref}/notes",
            json={
                "note": "Confirmed TOR exit node. Escalating to IR team.",
                "author": "j.smith@company.com",
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["case_ref"] == case_ref
        assert "TOR" in body["note"]
        assert body["author"] == "j.smith@company.com"

    def test_get_notes(self, client):
        case_ref = _shared["case_ref"]
        r = client.get(f"/api/v1/cases/{case_ref}/notes")
        assert r.status_code == 200
        notes = r.json()
        assert len(notes) == 1
        assert notes[0]["case_ref"] == case_ref

    def test_add_second_note(self, client):
        case_ref = _shared["case_ref"]
        client.post(
            f"/api/v1/cases/{case_ref}/notes",
            json={"note": "Lateral movement confirmed. Isolating host.", "author": "analyst"},
        )
        r = client.get(f"/api/v1/cases/{case_ref}/notes")
        assert len(r.json()) == 2

    def test_link_alert(self, client):
        case_ref = _shared["case_ref"]
        alert_id = _shared["alert_id"]
        r = client.post(
            f"/api/v1/cases/{case_ref}/alerts",
            json={"alert_id": alert_id},
        )
        assert r.status_code == 200
        # Case updated_at should reflect the link
        assert r.json()["case_ref"] == case_ref

    def test_link_alert_idempotent(self, client):
        """Linking the same alert twice should not error."""
        case_ref = _shared["case_ref"]
        alert_id = _shared["alert_id"]
        r = client.post(
            f"/api/v1/cases/{case_ref}/alerts",
            json={"alert_id": alert_id},
        )
        assert r.status_code == 200

    def test_link_alert_not_found(self, client):
        case_ref = _shared["case_ref"]
        r = client.post(
            f"/api/v1/cases/{case_ref}/alerts",
            json={"alert_id": 999999},
        )
        assert r.status_code == 404

    def test_filter_by_status(self, client):
        r = client.get("/api/v1/cases?status=investigating")
        assert r.status_code == 200
        cases = r.json()
        assert len(cases) == 1
        assert cases[0]["status"] == "investigating"

    def test_create_case_invalid_severity(self, client):
        r = client.post(
            "/api/v1/cases",
            json={"title": "Bad Case", "severity": "extreme"},
        )
        assert r.status_code == 422

    def test_create_case_empty_title(self, client):
        r = client.post(
            "/api/v1/cases",
            json={"title": ""},
        )
        assert r.status_code == 422


# ===========================================================================
# Scores
# ===========================================================================

class TestScores:
    def test_list_host_scores(self, client):
        r = client.get("/api/v1/scores/hosts")
        assert r.status_code == 200
        scores = r.json()
        assert isinstance(scores, list)
        assert len(scores) >= 1
        s = scores[0]
        for key in ("id", "run_id", "score_type", "target", "score", "label",
                     "details", "scored_at"):
            assert key in s, f"Missing score key: {key}"
        assert s["score_type"] == "host_risk"
        assert s["score"] >= 0

    def test_host_score_history(self, client):
        # host_risk scorer keys by dst_ip (victim host), not src_ip (attacker)
        r = client.get("/api/v1/scores/hosts/10.0.0.5")
        assert r.status_code == 200
        history = r.json()
        assert isinstance(history, list)
        assert len(history) >= 1
        assert history[0]["target"] == "10.0.0.5"

    def test_host_score_history_unknown_ip(self, client):
        r = client.get("/api/v1/scores/hosts/1.2.3.4")
        assert r.status_code == 200
        assert r.json() == []  # No scores for unknown IP

    def test_attack_surface_history(self, client):
        r = client.get("/api/v1/scores/attack-surface")
        assert r.status_code == 200
        history = r.json()
        assert isinstance(history, list)
        assert len(history) >= 1
        assert history[0]["score_type"] == "attack_surface"

    def test_scores_sorted_by_risk(self, client):
        r = client.get("/api/v1/scores/hosts")
        scores = r.json()
        if len(scores) >= 2:
            assert scores[0]["score"] >= scores[1]["score"]


# ===========================================================================
# Intel
# ===========================================================================

class TestIntel:
    def test_lookup_malicious_ip(self, client):
        r = client.get("/api/v1/intel/ip/185.220.101.45")
        assert r.status_code == 200
        body = r.json()
        assert body["ip"] == "185.220.101.45"
        assert body["reputation"]["is_malicious"] is True
        assert body["reputation"]["reputation_score"] > 0.9
        assert body["geo"]["country"] == "Russia"
        assert body["geo"]["is_tor"] is True
        assert len(body["threats"]["feed_hits"]) >= 3
        assert body["summary"]["is_malicious"] is True
        assert body["summary"]["feed_hits"] >= 3

    def test_lookup_tor_exit_node(self, client):
        r = client.get("/api/v1/intel/ip/23.129.64.101")
        assert r.status_code == 200
        body = r.json()
        assert body["geo"]["is_tor"] is True
        assert body["summary"]["is_tor"] is True

    def test_lookup_private_ip(self, client):
        r = client.get("/api/v1/intel/ip/10.0.0.5")
        assert r.status_code == 200
        body = r.json()
        assert body["reputation"]["is_malicious"] is False
        assert body["reputation"]["reputation_score"] == 0.0
        assert body["geo"]["country"] == "Internal"

    def test_lookup_unknown_ip(self, client):
        r = client.get("/api/v1/intel/ip/8.8.8.8")
        assert r.status_code == 200
        body = r.json()
        assert body["ip"] == "8.8.8.8"
        assert body["reputation"]["is_malicious"] is False
        assert body["summary"]["feed_hits"] == 0


# ===========================================================================
# Health reflects pipeline run counts (must run before purge deletes events)
# ===========================================================================

class TestHealthAfterRun:
    def test_health_reflects_run(self, client):
        r = client.get("/api/v1/health")
        body = r.json()
        assert body["total_events"] >= 5
        assert body["total_alerts"] >= 1
        assert body["total_runs"] >= 1

    def test_status_top_risk_hosts(self, client):
        r = client.get("/api/v1/status")
        body = r.json()
        hosts = body["top_risk_hosts"]
        assert len(hosts) >= 1
        host = hosts[0]
        assert "target" in host
        assert "score" in host
        assert "label" in host


# ===========================================================================
# Purge (must run last — aggressive windows may delete test event data)
# ===========================================================================

class TestPurge:
    def test_purge_no_old_events(self, client):
        """90-day window keeps recent events — deleted count depends on payload timestamps."""
        r = client.post("/api/v1/pipeline/purge", json={"days": 90})
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body["deleted_events"], int)
        assert body["retention_days"] == 90

    def test_purge_aggressive_window(self, client):
        """1-day retention request succeeds regardless of how many events it removes."""
        r = client.post("/api/v1/pipeline/purge", json={"days": 1})
        assert r.status_code == 200
        body = r.json()
        assert body["retention_days"] == 1
        assert isinstance(body["deleted_events"], int)

    def test_purge_invalid_days(self, client):
        r = client.post("/api/v1/pipeline/purge", json={"days": 0})
        assert r.status_code == 422

    def test_purge_too_many_days(self, client):
        r = client.post("/api/v1/pipeline/purge", json={"days": 9999})
        assert r.status_code == 422


# ===========================================================================
# API key authentication (SENTINEL_API_KEY enabled)
# ===========================================================================

_TEST_KEY = "sentinel-test-key-abc123"


@pytest.fixture(scope="class")
def authed_client():
    """TestClient with SENTINEL_API_KEY set — auth is enforced."""
    from config.settings import get_settings
    os.environ["SENTINEL_API_KEY"] = _TEST_KEY
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as c:
            yield c
    finally:
        del os.environ["SENTINEL_API_KEY"]
        get_settings.cache_clear()


class TestApiKeyAuth:
    def test_health_requires_no_key(self, authed_client):
        """Health endpoint is exempt from auth — monitoring must not be gated."""
        r = authed_client.get("/api/v1/health")
        assert r.status_code == 200

    def test_data_endpoint_without_key_returns_401(self, authed_client):
        r = authed_client.get("/api/v1/events")
        assert r.status_code == 401

    def test_data_endpoint_wrong_key_returns_401(self, authed_client):
        r = authed_client.get("/api/v1/events", headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 401

    def test_data_endpoint_correct_key_returns_200(self, authed_client):
        r = authed_client.get("/api/v1/events", headers={"X-API-Key": _TEST_KEY})
        assert r.status_code == 200

    def test_alerts_requires_key(self, authed_client):
        r = authed_client.get("/api/v1/alerts")
        assert r.status_code == 401

    def test_alerts_with_key_returns_200(self, authed_client):
        r = authed_client.get("/api/v1/alerts", headers={"X-API-Key": _TEST_KEY})
        assert r.status_code == 200

    def test_scores_requires_key(self, authed_client):
        r = authed_client.get("/api/v1/scores/hosts")
        assert r.status_code == 401

    def test_pipeline_run_requires_key(self, authed_client):
        r = authed_client.post("/api/v1/pipeline/run", json={"nra": [], "winlog": [], "mock": []})
        assert r.status_code == 401

    def test_pipeline_run_with_key_succeeds(self, authed_client):
        r = authed_client.post(
            "/api/v1/pipeline/run",
            json={"mock": [{"timestamp": "2026-05-09T02:00:00Z", "src_ip": "1.2.3.4",
                            "dst_ip": "10.0.0.5", "event_type": "port_scan", "severity": "low"}]},
            headers={"X-API-Key": _TEST_KEY},
        )
        assert r.status_code == 200

    def test_intel_requires_key(self, authed_client):
        r = authed_client.get("/api/v1/intel/ip/8.8.8.8")
        assert r.status_code == 401

    def test_intel_with_key_returns_200(self, authed_client):
        r = authed_client.get("/api/v1/intel/ip/8.8.8.8", headers={"X-API-Key": _TEST_KEY})
        assert r.status_code == 200
