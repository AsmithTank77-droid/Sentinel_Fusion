"""Tests for siem/elastic_forwarder.py."""

from __future__ import annotations

import json
import sys
import os
import urllib.error
import unittest.mock as mock
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.elastic_forwarder import ElasticForwarder, ElasticForwardError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bulk_ok_response(n_items: int) -> bytes:
    items = [{"index": {"_index": "sentinel-alerts-2026.06.08", "_id": str(i), "status": 201}} for i in range(n_items)]
    return json.dumps({"took": 10, "errors": False, "items": items}).encode()


def _bulk_error_response() -> bytes:
    items = [{"index": {"_index": "sentinel-alerts-2026.06.08", "status": 400, "error": {"type": "mapper_exception", "reason": "bad field"}}}]
    return json.dumps({"took": 5, "errors": True, "items": items}).encode()


def _pipeline_result(alerts=None, scores=None, hunt_findings=None) -> dict:
    return {
        "event_count":    3,
        "alerts":         alerts or [{"alert_type": "brute_force", "confidence": 0.9, "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1"}],
        "scores":         scores or {"host_risk": {"10.0.0.1": {"score": 7.5, "label": "high"}}},
        "hunt_findings":  hunt_findings or [],
        "report":         {"json": {"run_id": "test-run-123"}, "markdown": ""},
        "timeline":       [],
        "normalized_events": [],
        "trace":          [],
    }


# ---------------------------------------------------------------------------
# forward() — document counts
# ---------------------------------------------------------------------------

def test_forward_indexes_alerts_scores_and_run_summary():
    result = _pipeline_result(
        alerts=[
            {"alert_type": "brute_force", "confidence": 0.9},
            {"alert_type": "lateral_movement", "confidence": 0.8},
        ],
        scores={"host_risk": {"10.0.0.1": {"score": 7.5, "label": "high"}, "10.0.0.2": {"score": 3.0, "label": "low"}}},
        hunt_findings=[{"hunt_type": "beacon", "hunt_confidence": 0.7}],
    )
    # 2 alerts + 2 scores + 1 hunt + 1 run summary = 6 docs
    expected_docs = 6

    resp = mock.MagicMock()
    resp.read.return_value = _bulk_ok_response(expected_docs)
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        forwarder = ElasticForwarder()
        out = forwarder.forward(result, run_id="test-run-123")

    assert out["indexed"] == expected_docs
    assert out["errors"] == 0
    assert len(out["indices"]) == 4  # alerts, scores, hunt, runs


def test_forward_with_no_hunt_findings_still_sends_run_summary():
    result = _pipeline_result(hunt_findings=[])
    # 1 alert + 1 score + 0 hunt + 1 run = 3 docs
    resp = mock.MagicMock()
    resp.read.return_value = _bulk_ok_response(3)
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        out = ElasticForwarder().forward(result)

    assert out["indexed"] == 3
    assert "sentinel-runs" in " ".join(out["indices"])


def test_forward_counts_bulk_errors():
    result = _pipeline_result()
    resp = mock.MagicMock()
    resp.read.return_value = _bulk_error_response()
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        out = ElasticForwarder().forward(result)

    assert out["errors"] == 1


# ---------------------------------------------------------------------------
# forward() — index naming
# ---------------------------------------------------------------------------

def test_forward_uses_correct_index_prefix():
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["body"] = req.data.decode()
        resp = mock.MagicMock()
        resp.read.return_value = _bulk_ok_response(3)
        resp.__enter__ = lambda s: s
        resp.__exit__ = mock.MagicMock(return_value=False)
        return resp

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        ElasticForwarder(index_prefix="myorg").forward(_pipeline_result())

    assert "myorg-alerts-" in captured["body"]
    assert "myorg-scores-" in captured["body"]
    assert "myorg-runs-" in captured["body"]


def test_forward_run_id_included_in_all_docs():
    captured_body = {}

    def fake_urlopen(req, timeout=5):
        captured_body["data"] = req.data.decode()
        resp = mock.MagicMock()
        resp.read.return_value = _bulk_ok_response(3)
        resp.__enter__ = lambda s: s
        resp.__exit__ = mock.MagicMock(return_value=False)
        return resp

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        ElasticForwarder().forward(_pipeline_result(), run_id="run-abc")

    lines = [l for l in captured_body["data"].strip().split("\n") if not l.startswith('{"index"')]
    docs = [json.loads(l) for l in lines]
    assert all(d.get("run_id") == "run-abc" for d in docs)


# ---------------------------------------------------------------------------
# forward() — auth headers
# ---------------------------------------------------------------------------

def test_api_key_sent_as_authorization_header():
    captured_headers = {}

    def fake_urlopen(req, timeout=5):
        captured_headers.update(dict(req.headers))
        resp = mock.MagicMock()
        resp.read.return_value = _bulk_ok_response(3)
        resp.__enter__ = lambda s: s
        resp.__exit__ = mock.MagicMock(return_value=False)
        return resp

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        ElasticForwarder(api_key="my-key-123").forward(_pipeline_result())

    assert captured_headers.get("Authorization") == "ApiKey my-key-123"


def test_no_api_key_sends_no_auth_header():
    captured_headers = {}

    def fake_urlopen(req, timeout=5):
        captured_headers.update(dict(req.headers))
        resp = mock.MagicMock()
        resp.read.return_value = _bulk_ok_response(3)
        resp.__enter__ = lambda s: s
        resp.__exit__ = mock.MagicMock(return_value=False)
        return resp

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        ElasticForwarder(api_key="").forward(_pipeline_result())

    assert "Authorization" not in captured_headers


# ---------------------------------------------------------------------------
# Error handling — network failures raise ElasticForwardError
# ---------------------------------------------------------------------------

def test_raises_on_http_error():
    with mock.patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        url="http://localhost:9200/_bulk", code=503, msg="Service Unavailable", hdrs={}, fp=None
    )):
        try:
            ElasticForwarder().forward(_pipeline_result())
            assert False, "should have raised"
        except ElasticForwardError as exc:
            assert "503" in str(exc)


def test_raises_on_url_error():
    with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        try:
            ElasticForwarder().forward(_pipeline_result())
            assert False, "should have raised"
        except ElasticForwardError as exc:
            assert "Connection refused" in str(exc)


def test_raises_on_invalid_json_response():
    resp = mock.MagicMock()
    resp.read.return_value = b"not json"
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        try:
            ElasticForwarder().forward(_pipeline_result())
            assert False, "should have raised"
        except ElasticForwardError as exc:
            assert "JSON" in str(exc)


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------

def test_health_check_returns_true_on_green():
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps({"status": "green"}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        assert ElasticForwarder().health_check() is True


def test_health_check_returns_true_on_yellow():
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps({"status": "yellow"}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        assert ElasticForwarder().health_check() is True


def test_health_check_returns_false_on_red():
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps({"status": "red"}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=resp):
        assert ElasticForwarder().health_check() is False


def test_health_check_returns_false_on_network_error():
    with mock.patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        assert ElasticForwarder().health_check() is False
