"""Tests for notifications/webhook.py — WebhookNotifier."""

from __future__ import annotations

import json
import sys
import os
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notifications.webhook import WebhookNotifier, WebhookError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(alert_type="WINLOG-001", confidence=0.9, src_ip="1.2.3.4", severity="high"):
    return {
        "alert_type": alert_type,
        "confidence": confidence,
        "src_ip":     src_ip,
        "severity":   severity,
        "mitre_tactic": "credential-access",
        "details":    {"mitre_technique": "T1110"},
        "description": "Brute force detected",
    }


def _mock_urlopen(status=200):
    resp = mock.MagicMock()
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__  = mock.MagicMock(return_value=False)
    return mock.patch("urllib.request.urlopen", return_value=resp)


# ---------------------------------------------------------------------------
# notify() — basic behaviour
# ---------------------------------------------------------------------------

def test_notify_sends_high_confidence_alert():
    with _mock_urlopen() as mock_open:
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.7)
        result   = notifier.notify([_alert(confidence=0.9)], run_id="run-1")

    assert result["sent"] == 1
    assert result["skipped"] == 0
    mock_open.assert_called_once()


def test_notify_skips_low_confidence_alert():
    with _mock_urlopen() as mock_open:
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.7)
        result   = notifier.notify([_alert(confidence=0.5)], run_id="run-1")

    assert result["sent"] == 0
    assert result["skipped"] == 1
    mock_open.assert_not_called()


def test_notify_skips_alert_exactly_below_floor():
    with _mock_urlopen() as mock_open:
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.7)
        result   = notifier.notify([_alert(confidence=0.699)], run_id="run-1")

    assert result["sent"] == 0


def test_notify_sends_alert_exactly_at_floor():
    with _mock_urlopen():
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.7)
        result   = notifier.notify([_alert(confidence=0.7)], run_id="run-1")

    assert result["sent"] == 1


def test_notify_disabled_when_url_empty():
    notifier = WebhookNotifier(url="")
    result   = notifier.notify([_alert(confidence=0.99)], run_id="run-1")

    assert result["sent"]    == 0
    assert result["skipped"] == 1


def test_notify_empty_alerts_returns_zero():
    notifier = WebhookNotifier(url="http://webhook.example/hook")
    result   = notifier.notify([], run_id="run-1")

    assert result["sent"]    == 0
    assert result["skipped"] == 0


def test_notify_multiple_alerts_mixed_confidence():
    alerts = [
        _alert(confidence=0.95),  # sent
        _alert(confidence=0.40),  # skipped
        _alert(confidence=0.80),  # sent
        _alert(confidence=0.10),  # skipped
    ]
    with _mock_urlopen():
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.7)
        result   = notifier.notify(alerts, run_id="run-1")

    assert result["sent"]    == 2
    assert result["skipped"] == 2


# ---------------------------------------------------------------------------
# Payload structure
# ---------------------------------------------------------------------------

def test_payload_contains_required_fields():
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["body"] = json.loads(req.data.decode())
        resp = mock.MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__  = mock.MagicMock(return_value=False)
        return resp

    notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)
    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        notifier.notify([_alert()], run_id="run-abc")

    payload = captured["body"]
    assert payload["run_id"]      == "run-abc"
    assert payload["alert_type"]  == "WINLOG-001"
    assert payload["confidence"]  == 0.9
    assert payload["src_ip"]      == "1.2.3.4"
    assert payload["severity"]    == "high"
    assert payload["mitre_tactic"]    == "credential-access"
    assert payload["mitre_technique"] == "T1110"
    assert "timestamp" in payload


def test_payload_uses_correct_content_type():
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["headers"] = dict(req.headers)
        resp = mock.MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__  = mock.MagicMock(return_value=False)
        return resp

    notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)
    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        notifier.notify([_alert()], run_id="run-1")

    assert captured["headers"].get("Content-type") == "application/json"


def test_payload_src_ip_falls_back_to_initial_src_ip():
    alert = {
        "alert_type":    "WINLOG-002",
        "confidence":    0.9,
        "initial_src_ip": "5.5.5.5",
        "severity":      "high",
        "details":       {},
    }
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["body"] = json.loads(req.data.decode())
        resp = mock.MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__  = mock.MagicMock(return_value=False)
        return resp

    notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)
    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        notifier.notify([alert], run_id="run-1")

    assert captured["body"]["src_ip"] == "5.5.5.5"


# ---------------------------------------------------------------------------
# Network failure handling
# ---------------------------------------------------------------------------

def test_network_error_raises_webhook_error():
    import urllib.error
    notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)
    with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        try:
            notifier._post({"test": True})
            assert False, "should raise"
        except WebhookError as exc:
            assert "failed" in str(exc).lower()


def test_http_4xx_raises_webhook_error():
    with _mock_urlopen(status=404):
        notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)
        try:
            notifier._post({"test": True})
            assert False, "should raise"
        except WebhookError as exc:
            assert "404" in str(exc)


def test_notify_continues_after_single_failure():
    """A failed send on one alert should not prevent sending the next."""
    import urllib.error
    call_count = {"n": 0}

    def flaky_urlopen(req, timeout=5):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise urllib.error.URLError("timeout")
        resp = mock.MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__  = mock.MagicMock(return_value=False)
        return resp

    alerts = [_alert(confidence=0.9), _alert(confidence=0.95)]
    notifier = WebhookNotifier(url="http://webhook.example/hook", confidence_floor=0.0)

    # Should not raise even though first call fails
    try:
        with mock.patch("urllib.request.urlopen", side_effect=flaky_urlopen):
            notifier.notify(alerts, run_id="run-1")
    except Exception:
        assert False, "notify() should not raise on network failure"


# ---------------------------------------------------------------------------
# Orchestrator integration
# ---------------------------------------------------------------------------

def test_orchestrator_calls_webhook_when_configured():
    """_notify_webhook appends webhook trace entry when URL is set."""
    import core.pipeline.orchestrator as orch_mod
    from core.pipeline.orchestrator import PipelineOrchestrator

    fake_result = {
        "alerts": [_alert(confidence=0.9)],
        "report": {"json": {"run_id": "run-xyz"}},
    }
    trace = []

    with mock.patch("config.settings.settings") as s:
        s.webhook_url              = "http://webhook.example/hook"
        s.webhook_confidence_floor = 0.7
        s.intel_timeout            = 5
        with mock.patch("notifications.webhook.WebhookNotifier.notify", return_value={"sent": 1, "skipped": 0}):
            PipelineOrchestrator()._notify_webhook(fake_result, trace)

    assert trace[-1]["stage"]  == "webhook"
    assert trace[-1]["status"] == "ok"
    assert trace[-1]["sent"]   == 1


def test_orchestrator_skips_webhook_when_url_empty():
    from core.pipeline.orchestrator import PipelineOrchestrator

    fake_result = {"alerts": [_alert()], "report": {"json": {"run_id": "run-1"}}}
    trace = []

    with mock.patch("config.settings.settings") as s:
        s.webhook_url = ""
        PipelineOrchestrator()._notify_webhook(fake_result, trace)

    assert trace == []


def test_orchestrator_webhook_failure_does_not_raise():
    from core.pipeline.orchestrator import PipelineOrchestrator

    fake_result = {"alerts": [_alert()], "report": {"json": {"run_id": "run-1"}}}
    trace = []

    with mock.patch("config.settings.settings") as s:
        s.webhook_url              = "http://webhook.example/hook"
        s.webhook_confidence_floor = 0.7
        s.intel_timeout            = 5
        with mock.patch("notifications.webhook.WebhookNotifier.notify", side_effect=Exception("boom")):
            PipelineOrchestrator()._notify_webhook(fake_result, trace)

    assert trace[-1]["stage"]  == "webhook"
    assert trace[-1]["status"] == "error"
