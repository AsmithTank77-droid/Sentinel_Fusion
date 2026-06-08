"""
notifications/webhook.py — Outbound webhook alerting.

Posts a JSON payload to a configurable URL for every alert whose confidence
meets or exceeds the configured floor. Designed to integrate with Slack
incoming webhooks, PagerDuty Events API, Teams, or any generic HTTP receiver.

Enabled by setting SENTINEL_WEBHOOK_URL. Disabled (no outbound calls) when
the URL is empty. All network failures are caught — a webhook failure never
breaks the pipeline.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone


class WebhookError(Exception):
    """Raised when a webhook POST fails. Caught by the orchestrator."""


class WebhookNotifier:
    """
    Posts alert notifications to a webhook URL.

    Args:
        url:               Webhook endpoint. Empty string disables all sending.
        confidence_floor:  Minimum alert confidence (0–1) required to send.
        timeout:           HTTP request timeout in seconds.
    """

    def __init__(self, url: str, confidence_floor: float = 0.7, timeout: int = 5) -> None:
        self.url              = url
        self.confidence_floor = confidence_floor
        self.timeout          = timeout

    def notify(self, alerts: list[dict], run_id: str = "") -> dict:
        """
        Send a webhook POST for each alert at or above the confidence floor.

        Returns:
            {"sent": int, "skipped": int}
        """
        if not self.url:
            return {"sent": 0, "skipped": len(alerts)}

        sent    = 0
        skipped = 0

        for alert in alerts:
            confidence = float(alert.get("confidence") or 0)
            if confidence < self.confidence_floor:
                skipped += 1
                continue

            payload = self._build_payload(alert, run_id)
            try:
                self._post(payload)
                sent += 1
            except WebhookError:
                skipped += 1

        return {"sent": sent, "skipped": skipped}

    def _build_payload(self, alert: dict, run_id: str) -> dict:
        """Build the JSON payload for a single alert."""
        ctx = alert.get("context") or {}
        return {
            "run_id":         run_id,
            "alert_type":     alert.get("alert_type", ""),
            "confidence":     float(alert.get("confidence") or 0),
            "severity":       alert.get("severity", ""),
            "src_ip":         (
                alert.get("src_ip")
                or alert.get("initial_src_ip")
                or ctx.get("src_ip")
                or ""
            ),
            "dst_ip":         (
                alert.get("dst_ip")
                or alert.get("lateral_target")
                or ctx.get("destination")
                or ""
            ),
            "mitre_tactic":   alert.get("mitre_tactic", ""),
            "mitre_technique": alert.get("details", {}).get("mitre_technique", ""),
            "description":    alert.get("description", ""),
            "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def _post(self, payload: dict) -> None:
        """POST payload as JSON. Raises WebhookError on any failure."""
        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type":   "application/json",
                "User-Agent":     "SentinelFusion/3.0 webhook-notifier",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
        except (urllib.error.URLError, OSError) as exc:
            raise WebhookError(f"POST to {self.url} failed: {exc}") from exc

        if status >= 400:
            raise WebhookError(f"Webhook returned HTTP {status}")
