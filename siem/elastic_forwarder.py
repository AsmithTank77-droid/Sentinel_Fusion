"""
siem/elastic_forwarder.py — Elasticsearch SIEM integration for Sentinel_Fusion.

Forwards pipeline results (alerts, host scores, hunt findings, run summary)
to Elasticsearch after each pipeline run using the _bulk API.

Stateless. No external dependencies — stdlib urllib only.
Failures are non-fatal: the pipeline result is always returned regardless.

Four rolling daily indices:
    {prefix}-alerts-YYYY.MM.DD       — one doc per alert
    {prefix}-scores-YYYY.MM.DD       — one doc per host risk score
    {prefix}-hunt-YYYY.MM.DD         — one doc per hunt finding
    {prefix}-runs-YYYY.MM.DD         — one doc per pipeline run (summary)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone


class ElasticForwardError(Exception):
    """Raised when forwarding to Elasticsearch fails."""


class ElasticForwarder:
    """
    Forwards Sentinel_Fusion pipeline results to Elasticsearch.

    Usage:
        forwarder = ElasticForwarder(url="http://localhost:9200")
        result = forwarder.forward(pipeline_result, run_id="abc123")
    """

    def __init__(
        self,
        url: str = "http://localhost:9200",
        api_key: str = "",
        index_prefix: str = "sentinel",
        timeout: int = 5,
    ) -> None:
        self._url    = url.rstrip("/")
        self._key    = api_key
        self._prefix = index_prefix
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def forward(self, result: dict, run_id: str = "") -> dict:
        """
        Index a complete pipeline result into Elasticsearch.

        Args:
            result: Full dict returned by PipelineOrchestrator.run().
            run_id: Pipeline run ID for cross-index correlation.

        Returns:
            {"indexed": int, "errors": int, "indices": list[str]}

        Raises:
            ElasticForwardError: on network error or non-2xx response.
        """
        now          = datetime.now(timezone.utc)
        date_suffix  = now.strftime("%Y.%m.%d")
        timestamp    = now.isoformat()

        docs: list[tuple[str, dict]] = []

        # Alerts
        alert_index = f"{self._prefix}-alerts-{date_suffix}"
        for alert in result.get("alerts", []):
            docs.append((alert_index, {
                **alert,
                "@timestamp": timestamp,
                "run_id":     run_id,
                "sentinel_type": "alert",
            }))

        # Host risk scores
        score_index = f"{self._prefix}-scores-{date_suffix}"
        for host_ip, score_data in result.get("scores", {}).get("host_risk", {}).items():
            docs.append((score_index, {
                "host_ip":    host_ip,
                **score_data,
                "@timestamp": timestamp,
                "run_id":     run_id,
                "sentinel_type": "host_score",
            }))

        # Hunt findings
        hunt_index = f"{self._prefix}-hunt-{date_suffix}"
        for finding in result.get("hunt_findings", []):
            docs.append((hunt_index, {
                **finding,
                "@timestamp": timestamp,
                "run_id":     run_id,
                "sentinel_type": "hunt_finding",
            }))

        # Pipeline run summary
        run_index = f"{self._prefix}-runs-{date_suffix}"
        docs.append((run_index, {
            "run_id":            run_id,
            "@timestamp":        timestamp,
            "event_count":       result.get("event_count", 0),
            "alert_count":       len(result.get("alerts", [])),
            "hunt_finding_count": len(result.get("hunt_findings", [])),
            "sentinel_type":     "pipeline_run",
        }))

        return self._bulk_index(docs)

    def health_check(self) -> bool:
        """Return True if Elasticsearch is reachable and cluster status is green/yellow."""
        req = urllib.request.Request(
            f"{self._url}/_cluster/health",
            headers=self._auth_headers(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            return data.get("status") in ("green", "yellow")
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _bulk_index(self, docs: list[tuple[str, dict]]) -> dict:
        """Send all documents via the Elasticsearch _bulk API."""
        lines:   list[str] = []
        indices: set[str]  = set()

        for index_name, doc in docs:
            lines.append(json.dumps({"index": {"_index": index_name}}))
            lines.append(json.dumps(doc, default=str))
            indices.add(index_name)

        body = "\n".join(lines) + "\n"

        headers = {**self._auth_headers(), "Content-Type": "application/x-ndjson"}
        req = urllib.request.Request(
            f"{self._url}/_bulk",
            data=body.encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise ElasticForwardError(
                f"Elasticsearch _bulk returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ElasticForwardError(
                f"Cannot reach Elasticsearch at {self._url}: {exc.reason}"
            ) from exc
        except OSError as exc:
            raise ElasticForwardError(
                f"OS error sending to Elasticsearch: {exc}"
            ) from exc

        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ElasticForwardError(
                f"Invalid JSON from Elasticsearch _bulk: {exc}"
            ) from exc

        errors = sum(
            1
            for item in response.get("items", [])
            if "index" in item and item["index"].get("error")
        )

        return {
            "indexed": len(docs) - errors,
            "errors":  errors,
            "indices": sorted(indices),
        }

    def _auth_headers(self) -> dict[str, str]:
        if self._key:
            return {"Authorization": f"ApiKey {self._key}"}
        return {}
