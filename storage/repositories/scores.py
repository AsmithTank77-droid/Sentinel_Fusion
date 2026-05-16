"""
storage/repositories/scores.py — ScoreRepository.

Persists risk scores from each pipeline run and provides
historical score trending per host.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from storage.database import Database
from storage.models import StoredScore


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScoreRepository:
    """Read/write access to the scores table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def store_run_scores(self, scores: dict, run_id: str) -> int:
        """
        Persist all scores from a pipeline run.

        Expects the orchestrator scores dict:
        {
            "host_risk":      {host_ip: {risk_score, risk_label, ...}},
            "asset_risk":     {host_ip: {exposure_score, exposure_label, ...}},
            "attack_surface": {expansion_score, expansion_label, ...},
        }

        Returns count of rows written.
        """
        now   = _now()
        count = 0

        host_risk = scores.get("host_risk") or {}
        for target, data in host_risk.items():
            self._db.execute(
                """
                INSERT INTO scores
                    (run_id, score_type, target, score, label, details, scored_at)
                VALUES (?, 'host_risk', ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target,
                    float(data.get("risk_score", 0.0)),
                    data.get("risk_label", "unknown"),
                    json.dumps(data),
                    now,
                ),
            )
            count += 1

        asset_risk = scores.get("asset_risk") or {}
        for target, data in asset_risk.items():
            self._db.execute(
                """
                INSERT INTO scores
                    (run_id, score_type, target, score, label, details, scored_at)
                VALUES (?, 'asset_risk', ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target,
                    float(data.get("exposure_score", 0.0)),
                    data.get("exposure_label", "unknown"),
                    json.dumps(data),
                    now,
                ),
            )
            count += 1

        atk_surface = scores.get("attack_surface") or {}
        if atk_surface:
            self._db.execute(
                """
                INSERT INTO scores
                    (run_id, score_type, target, score, label, details, scored_at)
                VALUES (?, 'attack_surface', '__global__', ?, ?, ?, ?)
                """,
                (
                    run_id,
                    float(atk_surface.get("expansion_score", 0.0)),
                    atk_surface.get("expansion_label", "unknown"),
                    json.dumps(atk_surface),
                    now,
                ),
            )
            count += 1

        return count

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_latest_host_scores(self) -> list[StoredScore]:
        """Return the most recent host_risk score for each target."""
        rows = self._db.query(
            """
            SELECT s.*
            FROM   scores s
            INNER JOIN (
                SELECT target, MAX(scored_at) AS latest
                FROM   scores
                WHERE  score_type = 'host_risk'
                GROUP  BY target
            ) latest ON s.target = latest.target AND s.scored_at = latest.latest
            WHERE s.score_type = 'host_risk'
            ORDER BY s.score DESC
            """
        )
        return [self._row_to_model(r) for r in rows]

    def get_host_history(self, target: str, limit: int = 30) -> list[StoredScore]:
        """Return score history for a specific host, newest first."""
        rows = self._db.query(
            """
            SELECT * FROM scores
            WHERE score_type = 'host_risk' AND target = ?
            ORDER BY scored_at DESC LIMIT ?
            """,
            (target, limit),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_run(self, run_id: str) -> list[StoredScore]:
        rows = self._db.query(
            "SELECT * FROM scores WHERE run_id = ? ORDER BY score_type, score DESC",
            (run_id,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_attack_surface_history(self, limit: int = 30) -> list[StoredScore]:
        rows = self._db.query(
            """
            SELECT * FROM scores
            WHERE score_type = 'attack_surface'
            ORDER BY scored_at DESC LIMIT ?
            """,
            (limit,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_highest_risk_hosts(self, limit: int = 10) -> list[StoredScore]:
        """Return the most recent score for each host, sorted by risk descending."""
        rows = self._db.query(
            """
            SELECT s.*
            FROM   scores s
            INNER JOIN (
                SELECT target, MAX(scored_at) AS latest
                FROM   scores WHERE score_type = 'host_risk'
                GROUP  BY target
            ) latest ON s.target = latest.target AND s.scored_at = latest.latest
            WHERE s.score_type = 'host_risk'
            ORDER BY s.score DESC LIMIT ?
            """,
            (limit,),
        )
        return [self._row_to_model(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_model(row) -> StoredScore:
        return StoredScore(
            id=row["id"],
            run_id=row["run_id"],
            score_type=row["score_type"],
            target=row["target"],
            score=row["score"],
            label=row["label"],
            details=json.loads(row["details"] or "{}"),
            scored_at=row["scored_at"],
        )
