"""
api/routes/scores.py — Risk score query endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from api.dependencies import Store
from api.schemas.responses import ScoreResponse

router = APIRouter(prefix="/scores", tags=["scores"])


def _score_response(s) -> ScoreResponse:
    return ScoreResponse(
        id=s.id,
        run_id=s.run_id,
        score_type=s.score_type,
        target=s.target,
        score=s.score,
        label=s.label,
        details=s.details,
        scored_at=s.scored_at,
    )


@router.get(
    "/hosts",
    response_model=list[ScoreResponse],
    summary="Latest host risk scores",
)
def list_host_scores(store: Store) -> list[ScoreResponse]:
    """Returns the most recent host_risk score for each tracked host, sorted by score descending."""
    return [_score_response(s) for s in store.scores.get_latest_host_scores()]


@router.get(
    "/hosts/{ip}",
    response_model=list[ScoreResponse],
    summary="Host risk score history",
)
def host_score_history(
    ip: str,
    store: Store,
    limit: int = Query(30, ge=1, le=200, description="Max history entries"),
) -> list[ScoreResponse]:
    """Returns score history for a specific host IP, newest first."""
    return [_score_response(s) for s in store.scores.get_host_history(ip, limit=limit)]


@router.get(
    "/attack-surface",
    response_model=list[ScoreResponse],
    summary="Attack surface expansion history",
)
def attack_surface_history(
    store: Store,
    limit: int = Query(30, ge=1, le=200, description="Max history entries"),
) -> list[ScoreResponse]:
    """Returns global attack surface expansion scores, newest first."""
    return [_score_response(s) for s in store.scores.get_attack_surface_history(limit=limit)]
