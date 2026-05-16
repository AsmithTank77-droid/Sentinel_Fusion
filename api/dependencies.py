"""
api/dependencies.py — FastAPI dependency injection for shared resources.

Exposes two module-level singletons initialised by the app lifespan:
    StorageLayer      — SQLite persistence facade
    PipelineOrchestrator — stateless 8-stage pipeline runner

Route files import the Annotated type aliases (Store, Orchestrator) for
clean, zero-boilerplate dependency injection via FastAPI's Depends().
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from config.settings import get_settings
from core.pipeline.orchestrator import PipelineOrchestrator
from storage.store import StorageLayer

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    """Reject requests missing a valid X-API-Key header when auth is enabled.

    Auth is disabled when SENTINEL_API_KEY is empty (default for local dev).
    """
    cfg = get_settings()
    if not cfg.api_key:
        return  # auth disabled in this environment
    if api_key != cfg.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Supply X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

_store:        StorageLayer | None        = None
_orchestrator: PipelineOrchestrator | None = None


def init_dependencies(db_path: str = "sentinel.db") -> None:
    """Initialise singletons. Called once during app lifespan startup."""
    global _store, _orchestrator
    _store = StorageLayer(db_path)
    _store.connect()
    _orchestrator = PipelineOrchestrator()


def shutdown_dependencies() -> None:
    """Release resources. Called once during app lifespan shutdown."""
    global _store
    if _store is not None:
        _store.close()
        _store = None


def get_store() -> StorageLayer:
    if _store is None:
        raise RuntimeError("StorageLayer not initialised — app lifespan not running")
    return _store


def get_orchestrator() -> PipelineOrchestrator:
    if _orchestrator is None:
        raise RuntimeError("PipelineOrchestrator not initialised — app lifespan not running")
    return _orchestrator


Store        = Annotated[StorageLayer,         Depends(get_store)]
Orchestrator = Annotated[PipelineOrchestrator, Depends(get_orchestrator)]
