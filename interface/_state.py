"""
interface/_state.py — Shared CLI runtime state.

Holds the DB path that the --db flag sets at the top level and all
subcommand files read via get_db(). Avoids threading the db path
through every function signature.
"""

from __future__ import annotations

_db: str | None = None


def set_db(path: str | None) -> None:
    global _db
    _db = path


def get_db() -> str:
    if _db is not None:
        return _db
    from config.settings import settings
    return settings.db
