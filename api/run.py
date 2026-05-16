"""
api/run.py — Config-driven Uvicorn entrypoint.

Reads all server settings from config.settings and starts Uvicorn.
Use this instead of a bare uvicorn CLI call when you want the settings
module (env vars / .env file) to control host, port, workers, and log level.

Usage:
    python -m api.run
    SENTINEL_PORT=9000 SENTINEL_ENV=production python -m api.run
"""

from __future__ import annotations

import uvicorn

from config.settings import get_settings


def main() -> None:
    cfg = get_settings()
    uvicorn.run(
        "api.app:app",
        host=cfg.host,
        port=cfg.port,
        workers=cfg.workers,
        log_level=cfg.log_level,
        reload=cfg.debug,  # auto-reload only in debug mode
    )


if __name__ == "__main__":
    main()
