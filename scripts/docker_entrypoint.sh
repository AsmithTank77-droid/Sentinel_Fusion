#!/bin/sh
# docker_entrypoint.sh — seeds the database on first boot, then starts uvicorn.
set -e

echo "==> Sentinel Fusion starting..."

# Seed the database if it's empty (first boot only)
python /app/scripts/docker_seed.py

echo "==> Starting API server on ${SENTINEL_HOST}:${SENTINEL_PORT}"
exec uvicorn api.app:app \
    --host "${SENTINEL_HOST}" \
    --port "${SENTINEL_PORT}" \
    --log-level "${SENTINEL_LOG_LEVEL}" \
    --workers "${SENTINEL_WORKERS}"
