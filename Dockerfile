# ──────────────────────────────────────────────────────────────────────────────
# Sentinel Fusion — Production Dockerfile
# Multi-stage build: keeps the final image lean (no build tools, no test deps).
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install only what pip needs to compile wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ─────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="Sentinel Fusion"
LABEL description="SOC-grade detection and correlation engine"

# Non-root user for security
RUN groupadd --system sentinel && useradd --system --gid sentinel sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Persistent volume mount point for SQLite database
RUN mkdir -p /app/data && chown sentinel:sentinel /app/data

USER sentinel

# ── Environment defaults (override via docker-compose or -e flags) ─────────────
ENV SENTINEL_DB=/app/data/sentinel.db \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8000 \
    SENTINEL_LOG_LEVEL=info \
    SENTINEL_ENV=production \
    SENTINEL_WORKERS=1

EXPOSE 8000

# Healthcheck — polls the /api/v1/health endpoint every 30 seconds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" \
    || exit 1

CMD ["sh", "-c", \
     "uvicorn api.app:app \
      --host $SENTINEL_HOST \
      --port $SENTINEL_PORT \
      --log-level $SENTINEL_LOG_LEVEL \
      --workers $SENTINEL_WORKERS"]
