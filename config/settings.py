"""
config/settings.py — Platform-wide configuration via environment variables.

All settings have safe defaults for local development.
Override any value by setting the corresponding environment variable
or by placing a .env file in the project root.

Environment variables use the SENTINEL_ prefix:
    SENTINEL_DB=./data/sentinel.db
    SENTINEL_PORT=8000
    SENTINEL_LOG_LEVEL=info
    SENTINEL_RETENTION_DAYS=90
    SENTINEL_ENV=production

Usage:
    from config.settings import settings

    db_path = settings.db
    port    = settings.port
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Sentinel Fusion runtime configuration.

    Loaded once at import time via get_settings() (cached with lru_cache).
    Settings are immutable after startup — change env vars and restart.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    db: str = Field(
        default="sentinel.db",
        description="SQLite database file path. Use :memory: for in-process testing.",
    )

    # ------------------------------------------------------------------
    # API server
    # ------------------------------------------------------------------

    host: str = Field(
        default="0.0.0.0",
        description="Bind address for the Uvicorn server.",
    )

    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="TCP port for the API server.",
    )

    workers: int = Field(
        default=1,
        ge=1,
        le=32,
        description="Number of Uvicorn worker processes.",
    )

    log_level: str = Field(
        default="info",
        description="Uvicorn / application log level: debug, info, warning, error.",
    )

    # ------------------------------------------------------------------
    # Threat intelligence — live API enrichment
    # ------------------------------------------------------------------

    abuseipdb_key: str = Field(
        default="",
        description=(
            "AbuseIPDB API key for live IP reputation lookups. "
            "Empty string disables live lookups (stub data only). "
            "Set SENTINEL_ABUSEIPDB_KEY to enable."
        ),
    )

    geo_enabled: bool = Field(
        default=False,
        description=(
            "Enable live geolocation via ip-api.com (no key required). "
            "Set SENTINEL_GEO_ENABLED=true to enable. "
            "Disabled by default to avoid network calls in tests and airgapped envs."
        ),
    )

    intel_cache_ttl: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="TTL in seconds for cached IP reputation and geo results.",
    )

    intel_timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="HTTP request timeout in seconds for external intelligence APIs.",
    )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    api_key: str = Field(
        default="",
        description=(
            "API key required in the X-API-Key request header. "
            "Empty string disables authentication (development only). "
            "Set SENTINEL_API_KEY to a strong random value in production."
        ),
    )

    # ------------------------------------------------------------------
    # Application behaviour
    # ------------------------------------------------------------------

    env: str = Field(
        default="development",
        description="Runtime environment label: development, staging, production.",
    )

    debug: bool = Field(
        default=False,
        description="Enable FastAPI debug mode (detailed error responses). "
                    "Never enable in production.",
    )

    retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Default event retention window used by the purge endpoint.",
    )

    # ------------------------------------------------------------------
    # Detection thresholds — generic detectors
    # ------------------------------------------------------------------

    brute_force_threshold: int = Field(
        default=3,
        ge=1,
        le=10000,
        description=(
            "Minimum authentication failures from a single src_ip within "
            "brute_force_window seconds before brute_force_detected fires."
        ),
    )

    brute_force_window: int = Field(
        default=300,
        ge=10,
        le=86400,
        description="Sliding window in seconds for generic brute force detection.",
    )

    # ------------------------------------------------------------------
    # Detection thresholds — WINLOG behavioral rules
    # ------------------------------------------------------------------

    winlog_brute_force_threshold: int = Field(
        default=5,
        ge=1,
        le=10000,
        description=(
            "Minimum 4625 failures in winlog_brute_force_window seconds "
            "before WINLOG-001 fires. Increase on high-traffic domain controllers."
        ),
    )

    winlog_brute_force_window: int = Field(
        default=60,
        ge=10,
        le=86400,
        description="Sliding window in seconds for WINLOG-001 (brute force burst).",
    )

    winlog_brute_force_success_window: int = Field(
        default=120,
        ge=10,
        le=86400,
        description=(
            "Max seconds between last 4625 failure and a 4624 success "
            "for WINLOG-002 (brute-force-then-success) to fire."
        ),
    )

    winlog_lateral_window: int = Field(
        default=120,
        ge=10,
        le=86400,
        description=(
            "Max seconds between a 4648 explicit-credential logon and a "
            "type-3 4624 for WINLOG-004 (lateral movement) to fire."
        ),
    )

    winlog_account_backdoor_window: int = Field(
        default=300,
        ge=10,
        le=86400,
        description=(
            "Max seconds between account creation (4720) and group membership "
            "change (4732) for WINLOG-003 (account backdoor) to fire."
        ),
    )

    winlog_privesc_window: int = Field(
        default=30,
        ge=5,
        le=3600,
        description=(
            "Max seconds between a remote logon (4624 type 3/10) and "
            "special privileges (4672) for WINLOG-005 to fire."
        ),
    )

    # ------------------------------------------------------------------
    # Verdict quality
    # ------------------------------------------------------------------

    verdict_confidence_floor: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description=(
            "Minimum alert confidence required for an alert to influence the "
            "executive summary verdict. Alerts below this floor are still "
            "reported but do not escalate the verdict."
        ),
    )

    # ------------------------------------------------------------------
    # Elasticsearch SIEM integration
    # ------------------------------------------------------------------

    elastic_enabled: bool = Field(
        default=False,
        description=(
            "Forward pipeline results to Elasticsearch after each run. "
            "Set SENTINEL_ELASTIC_ENABLED=true to enable."
        ),
    )

    elastic_url: str = Field(
        default="http://localhost:9200",
        description="Elasticsearch base URL. Set SENTINEL_ELASTIC_URL.",
    )

    elastic_api_key: str = Field(
        default="",
        description=(
            "Elasticsearch API key for authentication. "
            "Leave empty for unauthenticated local instances."
        ),
    )

    elastic_index_prefix: str = Field(
        default="sentinel",
        description=(
            "Prefix for Elasticsearch index names. "
            "Indices: {prefix}-alerts, {prefix}-scores, {prefix}-hunt, {prefix}-runs."
        ),
    )

    elastic_timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="HTTP timeout in seconds for Elasticsearch API calls.",
    )

    cors_origins: str = Field(
        default="*",
        description=(
            "Comma-separated CORS allowed origins. "
            "Example: https://app.example.com,https://example.com. "
            "Use * to allow all origins (development only)."
        ),
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, v: str) -> str:
        valid = {"debug", "info", "warning", "error", "critical"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"log_level must be one of {sorted(valid)}")
        return v

    @field_validator("env")
    @classmethod
    def _valid_env(cls, v: str) -> str:
        valid = {"development", "staging", "production"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"env must be one of {sorted(valid)}")
        return v

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse the comma-separated cors_origins string into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def db_path(self) -> Path:
        """Resolved absolute Path to the SQLite file (or :memory: as a string)."""
        if self.db == ":memory:":
            return Path(":memory:")
        return Path(self.db).resolve()

    @property
    def version(self) -> str:
        return "1.0.0"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton Settings instance.

    Cached after first call so env/file is only parsed once per process.
    In tests, call get_settings.cache_clear() after patching env vars.
    """
    return Settings()


# Module-level convenience alias — import this directly in most cases.
settings: Settings = get_settings()
