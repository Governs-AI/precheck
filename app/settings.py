from typing import Optional
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings

_DEFAULT_SALT = "dev-pii-token-salt-change-in-production"
_DEFAULT_WEBHOOK_SECRET = "dev-webhook-secret-change-in-production"
_DEFAULT_KEY_HMAC_SECRET = "dev-key-hmac-secret-change-in-production"
_MIN_SECRET_LENGTH = 32

# Allowed values for RATE_LIMIT_FAIL_MODE.
# - "closed": deny (HTTP 503) when Redis is configured but unreachable. Safe
#   default in multi-replica deployments — a per-replica local fallback would
#   multiply the effective quota by N replicas (Cipher review on precheck#31).
# - "open":   allow without a counter check. Operator must explicitly accept
#   the quota-bypass risk.
# - "local":  per-replica in-memory fallback. Intended for single-replica dev.
_RATE_LIMIT_FAIL_MODES = {"closed", "open", "local"}


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Server configuration
    app_bind: str = "0.0.0.0:8080"
    debug: bool = False

    # Database configuration
    db_url: str = Field(
        default="sqlite:///./local.db",
        validation_alias=AliasChoices("DB_URL", "DATABASE_URL"),
    )

    # Redis configuration (optional).
    # In non-debug environments REDIS_URL must use the TLS scheme (rediss://)
    # and carry a password; see _validate_redis_url_posture below.
    redis_url: Optional[str] = None
    precheck_allow_cache_ttl_seconds: int = 60

    # Rate limiter behavior on Redis outage. See _RATE_LIMIT_FAIL_MODES.
    # Default is "closed" (fail-closed 503) to avoid the per-replica quota-
    # bypass described in the Cipher review on precheck#31. Operators running
    # a single replica in development may set this to "local".
    rate_limit_fail_mode: str = "closed"

    # Default per-minute limits. These are baselines used by the rate-limit
    # middleware when no policy override is supplied. Policy-driven overrides
    # land in §1.5d.
    rate_limit_requests_per_minute: int = 100
    rate_limit_tokens_per_minute: int = 100_000
    rate_limit_org_requests_per_minute: int = 1_000
    rate_limit_org_tokens_per_minute: int = 1_000_000

    # Public base URL for cloud mode
    public_base: Optional[str] = None

    # Presidio configuration
    use_presidio: bool = True
    presidio_model: str = "en_core_web_sm"  # sm, md, lg

    # API configuration — demo_api_key intentionally removed; all keys must live in DB
    api_key_header: str = "X-Governs-Key"
    key_hmac_secret: str = _DEFAULT_KEY_HMAC_SECRET

    # Webhook configuration
    # Base URL of the dashboard websocket gateway (e.g. wss://host/ws/gateway).
    # Per-request connection URLs are built by appending ?org=...&key=...&channels=org:<id>:decisions
    # in app.events. Single-tenant WEBHOOK_URL is gone — see GOV-13.
    webhook_base_url: Optional[str] = None
    # Connection-level API key the dashboard uses to authenticate the precheck
    # service itself when opening the websocket (separate from per-request keys).
    webhook_conn_key: Optional[str] = None
    webhook_secret: str = _DEFAULT_WEBHOOK_SECRET
    precheck_dlq: str = "/tmp/precheck.dlq.jsonl"
    webhook_timeout_s: float = 2.5
    webhook_max_retries: int = 3
    webhook_backoff_base_ms: int = 150

    # PII tokenization — REQUIRED in production; must not be the default value.
    # WARNING: any PII tokens previously generated with the default salt are
    # cryptographically weak and must be re-tokenised after rotating this value.
    pii_token_salt: str = _DEFAULT_SALT

    # Error handling behavior
    on_error: str = "block"  # block | pass | best_effort

    # Policy file configuration
    policy_file: str = "policy.tool_access.yaml"

    @model_validator(mode="after")
    def _reject_default_secrets(self) -> "Settings":
        if self.rate_limit_fail_mode not in _RATE_LIMIT_FAIL_MODES:
            raise ValueError(
                f"RATE_LIMIT_FAIL_MODE must be one of {sorted(_RATE_LIMIT_FAIL_MODES)}; "
                f"got {self.rate_limit_fail_mode!r}."
            )
        if not self.debug:
            self._validate_secret(
                name="PII_TOKEN_SALT",
                value=self.pii_token_salt,
                default_marker=_DEFAULT_SALT,
            )
            self._validate_secret(
                name="WEBHOOK_SECRET",
                value=self.webhook_secret,
                default_marker=_DEFAULT_WEBHOOK_SECRET,
            )
            self._validate_secret(
                name="KEY_HMAC_SECRET",
                value=self.key_hmac_secret,
                default_marker=_DEFAULT_KEY_HMAC_SECRET,
            )
            self._validate_redis_url_posture()
            if self.rate_limit_fail_mode == "local":
                raise ValueError(
                    "RATE_LIMIT_FAIL_MODE=local is only permitted in debug mode; "
                    "across multiple replicas the per-replica in-memory counter "
                    "multiplies the effective quota by N. Use 'closed' (default) "
                    "or explicitly opt into 'open'."
                )
        return self

    def _validate_redis_url_posture(self) -> None:
        """Reject plaintext or passwordless REDIS_URL outside debug mode.

        Rate-limit counters, the allow-decision cache, and any future queue
        traffic flow through this URL. Plaintext redis:// exposes API-key
        fingerprints and quota state on the wire; an unauthenticated Redis
        allows any pod in the namespace to read or poison the same counters.
        Both are rejected in non-debug environments.
        """
        if not self.redis_url:
            return
        parsed = urlsplit(self.redis_url)
        if parsed.scheme != "rediss":
            raise ValueError(
                "REDIS_URL must use the rediss:// (TLS) scheme outside debug mode; "
                f"got scheme {parsed.scheme!r}."
            )
        if not parsed.password:
            raise ValueError(
                "REDIS_URL must include a password outside debug mode; "
                "unauthenticated Redis lets any co-tenant read or poison rate-limit counters."
            )

    @staticmethod
    def _validate_secret(name: str, value: str, default_marker: str) -> None:
        if not value:
            raise ValueError(f"{name} must be non-empty in production.")
        if len(value) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"{name} must be at least {_MIN_SECRET_LENGTH} characters in production."
            )
        if value == default_marker:
            raise ValueError(
                f"{name} must be replaced with a unique, high-entropy value in production."
            )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
settings = Settings()
