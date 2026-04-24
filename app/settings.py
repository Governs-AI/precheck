from pydantic import AliasChoices, Field, model_validator
from typing import Optional

from pydantic_settings import BaseSettings

_DEFAULT_SALT = "dev-pii-token-salt-change-in-production"
_DEFAULT_WEBHOOK_SECRET = "dev-webhook-secret-change-in-production"
_DEFAULT_KEY_HMAC_SECRET = "dev-key-hmac-secret-change-in-production"
_MIN_SECRET_LENGTH = 32


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

    # Redis configuration (optional)
    redis_url: Optional[str] = None

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
        return self

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
