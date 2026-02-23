from pydantic_settings import BaseSettings
from pydantic import model_validator
from typing import Optional

_DEFAULT_SALT = "default-salt-change-in-production"
_DEFAULT_WEBHOOK_SECRET = "dev-secret"


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Server configuration
    app_bind: str = "0.0.0.0:8080"
    debug: bool = False

    # Database configuration
    db_url: str = "sqlite:///./local.db"

    # Redis configuration (optional)
    redis_url: Optional[str] = None

    # Public base URL for cloud mode
    public_base: Optional[str] = None

    # Presidio configuration
    use_presidio: bool = True
    presidio_model: str = "en_core_web_sm"  # sm, md, lg

    # API configuration
    api_key_header: str = "X-Governs-Key"

    # Webhook configuration
    webhook_url: Optional[str] = None
    webhook_secret: str = _DEFAULT_WEBHOOK_SECRET
    precheck_dlq: str = "/tmp/precheck.dlq.jsonl"
    webhook_timeout_s: float = 2.5
    webhook_max_retries: int = 3
    webhook_backoff_base_ms: int = 150

    # PII tokenization — REQUIRED in production; must not be the default value
    pii_token_salt: str = _DEFAULT_SALT

    # Error handling behavior
    on_error: str = "block"  # block | pass | best_effort

    # Policy file configuration
    policy_file: str = "policy.tool_access.yaml"

    @model_validator(mode="after")
    def _reject_default_secrets(self) -> "Settings":
        if not self.debug:
            if self.pii_token_salt == _DEFAULT_SALT:
                raise ValueError(
                    "PII_TOKEN_SALT must be set to a unique, high-entropy value in production. "
                    "Refusing to start with the default salt."
                )
            if self.webhook_secret == _DEFAULT_WEBHOOK_SECRET:
                raise ValueError(
                    "WEBHOOK_SECRET must be set to a strong random value in production. "
                    "Refusing to start with the default 'dev-secret'."
                )
        return self

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()
