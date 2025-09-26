from pydantic_settings import BaseSettings
from typing import Optional

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
    demo_api_key: str = "GAI_LOCAL_DEV_ABC"
    
    # Webhook configuration
    webhook_url: Optional[str] = None
    webhook_secret: str = "dev-secret"
    precheck_dlq: str = "/tmp/precheck.dlq.jsonl"
    webhook_timeout_s: float = 2.5
    webhook_max_retries: int = 3
    webhook_backoff_base_ms: int = 150
    
    # PII tokenization
    pii_token_salt: str = "default-salt-change-in-production"
    
    # Error handling behavior
    on_error: str = "block"  # block | pass | best_effort
    
    # Policy file configuration
    policy_file: str = "policy.tool_access.yaml"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Global settings instance
settings = Settings()
