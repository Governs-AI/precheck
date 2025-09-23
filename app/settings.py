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
    next_webhook_url: Optional[str] = None
    precheck_dlq: str = "/tmp/precheck.dlq.jsonl"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Global settings instance
settings = Settings()
