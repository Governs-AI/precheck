import pytest

from app.settings import Settings


def test_settings_accept_db_url(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DB_URL", "sqlite:///./db-url.db")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    settings = Settings(_env_file=None)

    assert settings.db_url == "sqlite:///./db-url.db"


def test_settings_accept_database_url(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./database-url.db")
    monkeypatch.delenv("DB_URL", raising=False)

    settings = Settings(_env_file=None)

    assert settings.db_url == "sqlite:///./database-url.db"


def _set_non_debug_safe_env(monkeypatch):
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./prod-safe.db")
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.setenv("WEBHOOK_SECRET", "w" * 32)
    monkeypatch.setenv("PII_TOKEN_SALT", "p" * 32)
    monkeypatch.setenv("KEY_HMAC_SECRET", "k" * 32)


@pytest.mark.parametrize(
    ("env_var", "value"),
    [
        ("WEBHOOK_SECRET", "short-secret"),
        ("PII_TOKEN_SALT", "short-salt"),
        ("KEY_HMAC_SECRET", "short-hmac"),
    ],
)
def test_settings_reject_short_non_debug_secrets(monkeypatch, env_var, value):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv(env_var, value)

    with pytest.raises(ValueError, match=env_var):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    ("env_var", "value"),
    [
        ("WEBHOOK_SECRET", "dev-webhook-secret-change-in-production"),
        ("PII_TOKEN_SALT", "dev-pii-token-salt-change-in-production"),
        ("KEY_HMAC_SECRET", "dev-key-hmac-secret-change-in-production"),
    ],
)
def test_settings_reject_default_non_debug_secret_markers(monkeypatch, env_var, value):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv(env_var, value)

    with pytest.raises(ValueError, match=env_var):
        Settings(_env_file=None)
