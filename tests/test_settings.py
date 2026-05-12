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
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("RATE_LIMIT_FAIL_MODE", raising=False)


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


# --------------------------------------------------------- REDIS_URL posture


def test_settings_reject_plaintext_redis_url_outside_debug(monkeypatch):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv("REDIS_URL", "redis://:secret@redis.internal:6379/0")

    with pytest.raises(ValueError, match="REDIS_URL.*rediss"):
        Settings(_env_file=None)


def test_settings_reject_passwordless_redis_url_outside_debug(monkeypatch):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv("REDIS_URL", "rediss://redis.internal:6379/0")

    with pytest.raises(ValueError, match="REDIS_URL.*password"):
        Settings(_env_file=None)


def test_settings_accept_tls_password_redis_url_outside_debug(monkeypatch):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv("REDIS_URL", "rediss://:secret@redis.internal:6379/0")

    s = Settings(_env_file=None)

    assert s.redis_url == "rediss://:secret@redis.internal:6379/0"


def test_settings_accept_plaintext_redis_url_in_debug(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./debug.db")
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    s = Settings(_env_file=None)

    assert s.redis_url == "redis://localhost:6379/0"


def test_settings_accept_unset_redis_url(monkeypatch):
    """REDIS_URL may be omitted entirely; the posture validator only applies
    when a URL is configured."""
    _set_non_debug_safe_env(monkeypatch)

    s = Settings(_env_file=None)

    assert s.redis_url is None


# --------------------------------------------------- RATE_LIMIT_FAIL_MODE


def test_settings_reject_invalid_fail_mode(monkeypatch):
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "teapot")

    with pytest.raises(ValueError, match="RATE_LIMIT_FAIL_MODE"):
        Settings(_env_file=None)


def test_settings_reject_local_fail_mode_outside_debug(monkeypatch):
    """`local` multiplies the effective quota by N replicas — reject outside
    debug mode (Cipher review on precheck#31)."""
    _set_non_debug_safe_env(monkeypatch)
    monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "local")

    with pytest.raises(ValueError, match="RATE_LIMIT_FAIL_MODE=local"):
        Settings(_env_file=None)


def test_settings_accept_local_fail_mode_in_debug(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./debug.db")
    monkeypatch.delenv("DB_URL", raising=False)
    monkeypatch.setenv("RATE_LIMIT_FAIL_MODE", "local")

    s = Settings(_env_file=None)

    assert s.rate_limit_fail_mode == "local"


def test_settings_default_fail_mode_is_closed(monkeypatch):
    _set_non_debug_safe_env(monkeypatch)

    s = Settings(_env_file=None)

    assert s.rate_limit_fail_mode == "closed"
