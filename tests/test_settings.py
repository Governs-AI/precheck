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
