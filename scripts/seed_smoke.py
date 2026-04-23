"""
One-time script: seeds a smoke-test user + API key on Neon (or any DB).

Run this once against the production Neon DB. The raw key it prints must be
added as GitHub secret SMOKE_API_KEY so CI smoke tests can authenticate.

Usage:
    DB_URL=postgresql://... KEY_HMAC_SECRET=... python scripts/seed_smoke.py

The script is idempotent — safe to re-run. Re-running prints the existing
key_prefix so you can confirm it matches the stored secret.
"""

import os
import sys
from datetime import datetime

# Ensure app package is importable from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

SMOKE_USER_ID = "smoke-test-user"
SMOKE_ORG_ID = "smoke-test-org"


def main() -> None:
    db_url = os.environ.get("DB_URL") or os.environ.get("DATABASE_URL")
    hmac_secret = os.environ.get("KEY_HMAC_SECRET")
    if not db_url:
        sys.exit("DB_URL or DATABASE_URL env var is required")
    if not hmac_secret:
        sys.exit("KEY_HMAC_SECRET env var is required")

    # Patch settings before importing storage so SQLAlchemy uses the right DB
    os.environ["DB_URL"] = db_url
    os.environ["KEY_HMAC_SECRET"] = hmac_secret
    # Disable production secret validators (salt not needed for this script)
    os.environ.setdefault("DEBUG", "true")

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from app.key_utils import generate_api_key
    from app.storage import APIKey, Base, Budget, User

    engine = create_engine(db_url)

    # Migrate api_keys table: add columns that may not exist in older Neon schema
    _migrations = [
        "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix VARCHAR",
        "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS org_id VARCHAR",
        "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP",
        # Rename legacy plaintext key column if it still exists
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns "
        "WHERE table_name='api_keys' AND column_name='key') THEN "
        "ALTER TABLE api_keys RENAME COLUMN key TO _key_legacy; END IF; END $$",
    ]
    with engine.connect() as conn:
        for stmt in _migrations:
            try:
                conn.execute(text(stmt))
            except Exception as e:
                print(f"migration skipped ({e})")
        conn.commit()
        print("schema migration done")

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # User
        user = db.query(User).filter_by(id=SMOKE_USER_ID).first()
        if not user:
            user = User(id=SMOKE_USER_ID, is_active=True, created_at=datetime.utcnow())
            db.add(user)
            print(f"created user: {SMOKE_USER_ID}")
        else:
            print(f"user already exists: {SMOKE_USER_ID}")

        # Budget — needed so precheck doesn't 402 on the smoke request
        budget = db.query(Budget).filter_by(user_id=SMOKE_USER_ID).first()
        if not budget:
            budget = Budget(
                user_id=SMOKE_USER_ID,
                monthly_limit=100.0,
                current_spend=0.0,
                budget_type="user",
                is_active=True,
            )
            db.add(budget)
            print("created budget: $100/month")

        # API key — only create if none exists for this user
        existing = db.query(APIKey).filter_by(user_id=SMOKE_USER_ID).first()
        if existing:
            print(f"\nAPI key already exists — key_prefix: {existing.key_prefix}")
            print("If you need the raw key, revoke this record and re-run.")
        else:
            raw_key, key_hash, key_prefix = generate_api_key()
            api_key = APIKey(
                key_hash=key_hash,
                key_prefix=key_prefix,
                user_id=SMOKE_USER_ID,
                org_id=SMOKE_ORG_ID,
                is_active=True,
                created_at=datetime.utcnow(),
            )
            db.add(api_key)
            db.commit()
            print(f"\n{'='*60}")
            print(f"RAW KEY (add this as GitHub secret SMOKE_API_KEY):")
            print(f"  {raw_key}")
            print(f"key_prefix (for display): {key_prefix}")
            print(f"{'='*60}")
            print("This is the only time the raw key is shown.")
            return

        db.commit()

    finally:
        db.close()


if __name__ == "__main__":
    main()
