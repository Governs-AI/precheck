#!/usr/bin/env python3
"""
Seed or reactivate a deterministic API key for local/CI test traffic.

Usage:
    KEY_HMAC_SECRET=... python scripts/seed_test_api_key.py \
      --key GAI_ci_load_test_key \
      --user-id load-test-user \
      --org-id load-test-org
"""

import argparse
import json
import os
import sys
from datetime import datetime

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
os.chdir(REPO_ROOT)
sys.path.insert(0, REPO_ROOT)

from sqlalchemy import select

from app.key_utils import hash_api_key
from app.storage import APIKey, SessionLocal, create_tables


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed or reactivate an API key record for local/CI tests."
    )
    parser.add_argument("--key", required=True, help="Raw API key value to seed")
    parser.add_argument("--user-id", required=True, help="User ID to attach")
    parser.add_argument("--org-id", default=None, help="Org ID to attach")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    create_tables()
    session = SessionLocal()

    try:
        key_hash = hash_api_key(args.key)
        record = session.scalar(select(APIKey).where(APIKey.key_hash == key_hash))

        if record is None:
            record = APIKey(
                key_hash=key_hash,
                key_prefix=args.key[:8],
                user_id=args.user_id,
                org_id=args.org_id,
                created_at=datetime.utcnow(),
                is_active=True,
                expires_at=None,
            )
            session.add(record)
            action = "created"
        else:
            record.key_prefix = args.key[:8]
            record.user_id = args.user_id
            record.org_id = args.org_id
            record.is_active = True
            record.expires_at = None
            action = "updated"

        session.commit()
        print(
            json.dumps(
                {
                    "status": action,
                    "key_prefix": record.key_prefix,
                    "user_id": record.user_id,
                    "org_id": record.org_id,
                    "is_active": bool(record.is_active),
                }
            )
        )
    finally:
        session.close()


if __name__ == "__main__":
    main()
