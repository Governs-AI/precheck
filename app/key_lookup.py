"""Resolve an incoming X-Governs-Key to its org.

Two kinds of key exist:

* Dashboard keys (`gai_…`, `gov_key_…`) live in the dashboard's `APIKey`
  table as a SHA-256 hash. That row is authoritative: when the dashboard
  deactivates, rotates or expires a key, precheck sees it on the next request.
* Precheck's own keys (`GAI_…`, from /v1/keys/rotate) live in `api_keys` as an
  HMAC with KEY_HMAC_SECRET.

Neither table ever holds a plaintext key.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .key_utils import hash_api_key
from .storage import APIKey, DashboardAPIKey

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class KeyRecord:
    org_id: Optional[str]
    user_id: Optional[str]
    is_active: bool
    expires_at: Optional[datetime]
    source: str  # "dashboard" | "precheck"

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < datetime.utcnow()

    @property
    def usable(self) -> bool:
        return self.is_active and not self.expired


def dashboard_key_hash(raw_key: str) -> str:
    """The dashboard's stored form of a key (apps/platform/lib/api-keys.ts)."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def find_key(db: Session, raw_key: str) -> Optional[KeyRecord]:
    """Look `raw_key` up in the dashboard's table first, then precheck's."""
    row: Any
    try:
        row = (
            db.query(DashboardAPIKey)
            .filter(DashboardAPIKey.key_hash == dashboard_key_hash(raw_key))
            .first()
        )
    except SQLAlchemyError as exc:
        # No dashboard table (precheck deployed on its own) or a DB hiccup.
        # Roll back so the session is usable for the precheck-table query.
        db.rollback()
        logger.debug("dashboard APIKey lookup failed: %s", type(exc).__name__)
        row = None
    if row is not None:
        return KeyRecord(
            org_id=row.org_id,
            user_id=row.user_id,
            is_active=bool(row.is_active),
            expires_at=row.expires_at,
            source="dashboard",
        )

    record: Any = (
        db.query(APIKey).filter(APIKey.key_hash == hash_api_key(raw_key)).first()
    )
    if record is None:
        return None
    return KeyRecord(
        org_id=record.org_id,
        user_id=record.user_id,
        is_active=bool(record.is_active),
        expires_at=record.expires_at,
        source="precheck",
    )
