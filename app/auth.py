from datetime import datetime
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .key_utils import hash_api_key
from .metrics import record_auth_failure
from .storage import APIKey, get_db


@dataclass(frozen=True)
class AuthContext:
    raw_key: str
    org_id: Optional[str]


async def require_api_key(
    x_governs_key: Optional[str] = Header(None, alias="X-Governs-Key"),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Validate API key by comparing HMAC hash — never stores or compares plaintext.

    Returns AuthContext(raw_key, org_id) so downstream handlers can route
    decisions to the correct org without re-querying the api_keys table.
    """
    if not x_governs_key:
        record_auth_failure("missing_api_key")
        raise HTTPException(status_code=401, detail="missing api key")

    key_hash = hash_api_key(x_governs_key)
    record = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()

    if record is None or not record.is_active:
        record_auth_failure("invalid_api_key")
        raise HTTPException(status_code=401, detail="invalid api key")

    if record.expires_at is not None and record.expires_at < datetime.utcnow():
        record_auth_failure("expired_api_key")
        raise HTTPException(status_code=401, detail="api key expired")

    return AuthContext(raw_key=x_governs_key, org_id=record.org_id)
