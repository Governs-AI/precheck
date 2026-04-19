from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from .storage import get_db, APIKey
from .metrics import record_auth_failure
from .key_utils import hash_api_key


async def require_api_key(
    x_governs_key: Optional[str] = Header(None, alias="X-Governs-Key"),
    db: Session = Depends(get_db),
) -> str:
    """Validate API key by comparing HMAC hash — never stores or compares plaintext."""
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

    return x_governs_key
