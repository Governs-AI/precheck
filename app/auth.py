from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from .storage import get_db, APIKey


async def require_api_key(
    x_governs_key: Optional[str] = Header(None, alias="X-Governs-Key"),
    db: Session = Depends(get_db),
) -> str:
    """Require and validate API key from header against the database."""
    if not x_governs_key:
        raise HTTPException(status_code=401, detail="missing api key")

    record = db.query(APIKey).filter(APIKey.key == x_governs_key).first()

    if record is None or not record.is_active:
        raise HTTPException(status_code=401, detail="invalid api key")

    if record.expires_at is not None and record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="api key expired")

    return x_governs_key
