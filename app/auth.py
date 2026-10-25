from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .key_lookup import find_key
from .metrics import record_auth_failure
from .storage import get_db


@dataclass(frozen=True)
class AuthContext:
    raw_key: str
    org_id: Optional[str]


async def require_api_key(
    x_governs_key: Optional[str] = Header(None, alias="X-Governs-Key"),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Validate the API key by its hash; plaintext is never stored or compared.

    Dashboard keys are checked against the dashboard's `APIKey` table,
    precheck's own keys against `api_keys` (see key_lookup). Returns
    AuthContext(raw_key, org_id) so downstream handlers can route decisions to
    the correct org without another lookup.
    """
    if not x_governs_key:
        record_auth_failure("missing_api_key")
        raise HTTPException(status_code=401, detail="missing api key")

    record = find_key(db, x_governs_key)

    if record is None or not record.is_active:
        record_auth_failure("invalid_api_key")
        raise HTTPException(status_code=401, detail="invalid api key")

    if record.expired:
        record_auth_failure("expired_api_key")
        raise HTTPException(status_code=401, detail="api key expired")

    return AuthContext(raw_key=x_governs_key, org_id=record.org_id)
