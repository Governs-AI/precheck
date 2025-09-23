from fastapi import Header, HTTPException
from typing import Optional
from .settings import settings

async def require_api_key(x_governs_key: Optional[str] = Header(None, alias="X-Governs-Key")):
    """Require and validate API key from header"""
    if not x_governs_key:
        raise HTTPException(status_code=401, detail="missing api key")
    
    # TODO: Look up key in database/cache
    # For MVP, accept demo key from settings
    if x_governs_key != settings.demo_api_key:
        raise HTTPException(status_code=401, detail="invalid api key")
    
    return x_governs_key
