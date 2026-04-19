import hashlib
import hmac
import os
import secrets

_KEY_HMAC_SECRET = os.environ.get("KEY_HMAC_SECRET", "").encode()


def _hmac_secret() -> bytes:
    if not _KEY_HMAC_SECRET:
        raise RuntimeError("KEY_HMAC_SECRET environment variable is required")
    return _KEY_HMAC_SECRET


def hash_api_key(raw_key: str) -> str:
    """Return HMAC-SHA256 hex digest of raw_key. Store this — never the raw key."""
    return hmac.new(_hmac_secret(), raw_key.encode(), hashlib.sha256).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return (raw_key, key_hash, key_prefix). Return raw_key to user once; store hash."""
    raw_key = "GAI_" + secrets.token_urlsafe(32)
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:8]
    return raw_key, key_hash, key_prefix


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
