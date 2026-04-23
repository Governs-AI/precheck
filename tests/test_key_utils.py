import hashlib
import hmac

import pytest

from app.key_utils import hash_api_key
from app.settings import settings


def test_hash_api_key_reads_secret_from_settings_at_call_time(monkeypatch):
    raw_key = "GAI_test_key_for_lazy_secret_lookup"

    monkeypatch.setattr(settings, "key_hmac_secret", "")
    with pytest.raises(RuntimeError, match="KEY_HMAC_SECRET"):
        hash_api_key(raw_key)

    monkeypatch.setattr(settings, "key_hmac_secret", "late-loaded-secret")

    expected = hmac.new(
        b"late-loaded-secret", raw_key.encode(), hashlib.sha256
    ).hexdigest()

    assert hash_api_key(raw_key) == expected
