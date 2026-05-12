import json
import logging
import threading
import time
from types import ModuleType
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from .settings import settings

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from redis import Redis
else:  # pragma: no cover - runtime-only fallback for optional typing
    Redis = Any

_redis_module: Optional[ModuleType] = None
imported_redis_module: Optional[ModuleType]

try:
    import redis as imported_redis_module
except Exception:  # pragma: no cover - exercised in environments without redis package
    imported_redis_module = None

_redis_module = imported_redis_module
redis: Optional[ModuleType] = _redis_module


class AllowDecisionCache:
    """Redis-first cache for cacheable allow decisions."""

    def __init__(self, redis_url: Optional[str] = None, ttl_seconds: int = 60):
        self.redis_client: Optional[Redis] = None
        self.ttl_seconds = max(0, int(ttl_seconds))
        self._local_lock = threading.Lock()
        self._local_store: Dict[str, Tuple[float, str]] = {}
        self._cleanup_interval = 60.0
        self._last_cleanup = 0.0

        if redis_url and redis is not None:
            try:
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()
            except Exception as exc:
                logger.warning(
                    "Failed to connect to Redis for allow-decision cache: %s",
                    type(exc).__name__,
                )
                self.redis_client = None
        elif redis_url and redis is None:
            logger.warning(
                "redis package not installed; using in-memory allow-decision cache"
            )

    def get(self, key: str) -> Optional[Dict]:
        if self.ttl_seconds <= 0:
            return None

        if self.redis_client:
            try:
                return self._get_redis(key)
            except Exception as exc:
                logger.warning(
                    "Redis allow-decision cache unavailable; falling back to in-memory cache: %s",
                    type(exc).__name__,
                )

        return self._get_local(key)

    def set(self, key: str, value: Dict) -> None:
        if self.ttl_seconds <= 0:
            return

        payload = json.dumps(value)

        if self.redis_client:
            try:
                self.redis_client.setex(key, self.ttl_seconds, payload)
                return
            except Exception as exc:
                logger.warning(
                    "Redis allow-decision cache unavailable; falling back to in-memory cache: %s",
                    type(exc).__name__,
                )

        self._set_local(key, payload)

    def clear(self) -> None:
        with self._local_lock:
            self._local_store.clear()
            self._last_cleanup = 0.0

    def _get_redis(self, key: str) -> Optional[Dict]:
        client = self.redis_client
        if client is None:
            return None

        payload = client.get(key)
        if payload is None:
            return None

        if isinstance(payload, bytes):
            payload_text = payload.decode("utf-8")
        elif isinstance(payload, bytearray):
            payload_text = bytes(payload).decode("utf-8")
        elif isinstance(payload, str):
            payload_text = payload
        else:
            logger.warning(
                "Unexpected allow-decision cache payload type from Redis: %s",
                type(payload).__name__,
            )
            return None

        return json.loads(payload_text)

    def _get_local(self, key: str) -> Optional[Dict]:
        current_time = time.time()
        with self._local_lock:
            self._cleanup_local_state(current_time)
            item = self._local_store.get(key)
            if item is None:
                return None

            expires_at, payload = item
            if expires_at <= current_time:
                self._local_store.pop(key, None)
                return None

            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                self._local_store.pop(key, None)
                return None

    def _set_local(self, key: str, payload: str) -> None:
        current_time = time.time()
        expires_at = current_time + self.ttl_seconds
        with self._local_lock:
            self._cleanup_local_state(current_time)
            self._local_store[key] = (expires_at, payload)

    def _cleanup_local_state(self, current_time: float) -> None:
        if current_time - self._last_cleanup < self._cleanup_interval:
            return

        expired_keys = [
            key
            for key, (expires_at, _payload) in self._local_store.items()
            if expires_at <= current_time
        ]
        for key in expired_keys:
            self._local_store.pop(key, None)

        self._last_cleanup = current_time


allow_decision_cache = AllowDecisionCache(
    settings.redis_url, settings.precheck_allow_cache_ttl_seconds
)
