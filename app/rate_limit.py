import logging
import math
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional

from .settings import settings

logger = logging.getLogger(__name__)

try:
    import redis
except Exception:  # pragma: no cover - exercised in environments without redis package
    redis = None


class RateLimiter:
    """Redis-first sliding-window rate limiter with in-memory fallback."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        self._local_lock = threading.Lock()
        self._local_windows: Dict[str, Deque[float]] = {}
        self._local_last_seen: Dict[str, float] = {}
        self._local_idle_ttl = 3600.0
        self._cleanup_interval = 60.0
        self._last_cleanup = 0.0

        if redis_url and redis is not None:
            try:
                self.redis_client = redis.from_url(redis_url)
                # Test connection
                self.redis_client.ping()
            except Exception as e:
                logger.warning("Failed to connect to Redis: %s", type(e).__name__)
                self.redis_client = None
        elif redis_url and redis is None:
            logger.warning("redis package not installed; using in-memory rate limiter")

    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """
        Check if request is allowed using a sliding window counter.

        Args:
            key: Unique identifier for the rate limit (e.g., user_id)
            limit: Maximum number of requests allowed
            window: Time window in seconds

        Returns:
            True if request is allowed, False otherwise
        """
        if limit <= 0 or window <= 0:
            return False

        if self.redis_client:
            try:
                return self._is_allowed_redis(key=key, limit=limit, window=window)
            except Exception as e:
                logger.warning(
                    "Redis rate limiter unavailable; falling back to in-memory limiter: %s",
                    type(e).__name__,
                )

        return self._is_allowed_local(key=key, limit=limit, window=window)

    def retry_after(self, key: str, limit: int, window: int) -> int:
        """Return seconds until the next request should be allowed."""
        if limit <= 0:
            return max(1, int(math.ceil(window)))
        if window <= 0:
            return 1

        if self.redis_client:
            try:
                return self._retry_after_redis(key=key, limit=limit, window=window)
            except Exception as e:
                logger.warning(
                    "Redis rate limiter unavailable; falling back to in-memory retry-after: %s",
                    type(e).__name__,
                )

        return self._retry_after_local(key=key, limit=limit, window=window)

    def clear(self) -> None:
        """Clear in-memory fallback state."""
        with self._local_lock:
            self._local_windows.clear()
            self._local_last_seen.clear()
            self._last_cleanup = 0.0

    def _is_allowed_redis(self, key: str, limit: int, window: int) -> bool:
        current_time = time.time()
        window_start = current_time - window
        member = f"{current_time}:{time.time_ns()}"

        # Use Redis pipeline for atomic operations.
        pipe = self.redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {member: current_time})
        pipe.expire(key, max(1, int(window)))

        results = pipe.execute()
        current_count = int(results[1])
        return current_count < limit

    def _retry_after_redis(self, key: str, limit: int, window: int) -> int:
        current_time = time.time()
        window_start = current_time - window

        pipe = self.redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        results = pipe.execute()

        current_count = int(results[1])
        if current_count < limit:
            return 0

        next_allowed_index = current_count - limit
        next_allowed = self.redis_client.zrange(
            key,
            next_allowed_index,
            next_allowed_index,
            withscores=True,
        )
        if not next_allowed:
            return 0

        next_allowed_at = float(next_allowed[0][1]) + window
        return max(1, int(math.ceil(next_allowed_at - current_time)))

    def _is_allowed_local(self, key: str, limit: int, window: int) -> bool:
        current_time = time.time()
        window_start = current_time - window

        with self._local_lock:
            self._cleanup_local_state(current_time)
            events = self._local_windows.setdefault(key, deque())

            while events and events[0] <= window_start:
                events.popleft()

            self._local_last_seen[key] = current_time

            if len(events) >= limit:
                return False

            events.append(current_time)
            return True

    def _retry_after_local(self, key: str, limit: int, window: int) -> int:
        current_time = time.time()
        window_start = current_time - window

        with self._local_lock:
            self._cleanup_local_state(current_time)
            events = self._local_windows.get(key)
            if not events:
                return 0

            while events and events[0] <= window_start:
                events.popleft()

            if not events:
                self._local_windows.pop(key, None)
                self._local_last_seen.pop(key, None)
                return 0

            self._local_last_seen[key] = current_time
            if len(events) < limit:
                return 0

            next_allowed_at = events[len(events) - limit] + window
            return max(1, int(math.ceil(next_allowed_at - current_time)))

    def _cleanup_local_state(self, current_time: float) -> None:
        if current_time - self._last_cleanup < self._cleanup_interval:
            return

        expired_keys = [
            key
            for key, last_seen in self._local_last_seen.items()
            if current_time - last_seen > self._local_idle_ttl
        ]
        for expired_key in expired_keys:
            self._local_last_seen.pop(expired_key, None)
            self._local_windows.pop(expired_key, None)

        self._last_cleanup = current_time


# Global rate limiter instance
rate_limiter = RateLimiter(settings.redis_url)
