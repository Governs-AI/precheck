"""Minute-bucket sliding-window rate limiter.

Counter shape (per §1.5c):
  - ``req:key:{key_id}:{minute_bucket}``
  - ``tokens:key:{key_id}:{minute_bucket}``
  - ``req:org:{org_id}:{minute_bucket}``
  - ``tokens:org:{org_id}:{minute_bucket}``

Each minute bucket is an atomic Redis counter with a two-minute TTL so the
previous bucket is still visible for the sliding-window weight.

Sliding-window weight (Cloudflare-style):

    weighted = prev_count * (1 - elapsed_in_current / 60) + current_count

Request is denied when ``weighted + cost > limit`` for any dimension.

Redis-outage behavior is controlled by ``fail_mode`` (Cipher review on
precheck#31). See ``RateLimiter.__init__`` for semantics.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .settings import settings

logger = logging.getLogger(__name__)

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


WINDOW_SECONDS = 60
_BUCKET_TTL_SECONDS = WINDOW_SECONDS * 2


@dataclass(frozen=True)
class LimitSpec:
    """One rate-limit dimension to evaluate on this request."""

    name: str  # e.g. "req-key", "req-org", "tokens-key", "tokens-org"
    key: str   # Redis key prefix, e.g. "req:key:<hash>" (bucket appended at runtime)
    limit: int
    cost: int  # 1 for request counters, token count for token counters


@dataclass(frozen=True)
class LimitState:
    limit: int
    remaining: int
    reset_in: int   # seconds until the current minute bucket ends
    retry_after: int  # seconds until a request of this cost would be permitted


class LimiterUnavailableError(RuntimeError):
    """Raised (internally) when Redis is configured but unreachable and the
    operator has not opted into a fallback mode. Middleware translates this
    into a 503 response."""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    states: Dict[str, LimitState]
    # Populated when the operator's fail-mode requires a 503 instead of 429.
    fail_closed_reason: Optional[str] = None


class RateLimiter:
    """Redis-backed minute-bucket rate limiter with explicit outage behavior.

    ``fail_mode``:
      * ``"closed"`` — Redis configured but unreachable returns a
        ``fail_closed_reason`` so the middleware can reply ``503``. This is
        the safe default under multi-replica deployments where a per-replica
        local fallback would multiply the effective quota by N replicas.
      * ``"open"``   — Redis unreachable → allow the request with no counter
        check. Opt-in only.
      * ``"local"``  — Redis unreachable → fall back to a per-replica in-memory
        counter. Intended for single-replica dev setups; rejected by
        ``Settings`` outside debug mode.

    When ``REDIS_URL`` was never configured (development/tests), the limiter
    always runs against local in-memory buckets regardless of ``fail_mode``.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        fail_mode: str = "closed",
    ):
        if fail_mode not in {"closed", "open", "local"}:
            raise ValueError(f"invalid rate_limit_fail_mode: {fail_mode!r}")
        self.fail_mode = fail_mode
        self._redis_url_configured = bool(redis_url)
        self.redis_client = None
        self._local_lock = threading.Lock()
        # Map of "<spec.key>:<bucket>" -> count for the in-memory fallback.
        self._local_buckets: Dict[str, int] = {}

        if redis_url and redis is not None:
            try:
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()
            except Exception as exc:
                logger.warning(
                    "Failed to connect to Redis for rate limiter: %s",
                    type(exc).__name__,
                )
                self.redis_client = None
        elif redis_url and redis is None:
            logger.warning(
                "redis package not installed; rate limiter degraded to in-memory mode"
            )

    # ---------------------------------------------------------------- public

    def check(self, specs: Sequence[LimitSpec]) -> RateLimitResult:
        """Evaluate all dimensions and increment counters on allow."""
        if not specs:
            return RateLimitResult(allowed=True, states={})

        now = time.time()
        bucket = int(now // WINDOW_SECONDS)
        elapsed_in_current = now - bucket * WINDOW_SECONDS

        if self._use_local():
            return self._check_local(specs, bucket, elapsed_in_current)

        if self.redis_client is None:
            return self._handle_unavailable(specs, reason="redis-not-connected")

        try:
            return self._check_redis(specs, bucket, elapsed_in_current)
        except Exception as exc:
            logger.warning(
                "Redis rate limiter request failed: %s", type(exc).__name__
            )
            return self._handle_unavailable(
                specs, reason=f"redis-error:{type(exc).__name__}"
            )

    def clear(self) -> None:
        """Clear in-memory state. Intended for tests only."""
        with self._local_lock:
            self._local_buckets.clear()

    # ------------------------------------------------------- internal helpers

    def _use_local(self) -> bool:
        """Run purely in local mode when no Redis URL was ever configured."""
        return not self._redis_url_configured

    def _handle_unavailable(
        self, specs: Sequence[LimitSpec], reason: str
    ) -> RateLimitResult:
        if self.fail_mode == "open":
            # Operator opted into quota-bypass on Redis outage.
            return RateLimitResult(
                allowed=True,
                states={s.name: self._unknown_state(s) for s in specs},
            )
        if self.fail_mode == "local":
            now = time.time()
            bucket = int(now // WINDOW_SECONDS)
            elapsed_in_current = now - bucket * WINDOW_SECONDS
            return self._check_local(specs, bucket, elapsed_in_current)
        # fail_mode == "closed" — caller translates this to HTTP 503.
        return RateLimitResult(
            allowed=False,
            states={s.name: self._unknown_state(s) for s in specs},
            fail_closed_reason=reason,
        )

    @staticmethod
    def _unknown_state(spec: LimitSpec) -> LimitState:
        return LimitState(
            limit=spec.limit, remaining=spec.limit, reset_in=WINDOW_SECONDS, retry_after=0
        )

    # ---------------------------------------------------------------- Redis

    def _check_redis(
        self,
        specs: Sequence[LimitSpec],
        bucket: int,
        elapsed_in_current: float,
    ) -> RateLimitResult:
        client = self.redis_client
        assert client is not None  # guarded by caller

        current_keys = [f"{s.key}:{bucket}" for s in specs]
        previous_keys = [f"{s.key}:{bucket - 1}" for s in specs]

        pipe = client.pipeline()
        for k in current_keys:
            pipe.get(k)
        for k in previous_keys:
            pipe.get(k)
        raw = pipe.execute()

        current_counts = [self._parse(v) for v in raw[: len(specs)]]
        previous_counts = [self._parse(v) for v in raw[len(specs) :]]

        allowed = True
        states: Dict[str, LimitState] = {}
        for spec, curr, prev in zip(specs, current_counts, previous_counts):
            weighted_before = _weighted(prev, curr, elapsed_in_current)
            # Would this request fit under the limit?
            projected = weighted_before + spec.cost
            state = _state_for(spec, curr, prev, elapsed_in_current, projected)
            states[spec.name] = state
            if projected > spec.limit:
                allowed = False

        if allowed:
            # Atomically increment and refresh TTL on the current bucket only.
            pipe = client.pipeline()
            for key, spec in zip(current_keys, specs):
                pipe.incrby(key, spec.cost)
                pipe.expire(key, _BUCKET_TTL_SECONDS)
            pipe.execute()

        return RateLimitResult(allowed=allowed, states=states)

    @staticmethod
    def _parse(raw) -> int:
        if raw is None:
            return 0
        if isinstance(raw, (bytes, bytearray)):
            try:
                return int(raw)
            except ValueError:
                return 0
        if isinstance(raw, int):
            return raw
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    # ------------------------------------------------------------- in-memory

    def _check_local(
        self,
        specs: Sequence[LimitSpec],
        bucket: int,
        elapsed_in_current: float,
    ) -> RateLimitResult:
        with self._local_lock:
            self._gc_local(bucket)
            allowed = True
            observations: List[Tuple[LimitSpec, int, int]] = []
            for spec in specs:
                curr = self._local_buckets.get(f"{spec.key}:{bucket}", 0)
                prev = self._local_buckets.get(f"{spec.key}:{bucket - 1}", 0)
                observations.append((spec, curr, prev))
                weighted_before = _weighted(prev, curr, elapsed_in_current)
                if weighted_before + spec.cost > spec.limit:
                    allowed = False

            states: Dict[str, LimitState] = {}
            for spec, curr, prev in observations:
                weighted_before = _weighted(prev, curr, elapsed_in_current)
                projected = weighted_before + spec.cost
                states[spec.name] = _state_for(
                    spec, curr, prev, elapsed_in_current, projected
                )

            if allowed:
                for spec, _curr, _prev in observations:
                    k = f"{spec.key}:{bucket}"
                    self._local_buckets[k] = self._local_buckets.get(k, 0) + spec.cost

        return RateLimitResult(allowed=allowed, states=states)

    def _gc_local(self, bucket: int) -> None:
        """Drop buckets older than the previous one."""
        stale = [
            k
            for k in self._local_buckets
            if int(k.rsplit(":", 1)[1]) < bucket - 1
        ]
        for k in stale:
            self._local_buckets.pop(k, None)


# ---------------------------------------------------------------- helpers


def _weighted(prev: int, current: int, elapsed_in_current: float) -> float:
    """Sliding-window count over the current 60-second window."""
    if elapsed_in_current >= WINDOW_SECONDS:
        return float(current)
    ratio = 1.0 - (elapsed_in_current / WINDOW_SECONDS)
    return prev * ratio + current


def _state_for(
    spec: LimitSpec,
    current: int,
    previous: int,
    elapsed_in_current: float,
    projected: float,
) -> LimitState:
    """Compute the LimitState returned to callers for this dimension.

    ``remaining`` is reported against the sliding window *after* admitting
    this request. When the request would be denied, ``retry_after`` is the
    number of seconds until the oldest contributing request ages out enough
    for ``projected <= limit`` to hold.
    """
    reset_in = max(1, int(math.ceil(WINDOW_SECONDS - elapsed_in_current)))
    remaining = max(0, int(math.floor(spec.limit - projected)))

    if projected <= spec.limit:
        return LimitState(
            limit=spec.limit,
            remaining=remaining,
            reset_in=reset_in,
            retry_after=0,
        )

    # Denied: figure out when the sliding weight drops enough to admit
    # ``spec.cost`` again.
    #
    #   weighted(t) = previous * (1 - (elapsed + t) / 60) + current + cost
    #   solve weighted(t) <= limit for t:
    #
    if previous > 0:
        # t such that previous * (1 - (elapsed + t)/60) + current + cost <= limit
        # => previous * (elapsed + t) / 60 >= previous + current + cost - limit
        # => t >= 60 * (previous + current + cost - limit) / previous - elapsed
        required = (previous + current + spec.cost - spec.limit) * WINDOW_SECONDS
        t = required / previous - elapsed_in_current
        retry_after = max(1, int(math.ceil(t)))
        # Capped at reset_in: after the current bucket ends the previous one
        # is gone entirely.
        retry_after = min(retry_after, reset_in)
    else:
        # previous is zero → only the current bucket contributes; we must
        # wait for it to roll.
        retry_after = reset_in

    return LimitState(
        limit=spec.limit,
        remaining=0,
        reset_in=reset_in,
        retry_after=retry_after,
    )


# ---------------------------------------------------------------- default specs


def specs_for_request(
    key_id: str,
    org_id: Optional[str],
    token_cost: int,
) -> List[LimitSpec]:
    """Build the standard four-dimension spec list for a single request.

    ``key_id`` and ``org_id`` are opaque identifiers (typically HMAC hashes of
    the raw API key, and the org UUID). Token cost should be a positive int;
    the caller is responsible for the estimation policy.
    """
    token_cost = max(1, int(token_cost))
    out: List[LimitSpec] = [
        LimitSpec(
            name="req-key",
            key=f"req:key:{key_id}",
            limit=settings.rate_limit_requests_per_minute,
            cost=1,
        ),
        LimitSpec(
            name="tokens-key",
            key=f"tokens:key:{key_id}",
            limit=settings.rate_limit_tokens_per_minute,
            cost=token_cost,
        ),
    ]
    if org_id:
        out.extend(
            [
                LimitSpec(
                    name="req-org",
                    key=f"req:org:{org_id}",
                    limit=settings.rate_limit_org_requests_per_minute,
                    cost=1,
                ),
                LimitSpec(
                    name="tokens-org",
                    key=f"tokens:org:{org_id}",
                    limit=settings.rate_limit_org_tokens_per_minute,
                    cost=token_cost,
                ),
            ]
        )
    return out


# ---------------------------------------------------------------- singleton

rate_limiter = RateLimiter(
    redis_url=settings.redis_url,
    fail_mode=settings.rate_limit_fail_mode,
)
