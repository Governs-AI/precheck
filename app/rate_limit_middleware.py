"""FastAPI middleware: per-key + per-org minute-bucket rate limiting.

Evaluated before route handlers so a flood of invalid-but-well-formed
requests from a single key cannot bypass the limiter by bailing in
``require_api_key``. Unauthenticated paths (``/api/v1/health``,
``/api/v1/ready``, ``/api/metrics``, ``/docs``, ``/openapi.json``, ``/``) are
allowed through without counter interaction so readiness probes and the
metrics scrape cannot be rate-limited or consume quota.

On ``fail_closed_reason`` (Redis configured but unreachable under the
``closed`` fail-mode), the middleware replies with HTTP 503.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Awaitable, Callable, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import SQLAlchemyError

from .key_utils import hash_api_key
from .rate_limit import RateLimitResult, rate_limiter, specs_for_request
from .settings import settings
from .storage import APIKey, SessionLocal

logger = logging.getLogger(__name__)


_UNAUTH_PATHS = frozenset(
    {
        "/",
        "/api/v1/health",
        "/api/v1/ready",
        "/api/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    }
)


def _tokens_estimate(request: Request) -> int:
    """Rough token estimate from Content-Length.

    Real LLM token counts require a tokenizer and the body. For middleware-
    level enforcement we approximate ``ceil(bytes / 4)`` — standard rough
    heuristic for English text — so per-request budget changes show up on the
    token counter before the request reaches the model. Post-response
    reconciliation (§1.5d) can refine this later.
    """
    raw = request.headers.get("content-length")
    if not raw:
        return 1
    try:
        n = int(raw)
    except ValueError:
        return 1
    return max(1, math.ceil(n / 4))


def _lookup_org_id(raw_key: str) -> Optional[str]:
    """Look up the ``org_id`` for ``raw_key``. Returns None if the key is
    unknown — authentication will reject the request downstream."""
    try:
        key_hash = hash_api_key(raw_key)
    except Exception:  # pragma: no cover - defensive
        return None
    session = SessionLocal()
    try:
        record = session.query(APIKey).filter(APIKey.key_hash == key_hash).first()
        if record is None:
            return None
        return record.org_id
    except SQLAlchemyError as exc:
        logger.warning("Rate-limit org lookup failed: %s", type(exc).__name__)
        return None
    finally:
        session.close()


def _apply_headers(response: Response, result: RateLimitResult) -> None:
    if not result.states:
        return
    # Report the most restrictive dimension so clients see the real budget.
    tightest = min(result.states.values(), key=lambda s: s.remaining)
    response.headers["X-RateLimit-Limit"] = str(tightest.limit)
    response.headers["X-RateLimit-Remaining"] = str(tightest.remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + tightest.reset_in)


def _retry_after_for(states) -> int:
    """Seconds until the most lenient denied dimension would admit again."""
    denied = [s.retry_after for s in states.values() if s.retry_after > 0]
    if not denied:
        return 1
    return max(1, min(denied))


def install_rate_limit_middleware(app: FastAPI) -> None:
    """Register the rate-limit middleware on ``app``."""

    @app.middleware("http")
    async def rate_limit_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path in _UNAUTH_PATHS:
            return await call_next(request)

        raw_key = request.headers.get(settings.api_key_header.lower())
        if not raw_key:
            # require_api_key will 401. Don't consume quota on missing auth.
            return await call_next(request)

        key_hash = hash_api_key(raw_key)
        org_id = _lookup_org_id(raw_key)
        token_cost = _tokens_estimate(request)
        specs = specs_for_request(
            key_id=key_hash, org_id=org_id, token_cost=token_cost
        )

        result = rate_limiter.check(specs)

        if result.fail_closed_reason is not None:
            logger.warning(
                "rate limiter unavailable (fail-closed): %s",
                result.fail_closed_reason,
            )
            resp = JSONResponse(
                status_code=503,
                content={"detail": "rate limiter unavailable"},
            )
            resp.headers["Retry-After"] = "1"
            return resp

        if not result.allowed:
            retry_after = _retry_after_for(result.states)
            resp = JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )
            _apply_headers(resp, result)
            return resp

        response = await call_next(request)
        _apply_headers(response, result)
        return response
