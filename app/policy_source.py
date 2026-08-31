"""Org-scoped policy source — reads from the dashboard's `Policy` table.

See ADR-005 (knowledge/ADR/005-policy-source-of-truth.md) for the design.

Public surface:
    get_active_policy(org_id: str) -> dict | None
    invalidate(org_id: str) -> None
    cache_stats() -> dict   # for diagnostics / metrics

The returned policy dict has the shape that `evaluate_with_payload_policy`
already understands (precheck/app/policies.py), so the evaluator does not
need to learn a new format — we just translate at the edge.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from .storage import DashboardPolicy, SessionLocal

logger = logging.getLogger(__name__)


def _ttl_seconds() -> int:
    raw = os.environ.get("POLICY_CACHE_TTL_S", "60")
    try:
        return max(1, int(raw))
    except ValueError:
        return 60


@dataclass(frozen=True)
class _CacheEntry:
    policy: Optional[dict]
    fetched_at: float


_cache: dict[str, _CacheEntry] = {}
_cache_lock = threading.RLock()
_metrics = {"hit": 0, "miss": 0, "invalidate": 0}


# ──────────────────────────────────────────────────────────────────────
# Shape translation: dashboard Policy row → precheck PolicyConfig dict
# ──────────────────────────────────────────────────────────────────────
# The dashboard stores `defaults` as a free-form JSON. The convention we
# enforce in v1 is `{"pii": "<action>"}` where action ∈
# {"redact", "block", "tokenize", "allow"}. The evaluator wants the precheck
# shape `defaults[direction]["action"]` with action ∈
# {"deny", "redact", "tokenize", "pass_through"}.
_PII_ACTION_MAP = {
    "redact": "redact",
    "block": "deny",
    "deny": "deny",
    "tokenize": "tokenize",
    "pass": "pass_through",
    "pass_through": "pass_through",
    "allow": "pass_through",
}


def _map_row_to_policy_config(row: DashboardPolicy) -> dict:
    """Translate a DashboardPolicy row into a precheck PolicyConfig dict.

    The output shape is consumed verbatim by `evaluate_with_payload_policy`
    (precheck/app/policies.py). Unknown keys in `row.defaults` are preserved
    verbatim so future extensions don't need to touch this function.
    """
    # Annotated Any rather than Dict[str, Any]: `row.defaults` is a SQLAlchemy
    # Column[Any] at type-check time, so a concrete dict annotation conflicts
    # with the assignment even though the runtime value is a dict.
    raw_defaults: Any = row.defaults or {}

    # Translate the v1 convention; default to "redact" if the field is absent.
    pii_action_in = str(raw_defaults.get("pii", "redact")).lower()
    pii_action = _PII_ACTION_MAP.get(pii_action_in, "redact")

    return {
        "version": row.version or "v1",
        "defaults": {
            "ingress": {"action": pii_action},
            "egress": {"action": pii_action},
            # Forward any non-pii defaults verbatim for forward-compat.
            **{k: v for k, v in raw_defaults.items() if k != "pii"},
        },
        "tool_access": row.tool_access or {},
        "deny_tools": row.deny_tools or [],
        "allow_tools": row.allow_tools or [],
        "network_scopes": row.network_scopes or [],
        "network_tools": row.network_tools or [],
        "on_error": row.on_error or "block",
        # Provenance — useful in logs and audit, ignored by the evaluator.
        "_policy_id": row.id,
        "_policy_name": row.name,
        "_priority": row.priority,
    }


# ──────────────────────────────────────────────────────────────────────
# DB read
# ──────────────────────────────────────────────────────────────────────
def _fetch_from_db(org_id: str) -> Optional[dict]:
    db: Session = SessionLocal()
    try:
        row = (
            db.query(DashboardPolicy)
            .filter(
                DashboardPolicy.org_id == org_id,
                DashboardPolicy.is_active.is_(True),
            )
            .order_by(
                DashboardPolicy.priority.desc(), DashboardPolicy.updated_at.desc()
            )
            .first()
        )
        if row is None:
            return None
        return _map_row_to_policy_config(row)
    except Exception as exc:
        # Don't blow up the request path on a DB hiccup — let the caller fall
        # back to the YAML policy. Logged loudly so it's visible in audits.
        logger.warning("policy_source: db fetch failed for org=%s err=%s", org_id, exc)
        return None
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────
def get_active_policy(org_id: Optional[str]) -> Optional[dict]:
    """Return the highest-priority active policy for `org_id`, or None.

    None means "no row in DB" — the caller should fall back to the YAML
    default policy (preserving today's behavior for orgs without a
    dashboard-managed policy).
    """
    if not org_id:
        return None

    now = time.monotonic()
    ttl = _ttl_seconds()

    with _cache_lock:
        entry = _cache.get(org_id)
        if entry is not None and (now - entry.fetched_at) < ttl:
            _metrics["hit"] += 1
            return entry.policy

    # Cache miss — fetch outside the lock to avoid holding it across IO.
    fetched = _fetch_from_db(org_id)

    with _cache_lock:
        _cache[org_id] = _CacheEntry(policy=fetched, fetched_at=time.monotonic())
        _metrics["miss"] += 1

    return fetched


def invalidate(org_id: Optional[str]) -> None:
    """Drop the cached entry for org_id. No-op if missing or org_id is empty.

    Called from the dashboard's invalidation webhook on policy writes
    (see ADR-005 §Write/invalidate path).
    """
    if not org_id:
        return
    with _cache_lock:
        _cache.pop(org_id, None)
        _metrics["invalidate"] += 1


def cache_stats() -> dict:
    """Return cache hit/miss/invalidate counts and current entry count."""
    with _cache_lock:
        return {**_metrics, "entries": len(_cache)}


def _clear_for_tests() -> None:
    """Test-only helper — clears the cache and resets counters."""
    with _cache_lock:
        _cache.clear()
        for k in _metrics:
            _metrics[k] = 0
