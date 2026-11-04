"""Org-scoped policy source — reads from the dashboard's `Policy` table.

See ADR-005 (knowledge/ADR/005-policy-source-of-truth.md) for the design.

Public surface:
    get_active_policy(org_id: str) -> dict | None   # raises PolicyStoreUnavailable
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

from .policies import DEFAULT_DENY_TOOLS, is_listed_tool, normalize_action
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
_metrics = {"hit": 0, "miss": 0, "invalidate": 0, "unavailable": 0, "stale": 0}


class PolicyStoreUnavailable(Exception):
    """The policy store could not be read, so the org's policy is unknown.

    Distinct from "the org has no active policy" (None): callers must not
    treat an outage as permission to use a caller-supplied policy.
    """


# ──────────────────────────────────────────────────────────────────────
# Shape translation: dashboard Policy row → precheck PolicyConfig dict
# ──────────────────────────────────────────────────────────────────────
def _direction_action(raw_defaults: Any, direction: str, fallback: str) -> str:
    """Read `defaults[direction].action` (the policy UI's shape), else fallback."""
    entry = raw_defaults.get(direction)
    if isinstance(entry, dict) and entry.get("action"):
        return normalize_action(entry.get("action"), fallback) or fallback
    return fallback


def _normalize_tool_access(tool_access: Any) -> dict:
    """Fold each rule's action and allow_pii values to evaluator vocabulary."""
    if not isinstance(tool_access, dict):
        return {}
    out = {}
    for name, rule in tool_access.items():
        if not isinstance(rule, dict):
            continue
        rule = dict(rule)
        if rule.get("action") is not None:
            rule["action"] = normalize_action(rule.get("action"), "redact")
        rule["direction"] = rule.get("direction") or "both"
        allow_pii = rule.get("allow_pii") or {}
        rule["allow_pii"] = {
            k: normalize_action(v, "redact")
            for k, v in allow_pii.items()
            if isinstance(k, str)
        }
        out[name] = rule
    return out


def _map_row_to_policy_config(row: DashboardPolicy) -> dict:
    """Translate a DashboardPolicy row into a precheck PolicyConfig dict.

    The output shape is consumed verbatim by `evaluate_with_payload_policy`
    (precheck/app/policies.py). Two `defaults` shapes are accepted:
    `{"pii": "<action>"}` (v1 API convention) and
    `{"ingress": {"action": ...}, "egress": {"action": ...}}` (policy UI).
    Actions may use either vocabulary (allow/block or pass_through/deny).
    """
    # Annotated Any rather than Dict[str, Any]: `row.defaults` is a SQLAlchemy
    # Column[Any] at type-check time, so a concrete dict annotation conflicts
    # with the assignment even though the runtime value is a dict.
    raw_defaults: Any = row.defaults or {}

    # The v1 convention sets both directions; default to "redact".
    pii_action = (
        normalize_action(raw_defaults.get("pii", "redact"), "redact") or "redact"
    )

    allow_tools: Any = list(row.allow_tools or [])
    # Code-execution tools stay denied unless the org explicitly allows one.
    deny_tools = [
        t for t in DEFAULT_DENY_TOOLS if not is_listed_tool(t, allow_tools)
    ] + [t for t in list(row.deny_tools or []) if t not in DEFAULT_DENY_TOOLS]

    return {
        "version": row.version or "v1",
        "defaults": {
            # Forward any other defaults verbatim for forward-compat.
            **{
                k: v
                for k, v in raw_defaults.items()
                if k not in ("pii", "ingress", "egress")
            },
            "ingress": {
                "action": _direction_action(raw_defaults, "ingress", pii_action)
            },
            "egress": {"action": _direction_action(raw_defaults, "egress", pii_action)},
        },
        "tool_access": _normalize_tool_access(row.tool_access),
        "deny_tools": deny_tools,
        "allow_tools": allow_tools,
        "network_scopes": row.network_scopes or ["net."],
        "network_tools": row.network_tools or ["web.", "http.", "fetch.", "request."],
        "on_error": row.on_error or "block",
        # Provenance — useful in logs, audit and cache keys; ignored by the evaluator.
        "_policy_id": row.id,
        "_policy_name": row.name,
        "_priority": row.priority,
        "_revision": (
            f"{row.id}:{row.updated_at.isoformat()}" if row.updated_at else row.id
        ),
    }


# ──────────────────────────────────────────────────────────────────────
# DB read
# ──────────────────────────────────────────────────────────────────────
def _fetch_from_db(org_id: str) -> Optional[dict]:
    """Return the org's mapped policy, None if it has none.

    Raises PolicyStoreUnavailable when the store cannot be queried.
    """
    try:
        db: Session = SessionLocal()
    except Exception as exc:
        raise PolicyStoreUnavailable(str(exc)) from exc
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
        raise PolicyStoreUnavailable(str(exc)) from exc
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

    If the store is unreachable, the org's last fetched policy is served
    even past its TTL. With no policy on hand, PolicyStoreUnavailable is
    raised; failures are never cached, so recovery is picked up at once.
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
    try:
        fetched = _fetch_from_db(org_id)
    except PolicyStoreUnavailable as exc:
        with _cache_lock:
            _metrics["unavailable"] += 1
            stale = _cache.get(org_id)
            if stale is not None and stale.policy is not None:
                _metrics["stale"] += 1
                logger.warning(
                    "policy_source: store unavailable for org=%s, serving last "
                    "known policy err=%s",
                    org_id,
                    exc,
                )
                return stale.policy
        logger.error("policy_source: store unavailable for org=%s err=%s", org_id, exc)
        raise

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
