# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Path x store-state x control invariant matrix.

Paths
    P1  precheck, explicit tool_access allow
    P2  precheck, tool_access confirm
    P3  precheck, tool_access redact when the text has PII
    P4  precheck, no tool rule, ingress default redact
    P5  precheck, no tool rule, default pass_through
    P6  precheck, no tool rule, default tokenize
    P7  precheck, network-scope path
    P8  precheck, strict fallback. When the org has no row the request
        sends no policy_config, so the static policy is what runs.
    P9  postcheck with the P1, P3, and P4 policies (variant on the cell id)
    P10 repeat precheck served from the allow-decision cache

Store states
    S1  store healthy, org policy row active
    S2  store healthy, org has no policy row
    S3  store down after a warm cache, past the TTL
    S4  store down, cold cache
    S5  store down, cold cache, caller sends a permissive policy
    S6  store recovers after an outage and the invalidate route drops the cache

Controls executed here: C1 budget cap, and I-S fail-closed.
C2 PII, C3 deny list, C4 confirm, and C5 detector coverage are listed so the
matrix shape is visible; they are skip or n/a in this slice.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from tests.test_budget_all_paths import (
    NEAR_CAP,
    OVER_CAP,
    PURCHASE_TOOL_CONFIG,
    WELL_UNDER,
    _row,
)
from tests.test_policy_invalidate_endpoint import _hmac
from tests.test_policy_store_fail_closed import (
    CARD,
    CARD_TEXT,
)
from tests.test_policy_store_fail_closed import ORG as STORE_ORG
from tests.test_policy_store_fail_closed import PERMISSIVE

# Reason string attached when evaluation uses the server fail-closed policy.
# Kept as a literal so this module still imports where that constant is absent.
OUTAGE_REASON = "policy_store.unavailable"
EMAIL = "jane.doe@example.com"
CHECKOUT_TEXT = "Check out cart 77"
REDACT_TEXT = "Check out cart 77 for jane.doe@example.com"
CLEAN_TEXT = "Summarise the release notes."
PRECHECK = "/api/v1/precheck"
POSTCHECK = "/api/v1/postcheck"
INVALIDATE = "/api/v1/internal/policy/invalidate"

if EMAIL not in CARD_TEXT or CARD not in CARD_TEXT:
    raise RuntimeError("policy-store card fixture text no longer contains the probes")

LAST_NOTES: Dict[str, "CellOutcome"] = {}

_PATHS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10")
_STATES = ("S1", "S2", "S3", "S4", "S5", "S6")
_CONTROLS = ("C1", "C2", "C3", "C4", "C5", "I-S")
_P9_VARIANTS = ("tool_allow", "tool_redact", "default_redact")
_P9_SOURCE = {
    "tool_allow": "P1",
    "tool_redact": "P3",
    "default_redact": "P4",
}


@dataclass(frozen=True)
class Cell:
    path: str
    state: str
    control: str
    variant: Optional[str] = None

    @property
    def id(self) -> str:
        if self.variant:
            return "{}-{}-{}-{}".format(
                self.path, self.variant, self.state, self.control
            )
        return "{}-{}-{}".format(self.path, self.state, self.control)


@dataclass(frozen=True)
class CellOutcome:
    cell_id: str
    path: str
    state: str
    control: str
    result: str
    note: str


@dataclass(frozen=True)
class PathSpec:
    path: str
    variant: Optional[str]
    route: str
    tool: str
    scope: str
    budget_text: str
    policy: dict
    omit_caller_when_org_absent: bool = False


def iter_cells():
    for path in _PATHS:
        variants = _P9_VARIANTS if path == "P9" else (None,)
        for variant in variants:
            for state in _STATES:
                for control in _CONTROLS:
                    yield Cell(path, state, control, variant)


def applicability(cell: Cell) -> Optional[Tuple[str, str]]:
    """Return (result, note) when the cell is not executed."""
    if cell.control == "C1" and cell.path == "P10":
        return (
            "n/a",
            "allow-decision cache does not store a result that carries "
            "budget_context, so a cache hit cannot show the budget cap",
        )
    if cell.control == "C4" and cell.path != "P2":
        return ("n/a", "confirm control is defined on P2 only")
    if cell.control == "I-S" and cell.state in {"S1", "S2"}:
        return (
            "n/a",
            "fail-closed behavior applies when the store is unreachable; "
            "S1 and S2 keep the store healthy",
        )
    if cell.control in {"C2", "C3", "C4", "C5"}:
        return ("skip", "not executed in this slice")
    return None


def active_cells() -> List[Cell]:
    return [cell for cell in iter_cells() if applicability(cell) is None]


def noted_cells() -> List[Cell]:
    return [cell for cell in iter_cells() if applicability(cell) is not None]


_CELL_BY_ID = {cell.id: cell for cell in iter_cells()}


def _both(action: str) -> dict:
    return {"ingress": {"action": action}, "egress": {"action": action}}


def _policy(default_action: str, tool_action: Optional[str] = None) -> dict:
    document = {
        "version": "v1",
        "defaults": _both(default_action if tool_action is None else "redact"),
        "tool_access": {},
        "deny_tools": [],
    }
    if tool_action is not None:
        document["tool_access"] = {
            "shop.checkout": {"action": tool_action, "direction": "both"}
        }
    return document


def _build_specs() -> Dict[Tuple[str, Optional[str]], PathSpec]:
    specs = {
        ("P1", None): PathSpec(
            "P1",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("redact", "allow"),
        ),
        ("P2", None): PathSpec(
            "P2",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("redact", "confirm"),
        ),
        ("P3", None): PathSpec(
            "P3",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            REDACT_TEXT,
            _policy("redact", "redact"),
        ),
        ("P4", None): PathSpec(
            "P4",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("redact"),
        ),
        ("P5", None): PathSpec(
            "P5",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("allow"),
        ),
        ("P6", None): PathSpec(
            "P6",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("tokenize"),
        ),
        ("P7", None): PathSpec(
            "P7",
            None,
            PRECHECK,
            "web.fetch",
            "net.external",
            CHECKOUT_TEXT,
            _policy("redact"),
        ),
        ("P8", None): PathSpec(
            "P8",
            None,
            PRECHECK,
            "shop.checkout",
            "local",
            CHECKOUT_TEXT,
            _policy("redact"),
            omit_caller_when_org_absent=True,
        ),
        ("P10", None): PathSpec(
            "P10",
            None,
            PRECHECK,
            "model.chat",
            "net.external",
            CHECKOUT_TEXT,
            _policy("redact"),
        ),
    }
    for variant, source in _P9_SOURCE.items():
        base = specs[(source, None)]
        specs[("P9", variant)] = PathSpec(
            "P9",
            variant,
            POSTCHECK,
            base.tool,
            base.scope,
            base.budget_text,
            base.policy,
            base.omit_caller_when_org_absent,
        )
    return specs


_SPECS = _build_specs()


def _spec_for(cell: Cell) -> PathSpec:
    return _SPECS[(cell.path, cell.variant)]


def _with_variant(cell: Cell, note: str) -> str:
    if cell.variant:
        return "variant={}; {}".format(cell.variant, note)
    return note


def _outcome(cell: Cell, result: str, note: str) -> CellOutcome:
    outcome = CellOutcome(
        cell.id, cell.path, cell.state, cell.control, result, _with_variant(cell, note)
    )
    LAST_NOTES[cell.id] = outcome
    return outcome


def noted_outcome(cell_id: str) -> CellOutcome:
    cell = _CELL_BY_ID[cell_id]
    status, note = applicability(cell)
    return _outcome(cell, status, note)


def execute(
    cell_id: str,
    *,
    test_client,
    db_session,
    store,
    api_key: str,
    monkeypatch,
) -> CellOutcome:
    cell = _CELL_BY_ID[cell_id]
    if applicability(cell) is not None:
        return noted_outcome(cell_id)
    logging.getLogger().setLevel(logging.ERROR)
    _force_detector(monkeypatch)
    try:
        if cell.control == "C1":
            return _run_c1(cell, test_client, db_session, store, api_key, monkeypatch)
        if cell.control == "I-S":
            return _run_is(cell, test_client, db_session, store, api_key, monkeypatch)
        status, note = applicability(cell)
        return _outcome(cell, status, note)
    except Exception as exc:
        return _outcome(cell, "fail", "{}: {}".format(type(exc).__name__, exc))


def _force_detector(monkeypatch) -> None:
    if os.environ.get("INVARIANT_FORCE_REGEX") != "1":
        return
    monkeypatch.setattr("app.policies.USE_PRESIDIO", False)
    monkeypatch.setattr("app.policies.ANALYZER", None)


def _detector() -> str:
    from app.policies import ANALYZER, USE_PRESIDIO

    if USE_PRESIDIO and ANALYZER is not None:
        return "presidio"
    return "regex"


def _install(db_session, spec: PathSpec, policy: dict, policy_id: str) -> str:
    row = _row(
        id=policy_id,
        org_id=STORE_ORG,
        name=policy_id,
        defaults=policy["defaults"],
        tool_access=policy.get("tool_access") or {},
        deny_tools=list(policy.get("deny_tools") or []),
    )
    db_session.add(row)
    db_session.commit()
    return policy_id


def _policy_id_for(spec: PathSpec, suffix: str) -> str:
    if spec.variant:
        return "pol-{}-{}-{}".format(spec.path, spec.variant, suffix)
    return "pol-{}-{}".format(spec.path, suffix)


def _arm_clock(monkeypatch):
    from app import policy_source

    clock = [1000.0]
    monkeypatch.setattr(policy_source.time, "monotonic", lambda: clock[0])
    return clock


def _stale_note(policy_id: str) -> Optional[str]:
    from app import policy_source

    try:
        cfg = policy_source.get_active_policy(STORE_ORG)
    except Exception as exc:
        return (
            "store-down lookup raised {} instead of serving the cached org policy"
        ).format(type(exc).__name__)
    got = None if not cfg else cfg.get("_policy_id")
    if got != policy_id:
        return "cached org policy {} was not served while the store was down (got {})".format(
            policy_id, got
        )
    return None


def _reset_runtime() -> None:
    from app import policy_source
    from app.decision_cache import allow_decision_cache
    from app.rate_limit import rate_limiter

    policy_source._clear_for_tests()
    allow_decision_cache.clear()
    rate_limiter.clear()


def _caller_for_budget(cell: Cell, spec: PathSpec):
    if cell.state in {"S3", "S5"}:
        return PERMISSIVE
    if cell.state in {"S2", "S4"}:
        if spec.omit_caller_when_org_absent:
            return None
        return spec.policy
    return None


def _post(
    client,
    api_key: str,
    *,
    route: str,
    tool: str,
    scope: Optional[str],
    text: str,
    user_id: Optional[str] = None,
    budget: Optional[dict] = None,
    policy_config: Optional[dict] = None,
    tool_config: Optional[dict] = None,
):
    payload = {"tool": tool, "raw_text": text}
    if scope is not None:
        payload["scope"] = scope
    if user_id is not None:
        payload["user_id"] = user_id
    if budget is not None:
        payload["budget_context"] = budget
    if policy_config is not None:
        payload["policy_config"] = policy_config
    if tool_config is not None:
        payload["tool_config"] = tool_config
    response = client.post(route, json=payload, headers={"X-Governs-Key": api_key})
    cache = response.headers.get("x-cache")
    try:
        body = response.json()
    except Exception:
        body = {"_raw": (response.text or "")[:180]}
    if not isinstance(body, dict):
        body = {"_raw": str(body)[:180]}
    return response.status_code, body, cache


def _purchase_config(tool: str) -> dict:
    return {
        "tool_name": tool,
        "direction": "ingress",
        "metadata": dict(PURCHASE_TOOL_CONFIG["metadata"]),
    }


def _has_budget_warning(body: dict) -> bool:
    status = body.get("budget_status") or {}
    info = body.get("budget_info") or {}
    if not isinstance(status, dict):
        status = {}
    if not isinstance(info, dict):
        info = {}
    if status.get("reason") == "budget_warning":
        return True
    if status.get("reason") == "budget_exceeded":
        return False
    percent = info.get("percent_used")
    return isinstance(percent, (int, float)) and percent > 90


def _is_budget_denial(body: dict) -> bool:
    if body.get("decision") != "deny":
        return False
    reasons = [str(item) for item in (body.get("reasons") or [])]
    if any("budget_exceeded" in item for item in reasons):
        return True
    status = body.get("budget_status") or {}
    if not isinstance(status, dict):
        return False
    return status.get("reason") == "budget_exceeded" or status.get("allowed") is False


def _invalidate(client) -> None:
    response = client.post(
        INVALIDATE,
        json={"org_id": STORE_ORG},
        headers={"x-govs-invalidate-hmac": _hmac(STORE_ORG)},
    )
    if response.status_code != 200:
        raise RuntimeError(
            "invalidate returned {} {}".format(
                response.status_code, response.text[:160]
            )
        )


def _prepare_org(
    cell: Cell, spec: PathSpec, db_session, store, monkeypatch
) -> Tuple[Optional[str], List[str]]:
    """Put the store in `cell.state`. Returns (org policy id, setup notes)."""
    notes: List[str] = []
    policy_id = None
    if cell.state == "S1":
        policy_id = _install(db_session, spec, spec.policy, _policy_id_for(spec, "s1"))
    elif cell.state == "S3":
        clock = _arm_clock(monkeypatch)
        policy_id = _install(db_session, spec, spec.policy, _policy_id_for(spec, "s3"))
        from app import policy_source

        warmed = policy_source.get_active_policy(STORE_ORG)
        if not warmed or warmed.get("_policy_id") != policy_id:
            notes.append("could not warm the org policy before the outage")
        clock[0] += 3600
        store["up"] = False
        stale = _stale_note(policy_id)
        if stale:
            notes.append(stale)
    elif cell.state in {"S4", "S5"}:
        store["up"] = False
    return policy_id, notes


def _recover(
    cell: Cell, spec: PathSpec, db_session, store, client, api_key: str, policy: dict
):
    """Outage, then store up, install `policy`, invalidate, ready for a normal call."""
    store["up"] = False
    _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CLEAN_TEXT,
        policy_config=PERMISSIVE,
    )
    store["up"] = True
    policy_id = _install(db_session, spec, policy, _policy_id_for(spec, "s6"))
    _invalidate(client)
    return policy_id


def _run_c1(cell, client, db_session, store, api_key, monkeypatch) -> CellOutcome:
    spec = _spec_for(cell)
    _reset_runtime()
    failures: List[str] = []
    if cell.state == "S6":
        _recover(cell, spec, db_session, store, client, api_key, spec.policy)
    else:
        _, setup_notes = _prepare_org(cell, spec, db_session, store, monkeypatch)
        failures.extend(setup_notes)

    caller = _caller_for_budget(cell, spec)
    tool_config = _purchase_config(spec.tool)
    probes = (
        ("over+user", OVER_CAP, "user-1", "over"),
        ("over-user", OVER_CAP, None, "over"),
        ("near+user", NEAR_CAP, "user-1", "near"),
        ("near-user", NEAR_CAP, None, "near"),
        ("under+user", WELL_UNDER, "user-1", "under"),
        ("under-user", WELL_UNDER, None, "under"),
    )
    observed = ["detector={}".format(_detector())]
    for label, budget, user_id, kind in probes:
        status, body, cache = _post(
            client,
            api_key,
            route=spec.route,
            tool=spec.tool,
            scope=spec.scope,
            text=spec.budget_text,
            user_id=user_id,
            budget=budget,
            policy_config=caller,
            tool_config=tool_config,
        )
        if status != 200:
            observed.append("{}=http{}".format(label, status))
            failures.append("{} http {}".format(label, status))
            continue
        decision = body.get("decision")
        if kind == "over":
            observed.append("{}={}".format(label, decision))
            if decision == "allow":
                failures.append("{} decision=allow".format(label))
            if cell.state == "S6" and spec.route == PRECHECK and cache == "HIT":
                failures.append(
                    "{} served from allow cache after recovery".format(label)
                )
        elif kind == "near":
            warned = _has_budget_warning(body)
            observed.append(
                "{}={}".format(label, "budget_warning" if warned else "no-warning")
            )
            if not warned:
                failures.append("{} missing budget warning".format(label))
        else:
            observed.append("{}={}".format(label, decision))
            if _is_budget_denial(body):
                failures.append("{} budget denial".format(label))
    note = "; ".join(observed)
    if failures:
        note = "{}; FAIL {}".format(note, "; ".join(failures))
        return _outcome(cell, "fail", note)
    return _outcome(cell, "pass", note)


def _flags(body: dict) -> str:
    text = body.get("raw_text_out") or ""
    reasons = body.get("reasons") or []
    return "decision={} policy_id={} card={} email={} outage={}".format(
        body.get("decision"),
        body.get("policy_id"),
        int(CARD in text),
        int(EMAIL in text),
        int(OUTAGE_REASON in reasons),
    )


def _check_fail_closed_body(body: dict) -> Optional[str]:
    reasons = body.get("reasons") or []
    if OUTAGE_REASON not in reasons:
        return "missing {}; {}".format(OUTAGE_REASON, _flags(body))
    decision = body.get("decision")
    text = body.get("raw_text_out") or ""
    if decision == "transform" and (CARD in text or EMAIL in text):
        return "transformed output still contains the card or email; {}".format(
            _flags(body)
        )
    if decision not in {"transform", "deny"}:
        return "decision {} is not the server fail-closed policy; {}".format(
            decision, _flags(body)
        )
    return None


def _run_is(cell, client, db_session, store, api_key, monkeypatch) -> CellOutcome:
    spec = _spec_for(cell)
    _reset_runtime()
    if cell.state == "S3":
        return _run_is_s3(cell, spec, client, db_session, store, api_key, monkeypatch)
    if cell.state == "S6":
        return _run_is_s6(cell, spec, client, db_session, store, api_key)
    return _run_is_down(cell, spec, client, store, api_key)


def _run_is_down(cell, spec, client, store, api_key) -> CellOutcome:
    store["up"] = False
    failures = []
    status, body, _cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CARD_TEXT,
        policy_config=PERMISSIVE,
    )
    observed = ["detector={}".format(_detector())]
    if status != 200:
        failures.append("card probe http {}".format(status))
        observed.append("card_probe=http{}".format(status))
    else:
        observed.append(_flags(body))
        problem = _check_fail_closed_body(body)
        if problem:
            failures.append(problem)
    if cell.path == "P10":
        cache_note, cache_fail = _cache_probe(client, api_key, spec)
        observed.append(cache_note)
        if cache_fail:
            failures.append(cache_fail)
    note = "; ".join(observed)
    if failures:
        return _outcome(cell, "fail", "{}; FAIL {}".format(note, "; ".join(failures)))
    return _outcome(cell, "pass", note)


def _cache_probe(client, api_key, spec) -> Tuple[str, Optional[str]]:
    first_status, first_body, _first_cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CLEAN_TEXT,
        policy_config=PERMISSIVE,
    )
    second_status, second_body, second_cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CLEAN_TEXT,
        policy_config=PERMISSIVE,
    )
    summary = "repeat_cache={} repeat_decision={} repeat_outage={}".format(
        second_cache,
        second_body.get("decision"),
        int(OUTAGE_REASON in (second_body.get("reasons") or [])),
    )
    if first_status != 200 or second_status != 200:
        return summary, "cache probe http {}/{}".format(first_status, second_status)
    if second_cache != "HIT":
        return summary, "repeat call was not served from the allow cache"
    if OUTAGE_REASON not in (second_body.get("reasons") or []):
        return summary, "cached allow is missing {}".format(OUTAGE_REASON)
    if second_body.get("decision") != first_body.get("decision"):
        return summary, "cached decision differs from the first call"
    return summary, None


def _run_is_s3(
    cell, spec, client, db_session, store, api_key, monkeypatch
) -> CellOutcome:
    """Compare one call before the TTL with one call after the store drops.

    The first call warms the cache. The clock then jumps past the TTL and the
    store stops answering, which is S3: the last org policy still has to win
    over the permissive caller policy.
    """
    clock = _arm_clock(monkeypatch)
    policy_id = _install(db_session, spec, spec.policy, _policy_id_for(spec, "s3"))
    before_status, before_body, _before_cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CARD_TEXT,
        policy_config=PERMISSIVE,
    )
    clock[0] += 3600
    store["up"] = False
    setup_notes = []
    stale = _stale_note(policy_id)
    if stale:
        setup_notes.append(stale)
    after_status, after_body, _after_cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CARD_TEXT,
        policy_config=PERMISSIVE,
    )
    observed = [
        "detector={}".format(_detector()),
        "before=({})".format(
            _flags(before_body)
            if before_status == 200
            else "http{}".format(before_status)
        ),
        "after=({})".format(
            _flags(after_body) if after_status == 200 else "http{}".format(after_status)
        ),
    ]
    failures = list(setup_notes)
    if before_status != 200 or after_status != 200:
        failures.append("http {}/{}".format(before_status, after_status))
    else:
        if OUTAGE_REASON in (after_body.get("reasons") or []):
            failures.append("outage replaced the cached org policy")
        if before_body.get("decision") != after_body.get("decision"):
            failures.append(
                "decision changed from {} to {} while the cached org policy should still apply".format(
                    before_body.get("decision"), after_body.get("decision")
                )
            )
        if before_body.get("policy_id") != after_body.get("policy_id"):
            failures.append(
                "policy_id changed from {} to {}".format(
                    before_body.get("policy_id"), after_body.get("policy_id")
                )
            )
        before_text = before_body.get("raw_text_out") or ""
        after_text = after_body.get("raw_text_out") or ""
        if (CARD in before_text) != (CARD in after_text) or (EMAIL in before_text) != (
            EMAIL in after_text
        ):
            failures.append("card or email leakage changed across the outage")
    note = "; ".join(observed)
    if failures:
        return _outcome(cell, "fail", "{}; FAIL {}".format(note, "; ".join(failures)))
    return _outcome(cell, "pass", note)


def _run_is_s6(cell, spec, client, db_session, store, api_key) -> CellOutcome:
    deny_policy = _policy("deny")
    _recover(cell, spec, db_session, store, client, api_key, deny_policy)
    status, body, cache = _post(
        client,
        api_key,
        route=spec.route,
        tool=spec.tool,
        scope=spec.scope,
        text=CLEAN_TEXT,
        policy_config=PERMISSIVE,
    )
    observed = [
        "detector={}".format(_detector()),
        "after={}".format(_flags(body) if status == 200 else "http{}".format(status)),
        "cache={}".format(cache),
    ]
    failures = []
    if status != 200:
        failures.append("http {}".format(status))
    else:
        if body.get("decision") != "deny":
            failures.append(
                "recovered decision is {} not deny".format(body.get("decision"))
            )
        if OUTAGE_REASON in (body.get("reasons") or []):
            failures.append("outage decision still applied after recovery")
        if spec.route == PRECHECK and cache == "HIT":
            failures.append("stale allow served from the decision cache after recovery")
    note = "; ".join(observed)
    if failures:
        return _outcome(cell, "fail", "{}; FAIL {}".format(note, "; ".join(failures)))
    return _outcome(cell, "pass", note)
