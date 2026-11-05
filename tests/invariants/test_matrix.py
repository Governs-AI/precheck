# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Run one invariant cell per path, store state, and control."""

import pytest

from tests.invariants.matrix import (
    active_cells,
    execute,
    iter_cells,
    noted_cells,
    noted_outcome,
)
from tests.test_policy_store_fail_closed import (  # noqa: F401
    _quiet_runtime,
    org_api_key,
    store,
)

_STATES = {"S1", "S2", "S3", "S4", "S5", "S6"}
_CONTROLS = {"C1", "C2", "C3", "C4", "C5", "I-S"}
_PATHS = {"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10"}


def test_catalog_covers_every_path_state_and_control():
    cells = list(iter_cells())
    ids = [cell.id for cell in cells]
    assert len(ids) == len(set(ids))
    assert {cell.path for cell in cells} == _PATHS
    assert {cell.state for cell in cells} == _STATES
    assert {cell.control for cell in cells} == _CONTROLS
    variants = {cell.variant for cell in cells if cell.path == "P9"}
    assert variants == {"tool_allow", "tool_redact", "default_redact"}
    assert {cell.variant for cell in cells if cell.path != "P9"} == {None}
    assert len(active_cells()) + len(noted_cells()) == len(cells)


@pytest.mark.parametrize("cell_id", [cell.id for cell in noted_cells()])
def test_invariant_cell_noted(cell_id):
    """Skeleton and not-applicable cells carry a reason and do not call the API."""
    outcome = noted_outcome(cell_id)
    if outcome.result == "n/a":
        pytest.skip("N/A: " + outcome.note)
    pytest.skip("SKIP: " + outcome.note)


@pytest.mark.parametrize("cell_id", [cell.id for cell in active_cells()])
def test_invariant_cell(
    cell_id,
    test_client,
    db_session,
    store,
    org_api_key,
    _quiet_runtime,
    monkeypatch,
):
    outcome = execute(
        cell_id,
        test_client=test_client,
        db_session=db_session,
        store=store,
        api_key=org_api_key,
        monkeypatch=monkeypatch,
    )
    if outcome.result != "pass":
        pytest.fail(outcome.note)
