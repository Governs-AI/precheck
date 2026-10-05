# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""The held-out benchmark pools must be disjoint from the published ones and
carry valid checksums, so a ``--pools heldout`` run measures unseen values
rather than a reshuffle of the same ones."""

import pytest

from bench import corpus


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number.replace(" ", "")]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


@pytest.fixture(autouse=True)
def _restore_published_pools():
    yield
    corpus.select_pools("published")


def _slot_values(items):
    return {s.value for it in items for s in it.spans}


def test_heldout_pools_cover_every_field():
    assert set(corpus.HELDOUT_POOLS) == set(corpus.POOL_FIELDS)
    for name in corpus.POOL_FIELDS:
        published, heldout = corpus.PUBLISHED_POOLS[name], corpus.HELDOUT_POOLS[name]
        assert type(published) is type(heldout)
        if isinstance(published, dict):
            assert set(published) == set(heldout)
            for lang in published:
                assert len(published[lang]) == len(heldout[lang])
        else:
            assert len(published) == len(heldout)


def test_heldout_slot_values_are_unseen():
    published = _slot_values(corpus.build(pools="published"))
    heldout = _slot_values(corpus.build(pools="heldout"))
    inline = {v for truths in corpus.INLINE_TRUTH.values() for v, _ in truths}
    assert (published & heldout) - inline == set()


def test_heldout_corpus_has_same_shape():
    published = corpus.build(pools="published")
    heldout = corpus.build(pools="heldout")
    assert len(heldout) == len(published) == 438
    assert (
        sum(len(i.spans) for i in heldout)
        == sum(len(i.spans) for i in published)
        == 630
    )
    assert [i.tier for i in heldout] == [i.tier for i in published]


def test_heldout_checksums_are_valid():
    assert all(_luhn_ok(c) for c in corpus.HELDOUT_POOLS["CARDS"])
    assert all(_iban_ok(i) for i in corpus.HELDOUT_POOLS["IBANS"])
    npi = corpus.HELDOUT_POOLS["NPIS"][0].split()[-1]
    assert _luhn_ok("80840" + npi)
    dea = corpus.HELDOUT_POOLS["DEAS"][0].split()[-1]
    d = [int(c) for c in dea[2:]]
    assert (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


def test_select_pools_rejects_unknown_and_restores():
    with pytest.raises(ValueError):
        corpus.select_pools("nope")
    corpus.select_pools("heldout")
    assert corpus.PERSONS is corpus.HELDOUT_POOLS["PERSONS"]
    corpus.select_pools("published")
    assert corpus.PERSONS is corpus.PUBLISHED_POOLS["PERSONS"]
