"""Tier 1 offline tests: every rule evaluated against its TP/FP fixtures.

One parametrized test per (rule, fixture) pair, so a failure names the
exact rule and event, e.g.::

    test_rule[susp_service_creation-fp_legit_installer]
"""

import pytest

from sigmaforge.evaluator import match_event
from sigmaforge.loader import discover_rule_paths, iter_rule_fixture_pairs, load_fixture

PAIRS = iter_rule_fixture_pairs()


def test_repository_has_rules():
    assert discover_rule_paths(), "No rules found under rules/. An empty repo must not pass CI."


@pytest.mark.parametrize("pair", PAIRS, ids=[p.test_id for p in PAIRS])
def test_rule(pair):
    event = load_fixture(pair.fixture_path)
    matched = match_event(pair.rule, event)
    if pair.expect_match:
        assert matched, (
            f"Rule {pair.rule_path.name} did NOT match true positive fixture "
            f"{pair.fixture_name}. The rule logic misses this attack variant."
        )
    else:
        assert not matched, (
            f"Rule {pair.rule_path.name} MATCHED false positive fixture "
            f"{pair.fixture_name}. The rule would fire on this benign activity."
        )
