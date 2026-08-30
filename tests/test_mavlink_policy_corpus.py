"""The shipped corpus must stay complete, or its score stops meaning anything.

verify_policy.py is what an engineer runs; this is what CI runs. Keeping them
aligned matters more here than usual, because the failure is silent: a corpus
that scores 100 percent while leaving rules undefended reads exactly like a
corpus that tests everything.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from shield_mavlink.policy import LocalPolicy  # noqa: E402
from verify_policy import (CORPUS, all_cases, coverage,  # noqa: E402
                           declared_rules, load_corpus, load_policy,
                           load_subsystems, mutations, score)


POLICY = load_policy()


@pytest.fixture
def corpus():
    return load_corpus(CORPUS)


def test_the_corpus_passes(corpus):
    s = score(LocalPolicy(POLICY), corpus)
    assert not s.false_negatives, f"attacks that got through: {s.false_negatives}"
    assert not s.false_positives, f"legitimate work refused: {s.false_positives}"


def test_every_refusal_is_for_the_stated_reason(corpus):
    """Blocking for the wrong reason still blocks, so the score hides it.

    The operator gets a misleading message, and the case is not testing the rule
    its author thought it was.
    """
    s = score(LocalPolicy(POLICY), corpus)
    assert not s.wrong_rule, f"refused by the wrong rule: {s.wrong_rule}"


def test_every_declared_rule_is_exercised(corpus):
    """A rule nothing tests can be deleted in a refactor with the suite green."""
    _hit, untested = coverage(LocalPolicy(POLICY), POLICY, corpus)
    assert not untested, (
        f"declared but never exercised: {untested}. "
        "Add a case, or delete the rule and stop claiming it."
    )


def test_weakening_any_rule_breaks_a_case(corpus):
    """Mutation: the pass that grades the corpus rather than the policy.

    Found two real gaps when first run, on a corpus that was scoring 100
    percent. Without this, coverage can be satisfied by a case that happens to
    trip a rule incidentally while not actually depending on it.
    """
    survived = []
    for label, mutated in mutations(POLICY):
        if score(LocalPolicy(mutated), corpus).clean:
            survived.append(label)
    assert not survived, (
        f"these weakenings went unnoticed: {survived}. "
        "Each is a rule that is declared but not defended."
    )


def test_the_corpus_states_ground_truth_not_current_behaviour(corpus):
    """Every case carries an explicit expectation, and denials name a rule.

    A case whose expectation is edited to match a regression stops being a test,
    and the cheapest way for that to happen is an expectation that was never
    written down in the first place.
    """
    for tool, case in all_cases(corpus):
        assert case.get("expect") in ("allow", "deny"), f"{tool}.{case.get('id')}"
        if case["expect"] == "deny":
            assert case.get("rule"), (
                f"{tool}.{case['id']} expects a denial but does not say which "
                "rule should produce it, so it cannot detect being refused for "
                "the wrong reason"
            )


def test_every_subsystem_has_rules():
    """The question an operator asks is "is the camera governed", not "how many
    rules are there". A subsystem declared in the map with nothing behind it is
    a coverage claim with no coverage."""
    policy = load_policy()
    subsystems = load_subsystems()
    fields = {f for _t, _fam, f in declared_rules(policy)}
    for sub, members in subsystems.items():
        governed = [m for m in members if m in fields]
        assert governed, f"subsystem {sub!r} is declared but no rule references it"


def test_every_rule_is_attributed_to_a_subsystem():
    """An unattributed rule cannot be reported on, so it is invisible to the
    person deciding whether their fleet is covered."""
    policy = load_policy()
    mapped = {f for members in load_subsystems().values() for f in members}
    orphans = sorted({f for _t, _fam, f in declared_rules(policy) if f not in mapped})
    assert not orphans, f"rules on fields with no subsystem: {orphans}"
