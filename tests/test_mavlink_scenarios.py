"""Every scenario must actually be refused, or the demo claims something false.

scenarios.py is shown to customers. A scenario the policy stops covering, after
a rule is renamed or relaxed, would keep printing its narration while the WITH
column quietly said "allowed". That is worse than having no demo.
"""
from __future__ import annotations

import os
import sys

import pytest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

from scenarios import BASE, SCENARIOS  # noqa: E402
from shield_mavlink.policy import LocalPolicy  # noqa: E402
from verify_policy import load_policy  # noqa: E402

POLICY = LocalPolicy(load_policy())


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s.sid for s in SCENARIOS])
def test_the_scenario_is_refused(sc):
    v = POLICY.check(sc.tool, {**BASE[sc.tool], **sc.params})
    assert v.blocked, (
        f"{sc.sid!r} is shown to customers as something the policy stops, "
        f"and it is currently allowed"
    )


@pytest.mark.parametrize("tool", sorted(BASE), ids=sorted(BASE))
def test_each_baseline_is_itself_allowed(tool):
    """The baselines must pass, or a scenario proves nothing.

    If the baseline were already refused, every scenario built on it would
    show a refusal regardless of the change it makes, and the demo would be
    a wall of blocks that means nothing.
    """
    v = POLICY.check(tool, BASE[tool])
    assert v.allowed, f"baseline for {tool} is refused: {v.reason}"


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s.sid for s in SCENARIOS])
def test_the_refusal_is_caused_by_the_stated_change(sc):
    """Refused for the reason the story tells, not incidentally.

    A scenario refused by some unrelated rule still prints a block, so the
    narration and the verdict would drift apart without this.
    """
    v = POLICY.check(sc.tool, {**BASE[sc.tool], **sc.params})
    assert v.field in sc.params, (
        f"{sc.sid!r} narrates {list(sc.params)} but was refused on "
        f"{v.field!r}, which the story never mentions"
    )
