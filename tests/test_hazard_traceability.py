"""Every rule names a hazard, every hazard names its rules, both stay in step.

This is the artefact most likely to be quoted at a regulator, which makes its
failure mode different from the rest of the repo. An overstated mitigation does
not cause a bug; it causes somebody to fly on an assumption that was never true.
So these tests fail the build rather than warn: a warning would be ignored, and
the value of a traceability matrix is entirely in its completeness.
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

from verify_policy import (POLICY_FILE, declared_rules,  # noqa: E402
                           load_hazards, load_policy)

HZ = load_hazards()
RULES = {f"{t}.{fam}.{f}" for t, fam, f in declared_rules(load_policy())}


def test_every_rule_names_a_hazard():
    """A rule that cannot name one is either unnecessary or the register is short."""
    orphans = sorted(RULES - set(HZ["rule_hazards"]))
    assert not orphans, f"rules with no hazard: {orphans}"


def test_no_mapping_refers_to_a_rule_that_is_gone():
    """The coupling that rots: rules get renamed, mappings do not, and a stale
    mapping reads as coverage."""
    stale = sorted(set(HZ["rule_hazards"]) - RULES)
    assert not stale, f"mappings for rules that no longer exist: {stale}"


def test_every_referenced_hazard_is_defined():
    """A dangling id reads as coverage and is not."""
    referenced = {h for hs in HZ["rule_hazards"].values() for h in hs}
    undefined = sorted(referenced - set(HZ["hazards"]))
    assert not undefined, f"referenced but undefined: {undefined}"


def test_every_hazard_is_covered_or_explicitly_accepted():
    """An uncovered hazard must be a decision, not an oversight.

    accepted_gaps exists so the only way to green is not deleting an
    inconvenient hazard, which is the failure this whole file exists to stop.
    """
    covered = {h for hs in HZ["rule_hazards"].values() for h in hs}
    uncovered = sorted(set(HZ["hazards"]) - covered - set(HZ["accepted_gaps"]))
    assert not uncovered, (
        f"hazards with no rules and no accepted-gap entry: {uncovered}. "
        "Add a rule, or record it as an accepted gap with a reason."
    )


def test_no_hazard_is_both_covered_and_accepted():
    covered = {h for hs in HZ["rule_hazards"].values() for h in hs}
    both = sorted(covered & set(HZ["accepted_gaps"]))
    assert not both, f"listed as an accepted gap while covered: {both}"


@pytest.mark.parametrize("hid", sorted(HZ["hazards"]))
def test_each_hazard_states_its_residual_risk(hid):
    """The field most likely to be written carelessly and most load-bearing.

    A residual reading "none" is almost always unfinished work, so the length
    floor is deliberate: it is hard to state a real limitation in ten characters.
    """
    h = HZ["hazards"][hid]
    for field in ("title", "description", "residual"):
        assert h.get(field, "").strip(), f"{hid} has no {field}"
    assert len(h["residual"]) > 40, (
        f"{hid} residual is too short to be a real statement of what is still "
        f"uncovered: {h['residual']!r}"
    )


@pytest.mark.parametrize("hid", sorted(HZ["hazards"]))
def test_each_hazard_says_what_else_mitigates_it(hid):
    """Claiming sole mitigation of a hazard PX4 also covers is a false claim by
    omission."""
    assert isinstance(HZ["hazards"][hid].get("mitigated_by_others"), list), (
        f"{hid} does not say what else mitigates it"
    )


def test_accepted_gaps_give_a_reason():
    for hid, reason in HZ["accepted_gaps"].items():
        assert hid in HZ["hazards"], f"accepted gap {hid} is not a defined hazard"
        assert len(reason) > 40, f"accepted gap {hid} needs a real reason"


def test_hazard_metadata_never_reaches_the_aircraft():
    """Documentation must not be signed into a bundle.

    Two reasons, and the second matters more: it is weight on a companion
    computer, and anything the evaluator can read is something that could one
    day influence a decision.
    """
    from shield_mavlink.bundle import sign_bundle
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    full = json.loads(POLICY_FILE.read_text())
    shipped = {"parameter_policies": full["parameter_policies"]}
    priv = Ed25519PrivateKey.generate().private_bytes_raw().hex()

    b = sign_bundle(shipped, private_key_hex=priv, tenant_id="t", fleet_id="f",
                    bundle_version=1, valid_for_s=60, now=1000)
    body = json.dumps(b)
    for key in ("hazards", "rule_hazards", "accepted_gaps", "residual"):
        assert key not in body, f"{key!r} reached the signed bundle"
