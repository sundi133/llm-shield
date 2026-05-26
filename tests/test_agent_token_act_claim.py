"""Agent tokens carry an RFC 8693 `act` nested claim.

This lets external SIEMs and standards-compliant policy engines walk the
delegation chain (human → agent → parent-agent) without Shield-specific
parsing. The flat `user_sub` / `agent_id` / `parent_agent_id` fields stay
in place so older verifiers keep working.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "22" * 32)

from core.agent_tokens import (
    mint_agent_token,
    reset_signer_cache_for_tests,
    verify_agent_token,
)
from core.jwt_utils import decode_jwt_unverified


@pytest.fixture(autouse=True)
def _reset():
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


def _common_kwargs(**overrides):
    base = dict(
        user_sub="alice",
        agent_id="billing-bot",
        agent_instance_id="inst-1",
        tenant_id="t1",
        build_hash="sha:abc",
        model_version="m",
        session_id="s",
    )
    base.update(overrides)
    return base


def test_direct_call_sets_sub_and_one_level_act():
    token = mint_agent_token(**_common_kwargs())
    claims = decode_jwt_unverified(token)

    assert claims["sub"] == "alice"
    assert claims["act"]["sub"] == "billing-bot"
    assert claims["act"]["agent_instance_id"] == "inst-1"
    assert "act" not in claims["act"], "no parent → no nested act"


def test_delegated_call_nests_parent_under_act():
    token = mint_agent_token(**_common_kwargs(parent_agent_id="parent-bot"))
    claims = decode_jwt_unverified(token)

    assert claims["sub"] == "alice"
    assert claims["act"]["sub"] == "billing-bot"
    assert claims["act"]["act"]["sub"] == "parent-bot"


def test_flat_fields_still_present_for_backward_compat():
    token = mint_agent_token(**_common_kwargs(parent_agent_id="parent-bot"))
    claims = decode_jwt_unverified(token)

    assert claims["user_sub"] == "alice"
    assert claims["agent_id"] == "billing-bot"
    assert claims["parent_agent_id"] == "parent-bot"


def test_verify_round_trips_identity():
    token = mint_agent_token(**_common_kwargs(parent_agent_id="parent-bot"))
    identity = verify_agent_token(token)

    assert identity.user_sub == "alice"
    assert identity.agent_id == "billing-bot"
    assert identity.parent_agent_id == "parent-bot"
