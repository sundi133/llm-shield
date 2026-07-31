"""user_sub must match the credential presented with it.

It was read from the request body and never checked, so a caller holding a valid
tenant key could mint an agent token naming any person — and every capability
minted from that token carried the name into the audit trail as though it had
been verified. Signed evidence of a claim nobody checked.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.routes_agent_auth import _enforce_user_sub_binding


def _req(sub=None):
    ident = SimpleNamespace(claims={"sub": sub} if sub else {})
    return SimpleNamespace(state=SimpleNamespace(workload_identity=ident))


def test_matching_subject_passes():
    _enforce_user_sub_binding(_req("user-abc"), "user-abc")


def test_a_different_subject_is_refused():
    with pytest.raises(HTTPException) as e:
        _enforce_user_sub_binding(_req("user-abc"), "ceo@example.com")
    assert e.value.status_code == 403
    assert "user-abc" in e.value.detail and "ceo@example.com" in e.value.detail


def test_no_verified_credential_is_unchanged():
    """This closes "the claim contradicts the proof", not "there is no proof".
    Requiring proof at all is SHIELD_ROLE_BINDING's job, and conflating them
    would break every deployment that does not send a user credential here."""
    _enforce_user_sub_binding(_req(None), "anything")
    _enforce_user_sub_binding(SimpleNamespace(state=SimpleNamespace()), "anything")
    _enforce_user_sub_binding(SimpleNamespace(), "anything")


def test_whitespace_is_not_a_bypass():
    with pytest.raises(HTTPException):
        _enforce_user_sub_binding(_req("user-abc"), "  user-abd  ")
    _enforce_user_sub_binding(_req("user-abc"), "  user-abc  ")


def test_empty_claim_against_a_verified_subject_is_refused():
    with pytest.raises(HTTPException):
        _enforce_user_sub_binding(_req("user-abc"), "")
