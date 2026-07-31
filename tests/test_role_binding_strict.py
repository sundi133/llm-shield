"""`strict` must refuse a self-asserted role.

It did not. strict and prefer behaved identically: both preferred a verified
claim, and both fell through to the body or header when none was present. So
there was no mode meaning "self-asserted roles are not accepted" — which is the
mode a security architect is actually asking for, and the FAQ had to say so.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.identity_resolution import (SOURCE_HEADER, SOURCE_NONE,
                                      clear_role_binding_cache_for_tests,
                                      resolve_identity)


def _req(role_header="doctor"):
    return SimpleNamespace(
        headers={"X-User-Role": role_header, "X-Agent-Key": "bot"},
        state=SimpleNamespace(identity=None),
        method="POST", url="https://shield.local/x")


def _resolve(mode, req=None):
    clear_role_binding_cache_for_tests()
    with patch.dict("os.environ", {"SHIELD_ROLE_BINDING": mode}):
        return resolve_identity(req or _req())


@pytest.fixture(autouse=True)
def _clean():
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


def test_off_accepts_the_header():
    r = _resolve("off")
    assert r.user_role == "doctor" and r.role_source == SOURCE_HEADER


def test_prefer_accepts_the_header_when_nothing_is_verified():
    """prefer means "prefer when available" — unchanged."""
    r = _resolve("prefer")
    assert r.user_role == "doctor" and r.role_source == SOURCE_HEADER


def test_strict_refuses_the_header():
    """The behaviour that did not exist before."""
    r = _resolve("strict")
    assert r.user_role == ""
    assert r.role_source == SOURCE_NONE


def test_strict_refuses_a_body_role_too():
    clear_role_binding_cache_for_tests()
    with patch.dict("os.environ", {"SHIELD_ROLE_BINDING": "strict"}):
        r = resolve_identity(_req(), body_user_role="admin")
    assert r.user_role == ""


def test_strict_and_prefer_now_differ():
    """The regression guard. They were indistinguishable, which is the bug."""
    assert _resolve("strict").user_role != _resolve("prefer").user_role


def test_strict_does_not_raise():
    """No role, not a 500. Authorization is the caller's decision, and "" grants
    nothing wherever it is consulted — fail closed without breaking a path that
    may legitimately have no user credential."""
    assert _resolve("strict") is not None
