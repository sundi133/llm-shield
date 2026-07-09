"""Tests for the revocation store."""

import pytest

from storage.revocation import (
    clear_all_for_tests,
    is_instance_revoked,
    is_jti_revoked,
    is_user_revoked,
    revoke_instance,
    revoke_jti,
    revoke_user,
)


@pytest.fixture(autouse=True)
def _no_redis_isolated(monkeypatch):
    """Force the in-process fallback store and clear it between tests."""
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    clear_all_for_tests()
    yield
    clear_all_for_tests()


def test_instance_default_not_revoked():
    assert is_instance_revoked("inst-1") is False


def test_revoke_instance_marks_revoked():
    revoke_instance("inst-1")
    assert is_instance_revoked("inst-1") is True


def test_revoke_instance_only_affects_target():
    revoke_instance("inst-1")
    assert is_instance_revoked("inst-2") is False


def test_revoke_jti():
    revoke_jti("jti-xyz")
    assert is_jti_revoked("jti-xyz") is True
    assert is_jti_revoked("jti-other") is False


def test_revoke_user():
    revoke_user("user-1")
    assert is_user_revoked("user-1") is True
    assert is_user_revoked("user-2") is False


def test_axes_are_independent():
    revoke_instance("inst-1")
    # user and jti namespaces are untouched
    assert is_user_revoked("inst-1") is False
    assert is_jti_revoked("inst-1") is False


def test_clear_all():
    revoke_instance("i")
    revoke_user("u")
    revoke_jti("j")
    clear_all_for_tests()
    assert not is_instance_revoked("i")
    assert not is_user_revoked("u")
    assert not is_jti_revoked("j")


def test_ttl_expiry_via_fallback():
    """When stored entry's expiry has passed, is_*_revoked returns False."""
    revoke_instance("inst-short", ttl=1)
    # Manually rewind expiry to the past
    from storage.tenant_store import _fallback_store
    key = "shield:revoke:instance:inst-short"
    _fallback_store[key] = "0"  # already-expired timestamp
    assert is_instance_revoked("inst-short") is False
