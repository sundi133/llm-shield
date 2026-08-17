"""The two halves of "may administer" must give one answer.

API key scopes decide what a credential may do. Portal sessions decide who a
person is. Both now reach require_registry_write, and the failure mode is
subtle in both directions:

  * an administrator who signs in but cannot do what an admin key can do makes
    SSO a downgrade, and people go back to sharing the key
  * a non-administrator who signs in and CAN write the registry makes SSO a
    privilege escalation dressed as a login

So this file tests the matrix directly rather than each half separately. The
combinations are the point; the individual rows are covered elsewhere.

Spec: docs/spec-portal-sso.md section 5 and section 8
"""
import pytest
from types import SimpleNamespace

from fastapi import HTTPException

import core.auth as auth
from storage import portal_sessions as ps, tenant_store as ts

TENANT = "acme"
ADMIN_KEY = "sk-admin-aaaaaaaaaaaaaaaaaaaa"
RUNTIME_KEY = "sk-runtime-bbbbbbbbbbbbbbbb"
LEGACY_KEY = "sk-legacy-cccccccccccccccccc"
CLAIMS = {"sub": "3f9c-dana", "email": "dana@acme.com",
          "issuer": "https://keycloak.internal/realms/acme"}


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    ts.add_api_key(TENANT, RUNTIME_KEY, scope="runtime")
    ts.add_api_key(TENANT, LEGACY_KEY)
    monkeypatch.setattr(auth, "_store_is_degraded", lambda: False)
    return data


def _request(*, key=None, session=None):
    """A request carrying a key, a session, both, or neither."""
    state = SimpleNamespace()
    if key:
        state.tenant_id = TENANT
        state.api_key_hash = ts._hash_key(key)
    cookies = {auth.PORTAL_COOKIE_NAME: session} if session else {}
    return SimpleNamespace(state=state, cookies=cookies, headers={},
                           client=None, url="/v1/agents/registry")


def _allowed(request) -> bool:
    try:
        auth.require_registry_write(request)
        return True
    except HTTPException:
        return False


# ── the matrix ───────────────────────────────────────────────────────────


def _principals(store):
    return {
        "admin key":       _request(key=ADMIN_KEY),
        "runtime key":     _request(key=RUNTIME_KEY),
        "unscoped key":    _request(key=LEGACY_KEY),
        "admin session":   _request(session=ps.create_session(
            TENANT, CLAIMS, is_admin=True)),
        "non-admin session": _request(session=ps.create_session(
            TENANT, CLAIMS, is_admin=False)),
    }


EXPECTED_ENFORCE = {
    "admin key": True,
    "runtime key": False,
    "unscoped key": False,
    "admin session": True,
    "non-admin session": False,
}


@pytest.mark.parametrize("who,expected", sorted(EXPECTED_ENFORCE.items()))
def test_the_matrix_under_enforce(store, monkeypatch, who, expected):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert _allowed(_principals(store)[who]) is expected


@pytest.mark.parametrize("who", sorted(EXPECTED_ENFORCE))
def test_everyone_writes_when_enforcement_is_off(store, monkeypatch, who):
    """off must stay byte-identical to before any of this existed."""
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    assert _allowed(_principals(store)[who]) is True


@pytest.mark.parametrize("who", sorted(EXPECTED_ENFORCE))
def test_everyone_writes_under_warn(store, monkeypatch, who):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    assert _allowed(_principals(store)[who]) is True


# ── the two failure directions, stated explicitly ────────────────────────


def test_sso_is_not_a_downgrade(store, monkeypatch):
    """An administrator who signs in must be able to do what an admin key can
    do. If not, people go back to sharing the key and SSO is theatre."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    assert _allowed(_request(session=sid)) is True


def test_sso_is_not_an_escalation(store, monkeypatch):
    """A non-administrator who signs in must be refused exactly like a runtime
    key. Otherwise a login IS the privilege escalation."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    assert _allowed(_request(session=sid)) is False


# ── precedence when both are present ─────────────────────────────────────


def test_a_non_admin_session_is_not_rescued_by_an_admin_key(store, monkeypatch):
    """The likely real-world combination: an admin key left in localStorage
    from before SSO, and a non-admin human signed in on top of it. The human
    is who is acting, so the human's answer must win.

    Deciding this the other way would let anyone who can authenticate borrow
    the shared key's privileges, which is the shared-key problem wearing a
    login page.
    """
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    assert _allowed(_request(key=ADMIN_KEY, session=sid)) is False


def test_an_admin_session_is_not_blocked_by_a_runtime_key(store, monkeypatch):
    """The mirror case, and the one that would make SSO feel broken."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    assert _allowed(_request(key=RUNTIME_KEY, session=sid)) is True


def test_a_revoked_session_falls_back_to_the_key(store, monkeypatch):
    """Revocation must take effect on the next request, and the caller then
    is whatever credential remains."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    req = _request(key=RUNTIME_KEY, session=sid)
    assert _allowed(req) is True
    ps.revoke_session(sid)
    assert _allowed(_request(key=RUNTIME_KEY, session=sid)) is False


# ── warn mode records the human, not just the key ────────────────────────


def test_warn_records_a_non_admin_human(store, monkeypatch):
    """The rollout procedure reads this audit to find who enforce would break.
    A signed-in non-administrator is exactly such a caller, and recording only
    key-based callers would make the preflight lie by omission."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    recorded: list = []
    monkeypatch.setattr(auth, "_record_scope_warning",
                        lambda req, t, s, a: recorded.append(s))
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    auth.require_registry_write(_request(session=sid))
    assert recorded == ["user:not-admin"]


def test_warn_is_silent_for_an_admin_human(store, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    recorded: list = []
    monkeypatch.setattr(auth, "_record_scope_warning",
                        lambda req, t, s, a: recorded.append(s))
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    auth.require_registry_write(_request(session=sid))
    assert recorded == []


# ── refusal messages name the right subject ──────────────────────────────


def test_a_refused_human_is_named(store, monkeypatch):
    """"This API key is scoped 'None'" would be a baffling thing to show
    somebody who just signed in with their work account."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    with pytest.raises(HTTPException) as e:
        auth.require_registry_write(_request(session=sid))
    assert "dana@acme.com" in e.value.detail
    assert "administrator" in e.value.detail


def test_a_refused_key_still_talks_about_scope(store, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    with pytest.raises(HTTPException) as e:
        auth.require_registry_write(_request(key=RUNTIME_KEY))
    assert "runtime" in e.value.detail
    assert "SHIELD_REGISTRY_WRITE_SCOPE" in e.value.detail
