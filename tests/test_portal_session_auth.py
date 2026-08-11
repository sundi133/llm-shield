"""A portal session authenticates /v1/tenant/* the way an API key does.

One function change — _require_tenant — gives two dozen handlers session
support at once, which is also why it is the one place this has to be right.

The tests that carry weight:

  * `test_a_session_beats_a_stale_api_key` — a browser holding a key in
    localStorage from before SSO would otherwise keep acting as that key after
    the user signs in, and every action would stay attributed to the tenant.
  * `test_the_idor_defence_still_applies_to_a_session` — the spoof check reads
    the resolved tenant, and a version reading request.state alone returns
    early for session callers, silently disabling it for exactly the callers
    SSO introduces.
  * `test_an_api_key_still_works_unchanged` — SSO is opt-in per tenant and must
    not break the CI job that has been posting for a year.

Spec: docs/spec-portal-sso.md PR 3
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_tenant_self as tenant_self
import core.auth as auth
from storage import portal_sessions as ps, tenant_store as ts

TENANT = "acme"
OTHER = "globex"
API_KEY = "sk-key-aaaaaaaaaaaaaaaaaaaa"
CLAIMS = {"sub": "3f9c-dana", "email": "dana@acme.com", "name": "Dana Okoro",
          "issuer": "https://keycloak.internal/realms/acme"}


class _KeyAuth(BaseHTTPMiddleware):
    """Stands in for AuthMiddleware: only an API key sets state.tenant_id."""

    async def dispatch(self, request: Request, call_next):
        key = (request.headers.get("X-API-Key") or "").strip()
        if key:
            tid = ts.resolve_tenant_by_api_key(key)
            if tid:
                request.state.tenant_id = tid
                request.state.api_key_hash = ts._hash_key(key)
        return await call_next(request)


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    monkeypatch.delenv("SHIELD_PORTAL_SESSION_IDLE", raising=False)
    ts.add_api_key(TENANT, API_KEY)
    return data


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setattr(tenant_self, "get_tenant",
                        lambda t: {"tenant_id": t, "name": t})
    app = FastAPI()
    app.add_middleware(_KeyAuth)
    app.include_router(tenant_self.router)
    return TestClient(app)


@pytest.fixture
def session(store):
    return ps.create_session(TENANT, CLAIMS, is_admin=True)


def _me(client, *, cookie=None, key=None):
    if cookie:
        client.cookies.set(auth.PORTAL_COOKIE_NAME, cookie)
    else:
        client.cookies.clear()
    headers = {"X-API-Key": key} if key else {}
    return client.get("/v1/tenant/me/session", headers=headers)


# ── a session authenticates ──────────────────────────────────────────────


def test_a_session_authenticates(client, session):
    r = _me(client, cookie=session)
    assert r.status_code == 200, r.text
    assert r.json()["method"] == "sso"
    assert r.json()["email"] == "dana@acme.com"
    assert r.json()["tenant_id"] == TENANT


def test_the_session_reports_admin(client, store):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    assert _me(client, cookie=sid).json()["is_admin"] is True


def test_a_non_admin_session_reports_so(client, store):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    assert _me(client, cookie=sid).json()["is_admin"] is False


def test_no_credential_at_all_is_a_401(client):
    assert _me(client).status_code == 401


def test_an_expired_session_is_a_401(client, store, monkeypatch):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    monkeypatch.setattr(ps, "_now", lambda: 9_999_999_999)
    assert _me(client, cookie=sid).status_code == 401


def test_a_revoked_session_stops_working_immediately(client, session):
    """The whole reason sessions are server-side."""
    assert _me(client, cookie=session).status_code == 200
    ps.revoke_session(session)
    assert _me(client, cookie=session).status_code == 401


def test_a_garbage_cookie_is_a_401_not_a_500(client):
    assert _me(client, cookie="not-a-session").status_code == 401


# ── the API key path is untouched ────────────────────────────────────────


def test_an_api_key_still_works_unchanged(client):
    """SSO is opt-in per tenant. Enabling it must not break the CI job that
    has been posting to this API for a year."""
    r = _me(client, key=API_KEY)
    assert r.status_code == 200
    assert r.json()["method"] == "api_key"
    assert r.json()["tenant_id"] == TENANT


def test_a_key_is_not_a_person(client):
    """is_admin is null rather than false: a credential is not a person, and
    what it may do is governed by its scope."""
    assert _me(client, key=API_KEY).json()["is_admin"] is None


# ── precedence ───────────────────────────────────────────────────────────


def test_a_session_beats_a_stale_api_key(client, session):
    """A browser that still holds a tenant key in localStorage from before SSO
    would otherwise keep acting as that key after the user signs in, and every
    action would stay attributed to the tenant rather than to them."""
    r = _me(client, cookie=session, key=API_KEY)
    assert r.json()["method"] == "sso"
    assert r.json()["sub"] == "3f9c-dana"


def test_a_session_for_another_tenant_wins_over_the_key_tenant(client, store):
    """Precedence has to be complete, not partial: resolving the tenant from
    the key while taking the identity from the session would attribute one
    tenant's actions to another tenant's user."""
    sid = ps.create_session(OTHER, CLAIMS, is_admin=True)
    r = _me(client, cookie=sid, key=API_KEY)
    assert r.json()["tenant_id"] == OTHER


# ── the IDOR defence must not lapse ──────────────────────────────────────


def test_the_idor_defence_still_applies_to_a_session(client, session):
    """_reject_tenant_id_spoof reads the RESOLVED tenant. A version reading
    request.state alone returns early for a session caller — no API key means
    no state.tenant_id — silently disabling VAPT 8.2 for exactly the callers
    SSO introduces."""
    client.cookies.set(auth.PORTAL_COOKIE_NAME, session)
    r = client.get("/v1/tenant/me", headers={"X-Tenant-Id": OTHER})
    assert r.status_code == 403, r.text
    assert "does not match" in r.json()["detail"]


def test_a_matching_tenant_header_is_still_allowed(client, session):
    client.cookies.set(auth.PORTAL_COOKIE_NAME, session)
    r = client.get("/v1/tenant/me", headers={"X-Tenant-Id": TENANT})
    assert r.status_code != 403


# ── the principal helper ─────────────────────────────────────────────────


def test_the_principal_is_resolved_once_per_request(client, session, monkeypatch):
    """_require_tenant is called by two dozen handlers and some call it twice.
    A store read per call would multiply by that."""
    reads = {"n": 0}
    real = ps.get_session

    def counting(sid):
        reads["n"] += 1
        return real(sid)

    monkeypatch.setattr(ps, "get_session", counting)
    _me(client, cookie=session)
    assert reads["n"] == 1, f"session read {reads['n']} times in one request"


def test_a_broken_session_store_falls_back_to_the_key(client, monkeypatch):
    """A store failure must not 500 every portal request. The key path is
    exactly as trustworthy as it was before sessions existed."""
    def boom(_):
        raise RuntimeError("redis is down")

    monkeypatch.setattr(ps, "get_session", boom)
    client.cookies.set(auth.PORTAL_COOKIE_NAME, "anything")
    r = client.get("/v1/tenant/me/session", headers={"X-API-Key": API_KEY})
    assert r.status_code == 200 and r.json()["method"] == "api_key"


# ── admin gate ───────────────────────────────────────────────────────────


def test_require_portal_admin_passes_an_admin(store):
    from types import SimpleNamespace
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    req = SimpleNamespace(cookies={auth.PORTAL_COOKIE_NAME: sid},
                          state=SimpleNamespace())
    auth.require_portal_admin(req)          # no raise


def test_require_portal_admin_refuses_a_non_admin(store):
    from fastapi import HTTPException
    from types import SimpleNamespace
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    req = SimpleNamespace(cookies={auth.PORTAL_COOKIE_NAME: sid},
                          state=SimpleNamespace())
    with pytest.raises(HTTPException) as e:
        auth.require_portal_admin(req)
    assert e.value.status_code == 403
    assert "dana@acme.com" in e.value.detail


def test_require_portal_admin_is_silent_without_a_session(store):
    """Key-authenticated callers are governed by their scope instead, so this
    must layer over the existing checks rather than replace them."""
    from types import SimpleNamespace
    auth.require_portal_admin(SimpleNamespace(cookies={},
                                              state=SimpleNamespace()))


# ── the guard path, again ────────────────────────────────────────────────


def test_the_guard_path_does_not_resolve_a_principal():
    """portal_principal is an admin-plane concern. A guard-path caller reading
    it would put a store read on /guardrails/*."""
    import inspect
    from guardrails.agentic import rbac_guard
    import api.routes_classify as rc

    for mod in (rbac_guard, rc):
        src = inspect.getsource(mod)
        assert "portal_principal" not in src
        assert "portal_sessions" not in src
