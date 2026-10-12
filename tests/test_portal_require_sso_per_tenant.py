"""Per-tenant `require_sso` (operator-controlled) on the portal routes.

PR 2 of docs/specs/spec-sso-primary-login.md. The platform operator can require
SSO for one tenant at a time (set via PUT /v1/admin/tenants/{id}); when on, the
API key is refused on /v1/tenant/* but a session still works, and the key is
UNAFFECTED on the guard/API path. The flag is NOT tenant self-service — a tenant
able to switch off its own requirement would not have been required to sign in.
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_tenant_self as tenant_self
import core.auth as auth
from storage import portal_sessions as ps, tenant_store as ts

TENANT = "acme"
API_KEY = "sk-key-aaaaaaaaaaaaaaaaaaaa"
CLAIMS = {"sub": "3f9c-dana", "email": "dana@acme.com", "name": "Dana Okoro",
          "issuer": "https://keycloak.internal/realms/acme"}


class _KeyAuth(BaseHTTPMiddleware):
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
    monkeypatch.delenv("SHIELD_PORTAL_REQUIRE_SSO", raising=False)
    ts.add_api_key(TENANT, API_KEY)
    return data


@pytest.fixture
def tenant_record():
    # Mutable: a test sets require_sso on it. None models a store blip.
    return {"tenant_id": TENANT, "name": TENANT}


@pytest.fixture
def client(store, tenant_record, monkeypatch):
    monkeypatch.setattr(
        tenant_self, "get_tenant",
        lambda t: tenant_record if (t == TENANT and tenant_record is not None)
        else (None if tenant_record is None else {"tenant_id": t}))
    app = FastAPI()
    app.add_middleware(_KeyAuth)
    app.include_router(tenant_self.router)
    return TestClient(app)


def _session(client, cookie):
    client.cookies.set(auth.PORTAL_COOKIE_NAME, cookie)


def _get(client, path, *, key=None):
    headers = {"X-API-Key": key} if key else {}
    if not key:
        client.cookies.clear()
    return client.get(path, headers=headers)


# ── default OFF is non-breaking ──────────────────────────────────────────


def test_key_works_when_require_sso_off(client):
    """Default (no flag) must not change today's behavior."""
    assert _get(client, "/v1/tenant/me/session", key=API_KEY).status_code == 200


# ── operator turns it on for ONE tenant ──────────────────────────────────


def test_key_refused_when_tenant_requires_sso(client, tenant_record):
    tenant_record["require_sso"] = True
    r = _get(client, "/v1/tenant/me/session", key=API_KEY)
    assert r.status_code == 403
    assert "SSO" in r.text


def test_session_still_works_when_require_sso_on(client, store, tenant_record):
    """SSO users are unaffected — the session resolves before the key check."""
    tenant_record["require_sso"] = True
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    _session(client, sid)
    assert client.get("/v1/tenant/me/session").status_code == 200


def test_env_flag_requires_sso_even_if_tenant_flag_off(client, monkeypatch):
    """Deployment-wide env posture OR per-tenant — either one requires SSO."""
    monkeypatch.setenv("SHIELD_PORTAL_REQUIRE_SSO", "1")
    assert _get(client, "/v1/tenant/me/session", key=API_KEY).status_code == 403


# ── the guard/API path is UNAFFECTED (the key still authenticates) ───────
# _require_tenant only governs /v1/tenant/* portal routes; resolve_tenant_by_api_key
# (the guard path) never calls it. This asserts the demotion is scoped.


def test_require_sso_does_not_touch_key_tenant_resolution(store, tenant_record):
    tenant_record["require_sso"] = True
    # The guard path resolves the tenant straight from the key, no portal check.
    assert ts.resolve_tenant_by_api_key(API_KEY) == TENANT


# ── transparency endpoint, read-only ─────────────────────────────────────


def test_portal_auth_reports_tenant_source(client, tenant_record):
    tenant_record["require_sso"] = True
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    _session(client, sid)
    d = client.get("/v1/tenant/me/portal-auth").json()
    assert d["require_sso"] is True
    assert d["source"] == "tenant"
    assert d["editable_by_tenant"] is False


def test_portal_auth_reports_env_source(client, monkeypatch):
    monkeypatch.setenv("SHIELD_PORTAL_REQUIRE_SSO", "1")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    _session(client, sid)
    d = client.get("/v1/tenant/me/portal-auth").json()
    assert d["require_sso"] is True and d["source"] == "env"


def test_portal_auth_default_source(client):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    _session(client, sid)
    d = client.get("/v1/tenant/me/portal-auth").json()
    assert d["require_sso"] is False and d["source"] == "default"


# ── the loophole is closed: a tenant cannot set its own requirement ──────


def test_tenant_has_no_self_service_write(client):
    """No PUT/POST on the tenant side — only the operator (admin plane) sets it."""
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    _session(client, sid)
    assert client.put("/v1/tenant/me/portal-auth",
                      json={"require_sso": False}).status_code in (404, 405)


# ── store blip must not escalate the per-tenant flag ─────────────────────


def test_store_blip_does_not_escalate(store, monkeypatch):
    """get_tenant returns None on a Redis blip -> per-tenant flag can't be read,
    so it does not spuriously REQUIRE sso (env posture alone governs)."""
    monkeypatch.setattr(tenant_self, "get_tenant", lambda t: None)
    monkeypatch.delenv("SHIELD_PORTAL_REQUIRE_SSO", raising=False)
    assert tenant_self._require_sso_enabled(TENANT) is False


# ── the operator's write surface carries the field ───────────────────────


def test_admin_update_model_accepts_require_sso():
    from storage.tenant_models import TenantUpdateRequest
    m = TenantUpdateRequest(require_sso=True)
    assert m.model_dump(exclude_none=True) == {"require_sso": True}
