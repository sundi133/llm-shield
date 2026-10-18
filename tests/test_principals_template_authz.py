"""Identity writes behind the write gate, scoped admin keys on policy templates,
and API keys that cannot change tenant.
Spec: docs/specs/principals-and-template-authz.md.

Gap 1: with SHIELD_REGISTRY_WRITE_SCOPE=enforce, a runtime tenant key could
still create a service account with any roles and mint it a key (a verified MCP
caller), switch "verified callers only" off, or remap IdP groups to roles. The
routes relied on require_portal_admin, which returns for a key caller, or on
nothing.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

T = "acme"
RUNTIME, UNSCOPED, ADMIN = "sk-acme-runtime-0001", "sk-acme-unscoped-001", "sk-acme-admin-00001"


# ── gap 1 ────────────────────────────────────────────────────────────


@pytest.fixture
def stores(monkeypatch):
    import storage.oauth_store as os_store
    import storage.principal_store as ps
    import storage.revocation as rev
    import storage.tenant_store as ts
    from storage.tenant_store import _fallback_store
    for mod in (ts, ps, rev):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
    for name in ("SHIELD_REGISTRY_WRITE_SCOPE", "REDIS_URL", "UPSTASH_REDIS_REST_URL",
                 "SHIELD_ROLE_BINDING"):
        monkeypatch.delenv(name, raising=False)
    _fallback_store.clear()
    os_store.clear_all_for_tests()
    ts._cache.clear() if hasattr(ts, "_cache") else None
    ts.create_tenant(T, {"name": "Acme"})
    ts.add_api_key(T, RUNTIME, scope="runtime")
    ts.add_api_key(T, UNSCOPED)
    ts.add_api_key(T, ADMIN, scope="admin")
    yield
    _fallback_store.clear()
    os_store.clear_all_for_tests()


@pytest.fixture
def audit(monkeypatch):
    rows = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: rows.append(k))
    return rows


@pytest.fixture
def client(stores, audit):
    """The four routers, behind a stand-in for AuthMiddleware: the tenant and
    the authenticating key's hash on request.state, as in production."""
    import api.routes_identity_config as idc
    import api.routes_mcp_admin as mcp_admin
    import api.routes_mcp_signin as signin
    import api.routes_principals as principals
    from storage.tenant_store import _hash_key, resolve_tenant_by_api_key
    app = FastAPI()

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        key = request.headers.get("X-API-Key", "")
        tenant = resolve_tenant_by_api_key(key) if key else None
        if tenant:
            request.state.tenant_id = tenant
            request.state.api_key_hash = _hash_key(key)
        return await call_next(request)
    for r in (principals.router, principals.sa_router, signin.router, mcp_admin.router, idc.router):
        app.include_router(r)
    return TestClient(app)


@pytest.fixture
def world(stores):
    """A service account with a key and an OAuth client, a person, an MCP server."""
    import asyncio
    import time
    import storage.principal_store as ps
    from storage.mcp_gateway_store import set_upstream
    from storage.oauth_store import OAuthClient, save_client
    sa = ps.create_service_account(T, name="ci", roles=["reader"], created_by="test")
    _, key = ps.create_principal_key(T, sa["id"], label="k")
    asyncio.run(save_client(OAuthClient(
        client_id="cid-1", client_name="sa", client_secret_hash="x", redirect_uris=[],
        grant_types=["client_credentials"], token_endpoint_auth_method="client_secret_post",
        scope="mcp", tenant_id=T, created_at=int(time.time()), principal_id=sa["id"])))
    set_upstream(T, "github", {"url": "https://mcp.example.com", "require_verified_identity": True})
    return {"sa": sa["id"], "key_id": key["key_id"], "client_id": "cid-1"}


def routes(w):
    sa, kid, cid = w["sa"], w["key_id"], w["client_id"]
    return [
        ("POST", "/v1/tenant/me/service-accounts", {"name": "evil", "roles": ["admin"]}),
        ("PATCH", f"/v1/tenant/me/principals/{sa}", {"roles": ["admin"]}),
        ("POST", f"/v1/tenant/me/principals/{sa}/keys", {"label": "mine"}),
        ("POST", f"/v1/tenant/me/principals/{sa}/keys/{kid}/rotate", {}),
        ("DELETE", f"/v1/tenant/me/principals/{sa}/keys/{kid}", None),
        ("POST", f"/v1/tenant/me/principals/{sa}/oauth-clients", None),
        ("DELETE", f"/v1/tenant/me/principals/{sa}/oauth-clients/{cid}", None),
        ("POST", f"/v1/tenant/me/principals/{sa}/suspend", None),
        ("POST", f"/v1/tenant/me/principals/{sa}/reactivate", None),
        ("DELETE", f"/v1/tenant/me/service-accounts/{sa}", None),
        ("PUT", "/v1/tenant/me/identity/policy", {"require_verified_identity": False}),
        ("PUT", "/v1/tenant/me/mcp/servers/github/identity", {"require_verified_identity": False}),
        ("PUT", "/v1/tenant/me/identity/role-binding", {"role_map": {"Everyone": "admin"}}),
    ]


ROUTE_IDS = ["create-sa", "update-sa", "mint-key", "rotate-key", "delete-key", "create-oauth",
             "delete-oauth", "suspend", "reactivate", "remove-sa", "identity-policy",
             "server-identity", "role-binding"]


def call(client, method, path, body, key):
    return client.request(method, path, json=body, headers={"X-API-Key": key})


def snapshot(w):
    import asyncio
    import storage.principal_store as ps
    from core.principal_lifecycle import principal_clients
    from storage.identity_policy import get_policy
    from storage.mcp_gateway_store import get_upstream
    from storage.role_binding_config import get_config
    return {
        "principals": sorted((p["id"], tuple(p.get("roles") or ()), p.get("status"))
                             for p in ps.list_principals(T)),
        "keys": sorted(k["key_id"] for k in ps.list_principal_keys(T, w["sa"])),
        "clients": sorted(c.client_id for c in asyncio.run(principal_clients(T, w["sa"]))),
        "policy": get_policy(T),
        "server": (get_upstream(T, "github") or {}).get("require_verified_identity"),
        "binding": (get_config(T) or {}).get("role_map"),
    }


@pytest.mark.parametrize("i", range(13), ids=ROUTE_IDS)
@pytest.mark.parametrize("key", [RUNTIME, UNSCOPED], ids=["runtime", "unscoped"])
def test_enforce_refuses_a_non_admin_key_and_changes_nothing(client, world, monkeypatch, i, key):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    before = snapshot(world)
    method, path, body = routes(world)[i]
    r = call(client, method, path, body, key)
    assert r.status_code == 403, (path, r.status_code, r.text)
    assert snapshot(world) == before


@pytest.mark.parametrize("i", range(13), ids=ROUTE_IDS)
def test_enforce_allows_an_admin_scoped_key(client, world, monkeypatch, i):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    method, path, body = routes(world)[i]
    r = call(client, method, path, body, ADMIN)
    assert r.status_code < 300, (path, r.status_code, r.text)


@pytest.mark.parametrize("i", range(13), ids=ROUTE_IDS)
def test_enforce_allows_a_portal_administrator(client, world, monkeypatch, i):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    admin = {"kind": "user", "tenant_id": T, "sub": "u1", "email": "a@acme.com", "is_admin": True}
    monkeypatch.setattr("core.auth.portal_principal", lambda r: admin)
    method, path, body = routes(world)[i]
    r = call(client, method, path, body, RUNTIME)          # a stale key in the browser
    assert r.status_code < 300, (path, r.status_code, r.text)


@pytest.mark.parametrize("i", range(13), ids=ROUTE_IDS)
def test_off_is_unchanged(client, world, i):
    method, path, body = routes(world)[i]
    r = call(client, method, path, body, RUNTIME)
    assert r.status_code < 300, (path, r.status_code, r.text)


@pytest.mark.parametrize("i", range(13), ids=ROUTE_IDS)
def test_warn_allows_and_records_who_enforce_would_refuse(client, world, monkeypatch, i):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    warned = []
    monkeypatch.setattr("core.auth._record_scope_warning",
                        lambda req, tenant, scope, action: warned.append((tenant, scope, action)))
    method, path, body = routes(world)[i]
    r = call(client, method, path, body, RUNTIME)
    assert r.status_code < 300, (path, r.status_code, r.text)
    assert warned and warned[0][0] == T and warned[0][1] == "runtime"


@pytest.mark.parametrize("i", [0, 1, 2, 5, 7, 10], ids=["create-sa", "update-sa", "mint-key",
                                                        "create-oauth", "suspend", "identity-policy"])
def test_a_signed_in_non_administrator_is_refused_in_every_mode(client, world, monkeypatch, i):
    user = {"kind": "user", "tenant_id": T, "sub": "u2", "email": "b@acme.com", "is_admin": False}
    monkeypatch.setattr("core.auth.portal_principal", lambda r: user)
    method, path, body = routes(world)[i]
    for mode in ("off", "warn", "enforce"):
        monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", mode)
        assert call(client, method, path, body, ADMIN).status_code == 403, (mode, path)


def test_enforce_with_an_unreadable_key_store_is_503(client, world, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    monkeypatch.setattr("core.auth._store_is_degraded", lambda: True)
    method, path, body = routes(world)[0]
    assert call(client, method, path, body, ADMIN).status_code == 503


def test_the_headline_a_runtime_key_cannot_mint_itself_a_verified_admin(client, world, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = call(client, "POST", "/v1/tenant/me/service-accounts", {"name": "me", "roles": ["admin"]}, RUNTIME)
    assert r.status_code == 403 and "use an admin-scoped key" in r.json()["detail"].lower()
    r = call(client, "POST", "/v1/tenant/me/service-accounts", {"name": "ci2", "roles": ["admin"]}, ADMIN)
    assert r.status_code == 200 and r.json()["roles"] == ["admin"]


def test_reads_are_unchanged(client, world, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert call(client, "GET", "/v1/tenant/me/principals", None, RUNTIME).status_code == 200
    assert call(client, "GET", "/v1/tenant/me/identity/policy", None, RUNTIME).status_code == 200


# ── route-table guards, both apps ────────────────────────────────────


def _apps():
    """The real apps' live route tables. core.app is built under a patched
    load_config, as every app test does (it binds load_config by name)."""
    from unittest.mock import patch
    import config.schema as cs
    import admin_app
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        data = create_app()
    cs.config = original
    return {"data": data, "admin": admin_app.app}


def _reaches(fn, needles, depth=2, _seen=None):
    """Whether fn's source, or a module-level helper it calls (to `depth`),
    contains one of `needles`."""
    import inspect
    import re
    import sys
    _seen = _seen or set()
    if fn in _seen:
        return False
    _seen.add(fn)
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        return False
    if any(n in src for n in needles):
        return True
    if depth == 0:
        return False
    mod = sys.modules.get(getattr(fn, "__module__", ""), None)
    for name in set(re.findall(r"\b(_[A-Za-z0-9_]+)\(", src)):
        helper = getattr(mod, name, None)
        if callable(helper) and _reaches(helper, needles, depth - 1, _seen):
            return True
    return False


def _routes(app):
    for r in app.routes:
        ep, path = getattr(r, "endpoint", None), getattr(r, "path", "")
        for m in sorted((getattr(r, "methods", None) or set()) - {"HEAD", "OPTIONS"}):
            yield m, path, ep


IDENTITY_MODULES = {"api.routes_principals", "api.routes_identity_config"}
IDENTITY_ROUTES = {("PUT", "/v1/tenant/me/identity/policy"),
                   ("PUT", "/v1/tenant/me/mcp/servers/{route}/identity")}


def test_every_identity_write_route_passes_the_write_gate():
    """A new route that changes who is a verified caller, or what roles one has,
    must go through require_registry_write. Enumerates the live route tables, so
    a route added to either app is checked."""
    seen, ungated = set(), []
    for plane, app in _apps().items():
        for m, path, ep in _routes(app):
            if m not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            if ep.__module__ not in IDENTITY_MODULES and (m, path) not in IDENTITY_ROUTES:
                continue
            seen.add((m, path))
            if not _reaches(ep, ("require_registry_write(",)):
                ungated.append((plane, m, path))
    assert len(seen) >= 13, sorted(seen)
    assert not ungated, f"identity write route(s) without the write gate: {ungated}"


# ── gap 2 ────────────────────────────────────────────────────────────
#
# The policy-template routes were the only /v1/admin routes that did not hold
# a managed admin credential to its scope: one scoped to oidc:read on one
# tenant could switch any tenant to monitor mode (nothing blocks).

ROOT = "root-secret-key-templates"


@pytest.fixture
def admin_client(monkeypatch):
    import core.auth as auth
    import storage.tenant_store as ts
    from api.routes_admin_credentials import router as creds_router
    from api.routes_policy_templates import router as templates_router
    from core.auth import AuthMiddleware
    ts._fallback_store.clear()
    auth._failed_attempts.clear()
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.delenv("SHIELD_ADMIN_CREDENTIALS", raising=False)
    for t in ("acme", "globex"):
        ts.create_tenant(t, {"name": t, "policy_mode": "enforce"})
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(templates_router)
    app.add_middleware(AuthMiddleware)
    yield TestClient(app)
    ts._fallback_store.clear()
    auth._failed_attempts.clear()


def _cred(client, name, scope=None):
    body = {"name": name, **({"scope": scope} if scope is not None else {})}
    r = client.post("/v1/admin/credentials", json=body, headers={"X-Admin-Key": ROOT})
    assert r.status_code == 200, r.text
    return {"X-Admin-Key": r.json()["secret"]}, r.json()["id"]


def _template_id():
    from core.policy_templates import list_templates
    t = list_templates()
    return (t[0]["id"] if isinstance(t[0], dict) else t[0])


def _mode(t):
    from storage.tenant_store import get_tenant
    return get_tenant(t).get("policy_mode")


def _guardrails(t):
    from storage.tenant_store import get_tenant
    cfg = get_tenant(t) or {}
    return cfg.get("input_guardrails"), cfg.get("output_guardrails")


def test_a_credential_scoped_to_something_else_cannot_switch_a_tenant_to_monitor(admin_client):
    h, _ = _cred(admin_client, "oidc-reader", {"operations": ["oidc:read"], "tenants": ["acme"]})
    before = _guardrails("globex")
    r = admin_client.put("/v1/admin/tenants/globex/policy-mode", json={"mode": "monitor"}, headers=h)
    assert r.status_code == 403 and _mode("globex") == "enforce"
    r = admin_client.post("/v1/admin/tenants/globex/apply-template",
                          json={"template_id": _template_id()}, headers=h)
    assert r.status_code == 403 and _guardrails("globex") == before


def test_tenants_write_works_on_its_tenant_only(admin_client):
    h, _ = _cred(admin_client, "acme-writer", {"operations": ["tenants:write", "tenants:read"],
                                               "tenants": ["acme"]})
    assert admin_client.put("/v1/admin/tenants/acme/policy-mode", json={"mode": "monitor"},
                            headers=h).status_code == 200
    assert _mode("acme") == "monitor"
    assert admin_client.post("/v1/admin/tenants/acme/apply-template",
                             json={"template_id": _template_id()}, headers=h).status_code == 200
    assert admin_client.put("/v1/admin/tenants/globex/policy-mode", json={"mode": "monitor"},
                            headers=h).status_code == 403
    assert _mode("globex") == "enforce"


def test_tenants_read_reads_but_does_not_write(admin_client):
    h, _ = _cred(admin_client, "acme-reader", {"operations": ["tenants:read"], "tenants": ["acme"]})
    assert admin_client.get("/v1/admin/tenants/acme/policy-mode", headers=h).status_code == 200
    assert admin_client.get("/v1/admin/tenants/globex/policy-mode", headers=h).status_code == 403
    assert admin_client.get("/v1/admin/policy-templates", headers=h).status_code == 200
    assert admin_client.put("/v1/admin/tenants/acme/policy-mode", json={"mode": "monitor"},
                            headers=h).status_code == 403


def test_the_catalog_needs_tenants_read(admin_client):
    h, _ = _cred(admin_client, "oidc-only", {"operations": ["oidc:read"]})
    assert admin_client.get("/v1/admin/policy-templates", headers=h).status_code == 403
    assert admin_client.get(f"/v1/admin/policy-templates/{_template_id()}", headers=h).status_code == 403


def test_root_operators_and_full_admin_credentials_are_unaffected(admin_client):
    from core.auth import ADMIN_COOKIE_NAME
    from storage.admin_sessions import create_session
    full, _ = _cred(admin_client, "full-admin")
    for h in ({"X-Admin-Key": ROOT}, full):
        assert admin_client.put("/v1/admin/tenants/globex/policy-mode", json={"mode": "monitor"},
                                headers=h).status_code == 200
        assert admin_client.get("/v1/admin/policy-templates", headers=h).status_code == 200
    sid = create_session({"sub": "op-1", "email": "op@votal.ai"}, roles=["platform-admin"])
    admin_client.cookies.set(ADMIN_COOKIE_NAME, sid)
    assert admin_client.put("/v1/admin/tenants/acme/policy-mode", json={"mode": "monitor"}).status_code == 200
    admin_client.cookies.delete(ADMIN_COOKIE_NAME)


def test_audit_rows_name_the_credential(admin_client, monkeypatch):
    import api.routes_policy_templates as rt
    rows = []
    monkeypatch.setattr(rt, "log_admin_action", lambda **kw: rows.append(kw["actor"]))
    h, cid = _cred(admin_client, "acme-writer", {"operations": ["tenants:write"], "tenants": ["acme"]})
    admin_client.put("/v1/admin/tenants/acme/policy-mode", json={"mode": "monitor"}, headers=h)
    admin_client.post("/v1/admin/tenants/acme/apply-template", json={"template_id": _template_id()},
                      headers={"X-Admin-Key": ROOT})
    assert rows == [f"adminkey:{cid}", "adminroot"]


def test_every_admin_route_holds_a_credential_to_its_scope():
    """Every /v1/admin route on both apps reaches require_admin_scope (or is
    root/operator only). The policy-template routes were the gap; this keeps
    the next one from appearing."""
    missing = []
    for plane, app in _apps().items():
        for m, path, ep in _routes(app):
            if not path.startswith("/v1/admin/") or path.startswith("/v1/admin/auth/"):
                continue
            if not _reaches(ep, ("require_admin_scope(", "require_admin_root_or_operator(")):
                missing.append((plane, m, path))
    assert not missing, f"/v1/admin route(s) that ignore a credential's scope: {sorted(set(missing))}"


# ── gap 3 ────────────────────────────────────────────────────────────
#
# Every writer overwrote apikey:{hash}, so whoever could name a key string
# moved the key, and all its traffic, into their tenant. sk-test-healthcare is
# published and long enough to be a custom key.

KEY_A, KEY_B = "sk-tenant-a-key-0000001", "sk-tenant-b-key-0000001"


@pytest.fixture
def keys(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    for name in ("SHIELD_REGISTRY_WRITE_SCOPE", "REDIS_URL", "UPSTASH_REDIS_REST_URL"):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts._cache.clear() if hasattr(ts, "_cache") else None
    ts.create_tenant("ta", {"name": "A"}, api_keys=[KEY_A])
    ts.create_tenant("tb", {"name": "B"}, api_keys=[KEY_B])
    yield ts
    ts._fallback_store.clear()


def test_a_key_cannot_be_added_to_another_tenant(keys):
    with pytest.raises(keys.KeyInUseError):
        keys.add_api_key("ta", KEY_B, scope="admin")
    assert keys.key_owner(KEY_B) == "tb" and keys.key_scope(KEY_B) is None
    with pytest.raises(keys.KeyInUseError):
        keys.create_tenant("tc", {"name": "C"}, api_keys=["sk-fresh-key-00000001", KEY_B])
    assert keys.get_tenant("tc") is None                       # nothing half-created
    assert keys.key_owner("sk-fresh-key-00000001") is None
    assert keys.key_owner(KEY_B) == "tb"


def test_re_adding_to_the_owner_rescopes_and_delete_then_add_moves(keys):
    keys.add_api_key("tb", KEY_B, scope="admin")
    assert keys.key_scope(KEY_B) == "admin" and keys.key_owner(KEY_B) == "tb"
    keys.remove_api_key(KEY_B)
    keys.add_api_key("ta", KEY_B)
    assert keys.key_owner(KEY_B) == "ta"


class _FakeRedis:
    """SET NX and GET with a lock, like Redis, to race two claims."""

    def __init__(self):
        import threading
        self.d, self.lock = {}, threading.Lock()

    def set(self, k, v, nx=False, ex=None):
        with self.lock:
            if nx and k in self.d:
                return None
            self.d[k] = v
            return True

    def get(self, k):
        with self.lock:
            return self.d.get(k)


def test_two_tenants_racing_for_one_key_cannot_both_win(keys, monkeypatch):
    import threading
    fake = _FakeRedis()
    monkeypatch.setattr(keys, "_get_redis", lambda: fake)
    barrier, won, lost = threading.Barrier(2), [], []

    def claim(t):
        barrier.wait()
        try:
            keys._claim_key("racehash", t)
            won.append(t)
        except keys.KeyInUseError:
            lost.append(t)
    threads = [threading.Thread(target=claim, args=(t,)) for t in ("ta", "tb")]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(won) == 1 and len(lost) == 1
    assert fake.get("apikey:racehash") == won[0]


def test_bytes_from_redis_are_the_owner(keys, monkeypatch):
    fake = _FakeRedis()
    fake.d["apikey:h"] = b"ta"
    monkeypatch.setattr(keys, "_get_redis", lambda: fake)
    keys._claim_key("h", "ta")                                  # its own: fine
    with pytest.raises(keys.KeyInUseError):
        keys._claim_key("h", "tb")


@pytest.fixture
def self_service(keys):
    import api.routes_tenant_self as rts
    from storage.tenant_store import _hash_key, resolve_tenant_by_api_key
    app = FastAPI()

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        key = request.headers.get("X-API-Key", "")
        tenant = resolve_tenant_by_api_key(key) if key else None
        if tenant:
            request.state.tenant_id = tenant
            request.state.api_key_hash = _hash_key(key)
        return await call_next(request)
    app.include_router(rts.router)
    return TestClient(app)


def test_self_service_cannot_claim_another_tenants_key(self_service, keys):
    r = self_service.post("/v1/tenant/me/api-keys", json={"custom_key": KEY_B},
                          headers={"X-API-Key": KEY_A})
    assert r.status_code == 409 and "tb" not in r.text
    assert keys.key_owner(KEY_B) == "tb"


def test_self_service_cannot_claim_the_quickstart_key(self_service, keys):
    r = self_service.post("/v1/tenant/me/api-keys", json={"custom_key": "sk-test-healthcare"},
                          headers={"X-API-Key": KEY_A})
    assert r.status_code == 400 and "reserved for the sandbox" in r.text
    assert keys.key_owner("sk-test-healthcare") is None          # still the sandbox fallback


def test_self_service_generated_keys_still_work(self_service, keys):
    r = self_service.post("/v1/tenant/me/api-keys", json={"label": "ci"}, headers={"X-API-Key": KEY_A})
    assert r.status_code == 200 and keys.key_owner(r.json()["api_key"]) == "ta"


def test_self_service_revoke_is_behind_the_write_gate(self_service, keys, monkeypatch):
    keys.add_api_key("ta", "sk-tenant-a-runtime-01", scope="runtime")
    keys.add_api_key("ta", "sk-tenant-a-other-0001")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = self_service.request("DELETE", "/v1/tenant/me/api-keys", json={"api_key": "sk-tenant-a-other-0001"},
                             headers={"X-API-Key": "sk-tenant-a-runtime-01"})
    assert r.status_code == 403 and keys.key_owner("sk-tenant-a-other-0001") == "ta"
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "off")
    r = self_service.request("DELETE", "/v1/tenant/me/api-keys", json={"api_key": "sk-tenant-a-other-0001"},
                             headers={"X-API-Key": "sk-tenant-a-runtime-01"})
    assert r.status_code == 200 and keys.key_owner("sk-tenant-a-other-0001") is None


@pytest.fixture
def tenants_admin(keys, monkeypatch):
    import core.auth as auth
    from api.routes_admin_credentials import router as creds_router
    from api.routes_tenant import router as tenant_router
    from core.auth import AuthMiddleware
    auth._failed_attempts.clear()
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.delenv("SHIELD_ADMIN_CREDENTIALS", raising=False)
    app = FastAPI()
    app.include_router(creds_router)
    app.include_router(tenant_router)
    app.add_middleware(AuthMiddleware)
    yield TestClient(app)
    auth._failed_attempts.clear()


def test_admin_add_cannot_move_another_tenants_key(tenants_admin, keys):
    h, _ = _cred(tenants_admin, "a-writer", {"operations": ["tenants:write"], "tenants": ["ta"]})
    r = tenants_admin.post("/v1/admin/tenants/ta/api-keys", json={"api_key": KEY_B}, headers=h)
    assert r.status_code == 409 and keys.key_owner(KEY_B) == "tb"
    r = tenants_admin.post("/v1/admin/tenants/ta/api-keys", json={"api_key": "sk-test-quickstart-1"},
                           headers={"X-Admin-Key": ROOT})
    assert r.status_code == 400
    r = tenants_admin.post("/v1/admin/tenants/test-tenant-001/api-keys",
                           json={"api_key": "sk-test-quickstart-1"}, headers={"X-Admin-Key": ROOT})
    assert r.status_code == 404                                   # no sandbox tenant yet
    keys.create_tenant("test-tenant-001", {"name": "sandbox"})
    r = tenants_admin.post("/v1/admin/tenants/test-tenant-001/api-keys",
                           json={"api_key": "sk-test-quickstart-1"}, headers={"X-Admin-Key": ROOT})
    assert r.status_code == 200 and keys.key_owner("sk-test-quickstart-1") == "test-tenant-001"


def test_admin_create_tenant_cannot_take_a_key(tenants_admin, keys):
    r = tenants_admin.post("/v1/admin/tenants", json={"tenant_id": "tc", "api_keys": [KEY_B]},
                           headers={"X-Admin-Key": ROOT})
    assert r.status_code == 409 and keys.get_tenant("tc") is None and keys.key_owner(KEY_B) == "tb"
    r = tenants_admin.post("/v1/admin/tenants", json={"tenant_id": "tc", "api_keys": ["sk-test-mine-00000"]},
                           headers={"X-Admin-Key": ROOT})
    assert r.status_code == 400 and keys.get_tenant("tc") is None


def test_admin_delete_only_removes_the_tenants_own_key(tenants_admin, keys):
    h, _ = _cred(tenants_admin, "a-writer", {"operations": ["tenants:write"], "tenants": ["ta"]})
    r = tenants_admin.request("DELETE", "/v1/admin/tenants/ta/api-keys", json={"api_key": KEY_B}, headers=h)
    assert r.status_code == 404 and keys.key_owner(KEY_B) == "tb"
    unknown = tenants_admin.request("DELETE", "/v1/admin/tenants/ta/api-keys",
                                    json={"api_key": "sk-nobody-has-this-1"}, headers=h)
    assert unknown.status_code == 404 and unknown.json() == r.json()   # cannot probe ownership
    r = tenants_admin.request("DELETE", "/v1/admin/tenants/ta/api-keys", json={"api_key": KEY_A}, headers=h)
    assert r.status_code == 200 and keys.key_owner(KEY_A) is None


def test_the_seed_route_reports_a_taken_seed_key(keys, monkeypatch):
    import api.routes_agents_registry as reg
    monkeypatch.setenv("SEED_TEST_API_KEY", KEY_B)
    monkeypatch.delenv("SHIELD_ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    app = FastAPI()
    app.include_router(reg.router)
    r = TestClient(app).post("/v1/agents/seed-test-data")
    if r.status_code in (403, 404):
        pytest.skip(f"seed route not reachable in this configuration ({r.status_code})")
    assert r.status_code == 409 and "SEED_TEST_API_KEY" in r.text
    assert keys.key_owner(KEY_B) == "tb"
