"""Registry writes require an admin-scoped key — off, then warn, then enforce.

An agent must hold a tenant key to be guarded, and that same key could rewrite
the agent registry and grant the agent every tool. This is the enforcement half
of the split.

Three things here carry the weight:

  * `test_every_write_path_is_gated` — parameterised over ALL of them. A
    control covering five of six paths is a bypass with a changelog entry, and
    the first draft of the spec missed three paths by reading imports.
  * `test_a_bearer_caller_is_enforced_too` — the helper reads the hash the
    middleware stashed. A version reading X-API-Key would exempt every Bearer
    caller silently.
  * `test_self_minting_cannot_choose_its_own_scope` — a caller that could pick
    the scope of a key it mints would mint itself an admin key.

Spec: docs/spec-registry-write-authorization.md PR 2
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_agents_registry as reg
import api.routes_agent_policy as agent_policy
import api.routes_policy as policy
import api.routes_tenant_self as tenant_self
from storage import policy_store, tenant_store as ts

TENANT = "acme"
SANDBOX = "test-tenant-001"
ADMIN_KEY = "sk-admin-aaaaaaaaaaaaaaaaaaaa"
RUNTIME_KEY = "sk-runtime-bbbbbbbbbbbbbbbb"
LEGACY_KEY = "sk-legacy-cccccccccccccccccc"

audit: list = []


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    for mod in (ts, policy_store):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
        monkeypatch.setattr(mod, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})

    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    ts.add_api_key(TENANT, RUNTIME_KEY, scope="runtime")
    ts.add_api_key(TENANT, LEGACY_KEY)

    audit.clear()
    import core.auth as auth
    monkeypatch.setattr(auth, "_record_scope_warning",
                        lambda req, t, s, a: audit.append({"scope": s, "action": a}))
    return data


class _Auth(BaseHTTPMiddleware):
    """Stands in for AuthMiddleware: resolves the tenant AND stashes the hash,
    from either header, exactly as the real one does."""

    async def dispatch(self, request: Request, call_next):
        key = (request.headers.get("X-API-Key")
               or (request.headers.get("Authorization") or "")[7:]).strip()
        if key:
            request.state.tenant_id = (
                SANDBOX if key.startswith("sk-test-") else TENANT)
            request.state.api_key_hash = ts._hash_key(key)
        return await call_next(request)


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setattr(reg, "get_tenant_from_api_key",
                        lambda r: getattr(r.state, "tenant_id", TENANT))
    monkeypatch.setattr(policy, "get_tenant", lambda t: {"tenant_id": t})
    monkeypatch.setattr(tenant_self, "_require_tenant", lambda r: TENANT)
    monkeypatch.setattr(tenant_self, "log_admin_action", lambda **kw: {})
    monkeypatch.setattr(tenant_self, "get_tenant", lambda t: {"tenant_id": t})
    app = FastAPI()
    app.add_middleware(_Auth)
    for r in (reg.router, agent_policy.router, policy.router, tenant_self.router):
        app.include_router(r)
    return TestClient(app)


def _h(key):
    return {"X-API-Key": key}


# Every path that reaches a registry write. Enumerated from the live route
# tables, not from reading imports — that is how three were missed.
def _create_registry(c, key, aid="bot-a"):
    return c.post("/v1/agents/registry", headers=_h(key), json={
        "agent_id": aid, "name": aid, "tools": ["read_logs"]})


def _create_register(c, key, aid="bot-b"):
    return c.post("/v1/agents/register", headers=_h(key), json={
        "agent_id": aid, "name": aid, "tools": ["read_logs"],
        "role_permissions": {"r": ["read_logs"]}})


def _update(c, key, aid="bot-a"):
    return c.put(f"/v1/agents/registry/{aid}", headers=_h(key),
                 json={"name": "renamed"})


def _delete(c, key, aid="bot-a"):
    return c.delete(f"/v1/agents/registry/{aid}", headers=_h(key))


def _bundle(c, key):
    return c.post(f"/v1/shield/policies/{TENANT}/bundle/import", headers=_h(key),
                  json={"tenant_id": TENANT, "policies": [], "agent_configs": {
                      "bundle-bot": {"name": "Bundle Bot", "tools": ["read_logs"]}}})


def _mint_key(c, key):
    return c.post("/v1/tenant/me/api-keys", headers=_h(key), json={})


WRITE_PATHS = [
    ("POST /v1/agents/registry", _create_registry),
    ("POST /v1/agents/register", _create_register),
    ("PUT /v1/agents/registry/{id}", _update),
    ("DELETE /v1/agents/registry/{id}", _delete),
    ("POST bundle/import", _bundle),
    ("POST /v1/tenant/me/api-keys", _mint_key),
]


# ── off: byte-identical to today ─────────────────────────────────────────


@pytest.mark.parametrize("name,call", WRITE_PATHS, ids=[p[0] for p in WRITE_PATHS])
def test_off_allows_a_runtime_key(client, monkeypatch, name, call):
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    assert call(client, RUNTIME_KEY).status_code != 403


def test_off_records_no_warning(client, monkeypatch):
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    _create_registry(client, RUNTIME_KEY)
    assert audit == []


# ── enforce: the whole point ─────────────────────────────────────────────


@pytest.mark.parametrize("name,call", WRITE_PATHS, ids=[p[0] for p in WRITE_PATHS])
def test_every_write_path_is_gated(client, monkeypatch, name, call):
    """A control that covers five of six paths is a bypass with a changelog
    entry. An enforcement gap on DELETE is the same escalation as one on
    POST."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert call(client, RUNTIME_KEY).status_code == 403, f"{name} was not gated"


@pytest.mark.parametrize("name,call", WRITE_PATHS, ids=[p[0] for p in WRITE_PATHS])
def test_an_unscoped_legacy_key_is_refused(client, monkeypatch, name, call):
    """The migration cliff, and it is deliberate: allowing unscoped keys would
    make enforcement decorative, since every key today is unscoped."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert call(client, LEGACY_KEY).status_code == 403, f"{name} let it through"


@pytest.mark.parametrize("name,call", WRITE_PATHS, ids=[p[0] for p in WRITE_PATHS])
def test_an_admin_key_still_writes(client, monkeypatch, name, call):
    """Enforcement that refuses everything is not enforcement."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert call(client, ADMIN_KEY).status_code != 403, f"{name} refused an admin key"


def test_the_refusal_names_the_flag_and_the_scope(client, monkeypatch):
    """An operator reading a deploy log must tell this from an expired key."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    body = _create_registry(client, RUNTIME_KEY).json()["detail"]
    assert "runtime" in body
    assert "SHIELD_REGISTRY_WRITE_SCOPE" in body


def test_the_unscoped_refusal_says_how_to_fix_it(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    body = _create_registry(client, LEGACY_KEY).json()["detail"]
    assert "scope=admin" in body


def test_a_403_is_not_swallowed_into_a_500(client, monkeypatch):
    """Those handlers wrap everything in try/except Exception. The refusal has
    to survive it."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert _create_registry(client, RUNTIME_KEY).status_code == 403


# ── warn: the preflight ──────────────────────────────────────────────────


def test_warn_allows_the_write(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    assert _create_registry(client, RUNTIME_KEY).status_code != 403


def test_warn_records_the_caller_it_would_break(client, monkeypatch):
    """Warn's only output, and what the rollout procedure actually reads."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    _create_registry(client, RUNTIME_KEY)
    assert audit and audit[-1]["scope"] == "runtime"


def test_warn_records_unscoped_keys_too(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    _create_registry(client, LEGACY_KEY)
    assert audit and audit[-1]["scope"] is None


def test_warn_is_silent_for_an_admin_key(client, monkeypatch):
    """A quiet audit is the signal that enforce is safe to turn on."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    _create_registry(client, ADMIN_KEY)
    assert audit == []


# ── the ways this could be bypassed ──────────────────────────────────────


def test_a_bearer_caller_is_enforced_too(client, monkeypatch):
    """The helper reads the stashed hash. A version reading X-API-Key would
    exempt every Authorization: Bearer caller — silently, and completely."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = client.post("/v1/agents/registry",
                    headers={"Authorization": f"Bearer {RUNTIME_KEY}"},
                    json={"agent_id": "bot-x", "name": "x", "tools": []})
    assert r.status_code == 403


def test_the_helper_does_not_read_the_api_key_header_alone():
    """Source-level companion. A behavioural test only catches the bypass that
    exists today."""
    import inspect
    import core.auth as auth
    src = inspect.getsource(auth.caller_key_scope)
    assert "api_key_hash" in src, "must prefer the stashed hash"


def test_self_minting_cannot_choose_its_own_scope(client, monkeypatch):
    """A caller that could pick the scope of a key it mints would mint itself
    an admin key and the whole mechanism would be decorative."""
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    r = client.post("/v1/tenant/me/api-keys", headers=_h(RUNTIME_KEY),
                    json={"custom_key": "sk-selfminted-dddddddddd", "scope": "admin"})
    assert r.status_code in (200, 201), r.text
    assert ts.key_scope("sk-selfminted-dddddddddd") is None, \
        "a self-minted key inherited a caller-chosen scope"


def test_seed_test_data_is_refused_under_enforce(client, monkeypatch):
    """It takes no credential at all, and its only other gate reads
    ENVIRONMENT — one letter of config from SHIELD_ENVIRONMENT."""
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert client.post("/v1/agents/seed-test-data").status_code == 403


def test_a_policy_only_bundle_does_not_need_an_admin_key(client, monkeypatch):
    """Importing policies is not a registry write and must not start needing
    an admin key because this endpoint can also carry agents."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = client.post(f"/v1/shield/policies/{TENANT}/bundle/import",
                    headers=_h(RUNTIME_KEY),
                    json={"policies": {}, "agent_configs": {}})
    assert r.status_code != 403


# ── the sandbox ──────────────────────────────────────────────────────────


def test_the_sandbox_tenant_is_exempt(client, monkeypatch):
    """A quickstart that requires a key-minting ceremony is a quickstart
    nobody finishes, and nothing of value lives in that one tenant."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = _create_registry(client, "sk-test-quickstart", aid="sandbox-bot")
    assert r.status_code != 403


# ── failure modes ────────────────────────────────────────────────────────


def test_fail_closed_when_the_key_store_is_unreadable(client, monkeypatch):
    """A refused write is recoverable by retrying; a wrongly-allowed one is a
    permanent grant nobody revisits."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    import core.auth as auth
    monkeypatch.setattr(auth, "_store_is_degraded", lambda: True)
    r = _create_registry(client, ADMIN_KEY)
    assert r.status_code == 503
    assert "scope" in r.json()["detail"].lower()


def test_a_degraded_store_does_not_break_a_deployment_that_opted_out(client, monkeypatch):
    """off and warn must survive a Redis blip untouched."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    import core.auth as auth
    monkeypatch.setattr(auth, "_store_is_degraded", lambda: True)
    assert _create_registry(client, RUNTIME_KEY).status_code != 503


def test_an_unknown_mode_reads_as_off(client, monkeypatch):
    """A typo must not silently enable a control that refuses traffic."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforced")   # typo
    assert _create_registry(client, RUNTIME_KEY).status_code != 403


def test_mode_comes_from_the_process_not_the_request(client, monkeypatch):
    """If a caller could send it, it would be X-User-Role all over again."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = client.post("/v1/agents/registry",
                    headers={**_h(RUNTIME_KEY), "X-Shield-Registry-Write-Scope": "off"},
                    json={"agent_id": "bot-y", "name": "y", "tools": []})
    assert r.status_code == 403


# ── no silent seventh path ───────────────────────────────────────────────


def test_no_ungated_write_route_has_appeared():
    """The first draft of the spec gated three routes because it found them by
    reading imports. This enumerates the live route table instead, and fails
    when a new write route appears in a module that can reach the registry.
    """
    import core.app as ca
    app = ca.create_app() if hasattr(ca, "create_app") else ca.app

    known = {
        ("POST", "/v1/agents/registry"),
        ("PUT", "/v1/agents/registry/{agent_id}"),
        ("DELETE", "/v1/agents/registry/{agent_id}"),
        ("POST", "/v1/agents/register"),
        ("POST", "/v1/shield/policies/{tenant_id}/bundle/import"),
        ("POST", "/v1/agents/seed-test-data"),
        ("POST", "/v1/tenant/me/api-keys"),
    }
    writers = {"api.routes_agents_registry", "api.routes_agent_policy",
               "api.routes_policy", "api.routes_tenant_self"}

    import inspect
    found = set()
    for r in app.routes:
        ep = getattr(r, "endpoint", None)
        if not ep or ep.__module__ not in writers:
            continue
        try:
            src = inspect.getsource(ep)
        except Exception:
            continue
        if "register_agent(" not in src and "_save_agents(" not in src \
                and "add_api_key(" not in src:
            continue
        for m in (getattr(r, "methods", None) or ()):
            if m in ("POST", "PUT", "DELETE"):
                found.add((m, r.path))

    new = found - known
    assert not new, (
        f"new route(s) reach a registry write and may be ungated: {sorted(new)}. "
        f"Add require_registry_write() and list them here.")
