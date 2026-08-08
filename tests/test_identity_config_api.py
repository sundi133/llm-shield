"""Tenant self-service role-binding config (admin plane).

The storage key has existed for a while with no writer at all — configuring a
tenant for Okta meant hand-writing JSON with redis-cli. These pin the endpoint
that closes that, and the two properties that make it safe to expose:

  * the tenant comes from verified request state, never the body or a path
    parameter, so there is no cross-tenant write;
  * a tenant may strengthen its own role binding but not weaken the deployment
    baseline, so self-service cannot undo an operator's SHIELD_ROLE_BINDING.

Spec: docs/spec-idp-role-claim-config.md task 2
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_identity_config as mod
from core.identity_resolution import clear_role_binding_cache_for_tests

BASE = "/v1/tenant/me/identity/role-binding"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SHIELD_ROLE_BINDING", raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


@pytest.fixture
def store(monkeypatch):
    """In-memory stand-in for the Redis-backed config, per tenant."""
    saved: dict = {}

    monkeypatch.setattr(mod, "get_config", lambda t: saved.get(t))

    def _set(tenant_id, cfg):
        saved[tenant_id] = cfg
        return cfg

    monkeypatch.setattr(mod, "set_config", _set)
    monkeypatch.setattr(mod, "log_admin_action", lambda **kw: saved
                        .setdefault("_audit", []).append(kw))
    return saved


@pytest.fixture
def client(store):
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(mod.router)
    return TestClient(app)


def _hdr(tenant="bankco"):
    return {"X-Test-Tenant": tenant}


# ── auth ─────────────────────────────────────────────────────────────────


def test_get_requires_a_tenant(client):
    assert client.get(BASE).status_code == 401


def test_put_requires_a_tenant(client):
    assert client.put(BASE, json={"role_claim": "groups"}).status_code == 401


def test_presets_require_a_tenant(client):
    assert client.get(f"{BASE}/presets").status_code == 401


# ── cross-tenant isolation ───────────────────────────────────────────────


def test_write_is_scoped_to_the_calling_tenant(client, store):
    """There is no tenant_id in the path or body, so a caller cannot name
    another tenant's config. This asserts the shape, not just the behaviour."""
    r = client.put(BASE, json={"role_claim": "groups"}, headers=_hdr("bankco"))
    assert r.status_code == 200
    assert "bankco" in store
    assert set(store) - {"_audit"} == {"bankco"}


def test_one_tenant_cannot_read_anothers_config(client, store):
    client.put(BASE, json={"role_claim": "groups"}, headers=_hdr("bankco"))
    r = client.get(BASE, headers=_hdr("otherco"))
    assert r.status_code == 200
    assert r.json()["role_claim"] == "realm_access.roles"   # its own default


def test_body_tenant_id_is_ignored(client, store):
    """An extra tenant_id in the body must not redirect the write."""
    client.put(BASE, json={"role_claim": "groups", "tenant_id": "victim"},
               headers=_hdr("bankco"))
    assert "victim" not in store


# ── reads ────────────────────────────────────────────────────────────────


def test_unconfigured_tenant_gets_the_keycloak_default(client):
    body = client.get(BASE, headers=_hdr()).json()
    assert body["role_claim"] == "realm_access.roles"
    assert body["role_map"] == {}
    assert body["mode"] is None


def test_view_explains_why_a_mode_is_not_taking_effect(client, store, monkeypatch):
    """SHIELD_ROLE_BINDING=off overrides tenant config globally. Without this
    the tenant sees 'prefer' stored, watches header roles keep winning, and has
    nothing to look at."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    store["bankco"] = {"mode": "prefer"}
    body = client.get(BASE, headers=_hdr()).json()
    assert body["mode"] == "prefer"
    assert body["effective_mode"] == "off"
    assert body["env_kill_switch"] is True


def test_effective_mode_reflects_the_tenant_when_env_allows(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    store["bankco"] = {"mode": "strict"}
    body = client.get(BASE, headers=_hdr()).json()
    assert body["effective_mode"] == "strict"
    assert body["env_kill_switch"] is False


def test_presets_cover_the_major_idps(client):
    presets = client.get(f"{BASE}/presets", headers=_hdr()).json()["presets"]
    assert presets["keycloak"]["role_claim"] == "realm_access.roles"
    assert presets["okta"]["role_claim"] == "groups"
    assert presets["entra"]["role_claim"] == "roles"


# ── writes ───────────────────────────────────────────────────────────────


def test_put_persists_and_returns_the_new_view(client, store):
    r = client.put(BASE, json={"role_claim": "groups",
                               "role_map": {"bank-payments": "payments_officer"}},
                   headers=_hdr())
    assert r.status_code == 200
    assert r.json()["role_claim"] == "groups"
    assert store["bankco"]["role_map"] == {"bank-payments": "payments_officer"}


def test_put_merges_rather_than_replaces(client, store):
    """An operator changing the claim path should not have to restate the map."""
    client.put(BASE, json={"role_map": {"g": "r"}}, headers=_hdr())
    client.put(BASE, json={"role_claim": "groups"}, headers=_hdr())
    assert store["bankco"]["role_map"] == {"g": "r"}
    assert store["bankco"]["role_claim"] == "groups"


def test_put_records_provenance(client, store):
    client.put(BASE, json={"role_claim": "groups"}, headers=_hdr())
    assert store["bankco"]["updated_by"] == "tenant:bankco"
    assert store["bankco"]["updated_at"]


def test_put_writes_the_admin_audit(client, store):
    client.put(BASE, json={"role_claim": "groups"}, headers=_hdr())
    actions = [e["action"] for e in store["_audit"]]
    assert "identity.role_binding.update" in actions


def test_storage_failure_is_a_503_not_a_silent_drop(client, store, monkeypatch):
    """A config that looks saved and is not leaves the operator believing role
    binding is configured."""
    def _boom(tenant_id, cfg):
        raise RuntimeError("redis down")

    monkeypatch.setattr(mod, "set_config", _boom)
    r = client.put(BASE, json={"role_claim": "groups"}, headers=_hdr())
    assert r.status_code == 503


# ── validation ───────────────────────────────────────────────────────────


def test_unknown_mode_is_refused(client):
    r = client.put(BASE, json={"mode": "striict"}, headers=_hdr())
    assert r.status_code == 422


@pytest.mark.parametrize("mode", ["off", "prefer", "strict", "strict_proxy"])
def test_every_real_mode_is_accepted(client, mode):
    assert client.put(BASE, json={"mode": mode}, headers=_hdr()).status_code == 200


def test_empty_role_claim_is_refused(client):
    assert client.put(BASE, json={"role_claim": "   "}, headers=_hdr()).status_code == 422


def test_oversized_role_claim_is_refused(client):
    r = client.put(BASE, json={"role_claim": "x" * 129}, headers=_hdr())
    assert r.status_code == 422


def test_oversized_role_map_is_refused(client):
    r = client.put(BASE, json={"role_map": {f"k{i}": "r" for i in range(257)}},
                   headers=_hdr())
    assert r.status_code == 422


def test_oversized_role_map_term_is_refused(client):
    r = client.put(BASE, json={"role_map": {"x" * 129: "r"}}, headers=_hdr())
    assert r.status_code == 422


def test_empty_role_map_term_is_refused(client):
    assert client.put(BASE, json={"role_map": {"g": "  "}},
                      headers=_hdr()).status_code == 422


def test_role_allowlist_is_refused_while_unenforced(client):
    """Storing a control nothing enforces is worse than not offering it: the
    operator sets it, believes roles outside it are refused, and they are not."""
    r = client.put(BASE, json={"role_allowlist": ["a"]}, headers=_hdr())
    assert r.status_code == 422
    assert "not enforced" in r.json()["detail"]


# ── a tenant may strengthen, never weaken ────────────────────────────────


def test_tenant_cannot_weaken_the_deployment_baseline(client, monkeypatch):
    """An operator who set strict made a security decision. A tenant storing
    'off' over it would quietly undo that for their own traffic."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "strict")
    r = client.put(BASE, json={"mode": "off"}, headers=_hdr())
    assert r.status_code == 422
    assert "weaker" in r.json()["detail"]


def test_tenant_cannot_downgrade_strict_to_prefer(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "strict")
    assert client.put(BASE, json={"mode": "prefer"},
                      headers=_hdr()).status_code == 422


def test_tenant_may_strengthen(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    assert client.put(BASE, json={"mode": "strict"},
                      headers=_hdr()).status_code == 200


def test_env_off_lets_a_tenant_set_anything(client, monkeypatch):
    """With the kill switch on, no tenant mode takes effect anyway, so there is
    no baseline to protect — and refusing writes would block staging a config
    before turning binding on."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    assert client.put(BASE, json={"mode": "prefer"},
                      headers=_hdr()).status_code == 200


def test_strict_proxy_ranks_below_strict(client, monkeypatch):
    """strict_proxy accepts a vouched header; strict accepts nothing. The
    ordering must reflect that or the guard lets through a real downgrade."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "strict")
    assert client.put(BASE, json={"mode": "strict_proxy"},
                      headers=_hdr()).status_code == 422
