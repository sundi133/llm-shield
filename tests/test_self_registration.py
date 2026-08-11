"""A developer may declare an agent. They may not grant it anything.

Scoping keys answers whether a credential may write the registry at all. Under
`enforce` a runtime key cannot, which is correct and also means a developer
needs an administrator to see their agent appear at all. That trade loses to a
model where they don't, so this is the softer control underneath: self-register
freely, arrive inert.

The load-bearing test is
`test_a_pending_agent_is_blocked_by_the_real_guard`. Everything else asserts
what gets written; that one proves the claim this design rests on — that the
enforcement already exists, because `_registry_agent_status()` has always
blocked a non-active agent. If that stops being true, `pending` silently
becomes "registered and running".

Spec: docs/spec-registry-write-authorization.md PR 3
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_agents_registry as reg
import api.routes_agent_policy as agent_policy
from storage import policy_store, tenant_store as ts

TENANT = "acme"
SANDBOX = "test-tenant-001"
ADMIN_KEY = "sk-admin-aaaaaaaaaaaaaaaaaaaa"
RUNTIME_KEY = "sk-runtime-bbbbbbbbbbbbbbbb"
LEGACY_KEY = "sk-legacy-cccccccccccccccccc"

GRANTS = {"tools": ["read_logs", "rotate_credential"],
          "role_permissions": {"intern": ["rotate_credential"]},
          "agent_permissions": {"other-bot": ["read_logs"]},
          "allowed_resources": ["service/*"]}


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
    return data


class _Auth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = (request.headers.get("X-API-Key") or "").strip()
        if key:
            request.state.tenant_id = (
                SANDBOX if key.startswith("sk-test-") else TENANT)
            request.state.api_key_hash = ts._hash_key(key)
        return await call_next(request)


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setattr(reg, "get_tenant_from_api_key",
                        lambda r: getattr(r.state, "tenant_id", TENANT))
    app = FastAPI()
    app.add_middleware(_Auth)
    app.include_router(reg.router)
    app.include_router(agent_policy.router)
    return TestClient(app)


def _create(c, key, aid="payments-bot", **extra):
    body = {"agent_id": aid, "name": aid, **GRANTS}
    body.update(extra)
    return c.post("/v1/agents/registry", headers={"X-API-Key": key}, json=body)


def _agent(c, key, aid="payments-bot"):
    return c.get("/v1/agents/registry",
                 headers={"X-API-Key": key}).json()["agents"][aid]


# ── on: today's behaviour ────────────────────────────────────────────────


def test_on_is_the_default(monkeypatch):
    monkeypatch.delenv("SHIELD_REGISTRY_SELF_REGISTER", raising=False)
    import core.auth as auth
    assert auth.self_register_mode() == "on"


def test_on_keeps_every_grant(client, monkeypatch):
    monkeypatch.delenv("SHIELD_REGISTRY_SELF_REGISTER", raising=False)
    assert _create(client, RUNTIME_KEY).status_code == 200
    a = _agent(client, RUNTIME_KEY)
    assert a["tools"] == GRANTS["tools"]
    assert a["status"] == "active"


def test_an_unknown_mode_reads_as_on(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "pendingg")   # typo
    _create(client, RUNTIME_KEY)
    assert _agent(client, RUNTIME_KEY)["status"] == "active"


# ── pending: declare yes, grant no ───────────────────────────────────────


@pytest.fixture
def pending(monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "pending")


def test_a_runtime_key_lands_pending(client, pending):
    assert _create(client, RUNTIME_KEY).status_code == 200
    assert _agent(client, RUNTIME_KEY)["status"] == "pending"


@pytest.mark.parametrize("field", sorted(GRANTS))
def test_every_grant_is_stripped_even_though_the_body_asked(client, pending, field):
    """The load-bearing assertion of this mode. A body carrying grants must
    not produce an agent that has them."""
    _create(client, RUNTIME_KEY)
    assert not _agent(client, RUNTIME_KEY)[field], \
        f"{field} survived self-registration"


def test_an_unscoped_key_is_constrained_too(client, pending):
    """Every key today is unscoped. If those were exempt this would do
    nothing at all until a migration nobody has run yet."""
    _create(client, LEGACY_KEY, aid="legacy-bot")
    assert _agent(client, LEGACY_KEY, "legacy-bot")["status"] == "pending"


def test_resource_scope_enforcement_is_not_left_on(client, pending):
    """require_resource_scope defaults from allowed_resources. Clearing the
    resources without clearing the flag would leave an agent that denies
    everything for a reason nobody can see."""
    _create(client, RUNTIME_KEY)
    assert _agent(client, RUNTIME_KEY)["require_resource_scope"] is False


def test_the_declaration_survives(client, pending):
    """A pending entry with no name or owner is not worth reviewing. Only
    grants are stripped."""
    _create(client, RUNTIME_KEY, name="Payments Bot",
            description="handles refunds", owner="team-payments",
            environments=["prod"])
    a = _agent(client, RUNTIME_KEY)
    assert a["name"] == "Payments Bot"
    assert a["description"] == "handles refunds"
    assert a["owner"] == "team-payments"
    assert a["environments"] == ["prod"]


def test_the_reviewer_can_see_why_it_is_pending(client, pending):
    _create(client, RUNTIME_KEY)
    assert _agent(client, RUNTIME_KEY)["self_registered"] is True


def test_an_admin_key_is_unaffected(client, pending):
    _create(client, ADMIN_KEY, aid="admin-bot")
    a = _agent(client, ADMIN_KEY, "admin-bot")
    assert a["status"] == "active"
    assert a["tools"] == GRANTS["tools"]


def test_the_sandbox_is_unaffected(client, pending):
    r = _create(client, "sk-test-quickstart", aid="sandbox-bot")
    assert r.status_code == 200
    assert r.json()["agent"]["status"] == "active"


def test_the_other_creation_route_is_constrained_too(client, pending):
    """POST /v1/agents/register reaches the registry by a different path. A
    constraint on one creation route is a documented bypass."""
    r = client.post("/v1/agents/register", headers={"X-API-Key": RUNTIME_KEY},
                    json={"agent_id": "other-route-bot", "name": "x",
                          "tools": ["rotate_credential"],
                          "role_permissions": {"intern": ["rotate_credential"]}})
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["status"] == "pending"
    assert r.json()["agent"]["tools"] == []


# ── updates are governed by the write scope, not by this ─────────────────


def test_an_update_does_not_demote_a_live_agent(client, monkeypatch):
    """Demoting a running agent to pending because someone renamed it would be
    an outage caused by a governance feature."""
    _create(client, ADMIN_KEY)
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "pending")
    r = client.put("/v1/agents/registry/payments-bot",
                   headers={"X-API-Key": RUNTIME_KEY}, json={"name": "renamed"})
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["status"] == "active"
    assert r.json()["agent"]["tools"] == GRANTS["tools"]


# ── off ──────────────────────────────────────────────────────────────────


def test_off_refuses_a_runtime_key(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "off")
    r = _create(client, RUNTIME_KEY)
    assert r.status_code == 403
    assert "SHIELD_REGISTRY_SELF_REGISTER" in r.json()["detail"]


def test_off_still_lets_an_admin_register(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "off")
    assert _create(client, ADMIN_KEY, aid="admin-bot").status_code == 200


def test_off_writes_nothing_when_it_refuses(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_SELF_REGISTER", "off")
    _create(client, RUNTIME_KEY)
    assert "payments-bot" not in (
        client.get("/v1/agents/registry",
                   headers={"X-API-Key": ADMIN_KEY}).json()["agents"])


# ── the claim this whole design rests on ─────────────────────────────────


def test_a_pending_agent_is_blocked_by_the_real_guard(store, monkeypatch):
    """No new enforcement code: _registry_agent_status() has always refused a
    non-active agent. This drives the real RBACGuard to prove it, because if
    that ever changes, `pending` silently means "registered and running".
    """
    import json
    from guardrails.agentic.rbac_guard import _registry_agent_status

    store[f"agents:{TENANT}"] = json.dumps({
        "pending-bot": {"agent_id": "pending-bot", "status": "pending",
                        "tools": [], "role_permissions": {}},
        "active-bot": {"agent_id": "active-bot", "status": "active",
                       "tools": ["read_logs"],
                       "role_permissions": {"intern": ["read_logs"]}},
    })
    import guardrails.agentic.rbac_guard as rg
    monkeypatch.setattr(rg, "_load_agent_entry",
                        lambda a, t: json.loads(store[f"agents:{t}"]).get(a))

    assert _registry_agent_status("pending-bot", TENANT) == "pending"
    assert _registry_agent_status("active-bot", TENANT) == "active"

    # Drive the real guard rather than assert on its source. A source check
    # passes just as well if the block moved somewhere it never runs.
    import asyncio
    guard = rg.RBACGuard()

    def _check(agent_key):
        return asyncio.run(guard.check("", {
            "agent_key": agent_key, "tool_name": "read_logs",
            "tenant_id": TENANT, "user_role": "intern"}))

    blocked = _check("pending-bot")
    assert blocked.passed is False, (
        "a pending agent was allowed — `pending` now means registered AND "
        "running. See docs/spec-registry-write-authorization.md")
    assert blocked.action == "block"
    assert "pending" in blocked.message
    # administrative: a softened action or monitor mode must not let it run.
    assert blocked.details.get("administrative") is True
