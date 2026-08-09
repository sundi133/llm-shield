"""Agent ownership: who to ask, and never who may act.

A registry entry recorded when an agent was created and never by whom. That is
the first question in an access review, and a reviewer with nobody to ask
either rubber-stamps the campaign or stalls it — both of which make the
campaign worthless.

The load-bearing test here is `test_no_authorization_path_reads_owner`.
Everything else is plumbing. `owner` is free text a tenant admin types, so the
moment a grant depends on it, an authorization decision depends on an
unverified string. That invariant is the kind that erodes one convenient
exception at a time, so it is asserted rather than documented.

Spec: docs/spec-agent-ownership-environment.md
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_agents_registry as reg
import api.routes_governance as gov

TENANT = "acme"


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


@pytest.fixture
def store(monkeypatch):
    """In-memory stand-in for the Redis-backed registry."""
    data: dict = {}

    monkeypatch.setattr(reg, "get_redis_data", lambda k: data.get(k))
    monkeypatch.setattr(reg, "_save_agents",
                        lambda t, agents: data.__setitem__(f"agents:{t}", agents))
    monkeypatch.setattr(reg, "get_tenant_from_api_key", lambda r: TENANT)
    monkeypatch.setattr(gov, "get_redis_data", lambda k: data.get(k))
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda r: TENANT)
    monkeypatch.setattr(gov, "_activity_index", lambda t: {})
    return data


@pytest.fixture
def client(store):
    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.include_router(reg.router)
    app.include_router(gov.router)
    return TestClient(app)


def _hdr():
    return {"X-API-Key": TENANT}


def _create(client, agent_id="payments-bot", **extra):
    body = {"agent_id": agent_id, "name": agent_id, "tools": ["read_logs"]}
    body.update(extra)
    return client.post("/v1/agents/registry", json=body, headers=_hdr())


# ── round trip ───────────────────────────────────────────────────────────


def test_owner_round_trips(client):
    r = _create(client, owner="team-payments",
                owner_contact="payments-oncall@example.com")
    assert r.status_code == 200, r.text
    agent = r.json()["agent"]
    assert agent["owner"] == "team-payments"
    assert agent["owner_contact"] == "payments-oncall@example.com"


def test_owner_is_optional(client):
    """Every entry written before this field existed must stay valid."""
    r = _create(client)
    assert r.status_code == 200
    assert r.json()["agent"]["owner"] == ""


def test_owner_survives_an_unrelated_update(client):
    """A PUT about tools must not silently delete the owner.

    The merge already behaves this way; asserted because a future refactor to
    a replace-semantics update would quietly drop metadata people rely on.
    """
    _create(client, owner="team-payments")
    r = client.put("/v1/agents/registry/payments-bot",
                   json={"tools": ["read_logs", "restart_service"]}, headers=_hdr())
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["owner"] == "team-payments"


def test_owner_can_be_changed(client):
    _create(client, owner="team-payments")
    r = client.put("/v1/agents/registry/payments-bot",
                   json={"owner": "team-treasury"}, headers=_hdr())
    assert r.json()["agent"]["owner"] == "team-treasury"


# ── validation ───────────────────────────────────────────────────────────


def test_oversized_owner_refused(client):
    assert _create(client, owner="x" * 129).status_code == 400


def test_oversized_contact_refused(client):
    assert _create(client, owner_contact="x" * 257).status_code == 400


def test_non_string_owner_refused(client):
    assert _create(client, owner={"team": "payments"}).status_code == 400


def test_owner_is_sanitized(client):
    """Same treatment as name and description — it renders in the portal."""
    agent = _create(client, owner="<script>alert(1)</script>").json()["agent"]
    assert "<script>" not in agent["owner"]


# ── the invariant ────────────────────────────────────────────────────────


def test_no_authorization_path_reads_owner():
    """Ownership is metadata. No grant, denial or capability may depend on it.

    Checked by reading the source of the authorization paths rather than by
    behaviour: a behavioural test only catches an owner that changes an outcome
    today, while this catches the reference that will change one tomorrow.
    """
    import inspect
    from guardrails.agentic import rbac_guard
    import api.routes_agent_auth as agent_auth

    for mod in (rbac_guard, agent_auth):
        src = inspect.getsource(mod)
        for token in ('"owner"', "'owner'", ".owner", "owner_contact"):
            assert token not in src, (
                f"{mod.__name__} references {token} — ownership is free text a "
                f"tenant types, and an authorization decision must not depend "
                f"on it. See the spec, section 5.")


# ── governance surfaces it ───────────────────────────────────────────────


def test_governance_lists_owner(client):
    _create(client, owner="team-payments", owner_contact="#payments")
    agents = client.get("/v1/governance/agents", headers=_hdr()).json()["agents"]
    entry = next(a for a in agents if a["agent_id"] == "payments-bot")
    assert entry["owner"] == "team-payments"
    assert entry["owner_contact"] == "#payments"


def test_governance_owner_defaults_to_empty_not_missing(client):
    """The portal renders this directly; None would print as "null"."""
    _create(client)
    agents = client.get("/v1/governance/agents", headers=_hdr()).json()["agents"]
    assert agents[0]["owner"] == ""


# ── the unowned report ───────────────────────────────────────────────────


def test_unowned_lists_only_agents_without_an_owner(client):
    _create(client, agent_id="owned-bot", owner="team-a")
    _create(client, agent_id="orphan-bot")
    r = client.get("/v1/governance/agents/unowned", headers=_hdr()).json()
    ids = [a["agent_id"] for a in r["agents"]]
    assert ids == ["orphan-bot"]
    assert r["unowned_count"] == 1
    assert r["registered_count"] == 2


def test_whitespace_owner_counts_as_unowned(client):
    """A space is not an owner, and someone will type one to clear the field."""
    _create(client, agent_id="orphan-bot", owner="   ")
    r = client.get("/v1/governance/agents/unowned", headers=_hdr()).json()
    assert r["unowned_count"] == 1


def test_unowned_is_ordered_by_blast_radius(client):
    """Most-granted first: that is the one worth chasing an owner for."""
    _create(client, agent_id="small-bot", tools=["read_logs"])
    _create(client, agent_id="big-bot",
            tools=["read_logs", "restart_service", "rotate_credential"])
    agents = client.get("/v1/governance/agents/unowned",
                        headers=_hdr()).json()["agents"]
    assert [a["agent_id"] for a in agents] == ["big-bot", "small-bot"]


def test_unowned_is_empty_not_404_when_all_owned(client):
    _create(client, owner="team-a")
    r = client.get("/v1/governance/agents/unowned", headers=_hdr())
    assert r.status_code == 200
    assert r.json()["agents"] == []


def test_unowned_route_is_not_shadowed_by_the_agent_id_route(client):
    """/agents/unowned must not resolve as /agents/{agent_id}."""
    r = client.get("/v1/governance/agents/unowned", headers=_hdr())
    assert r.status_code == 200
    assert "unowned_count" in r.json()


# ── environments: write-side validation (enforcement lives in
#    test_agent_environment.py) ────────────────────────────────────────────


def test_environments_round_trip(client):
    agent = _create(client, environments=["prod", "staging"]).json()["agent"]
    assert agent["environments"] == ["prod", "staging"]


def test_environments_default_to_empty(client):
    """Empty means "runs anywhere" — the pre-existing behaviour."""
    assert _create(client).json()["agent"]["environments"] == []


def test_non_list_environments_refused(client):
    assert _create(client, environments="prod").status_code == 400


def test_too_many_environments_refused(client):
    assert _create(client, environments=[f"e{i}" for i in range(17)]).status_code == 400


def test_empty_environment_name_refused(client):
    assert _create(client, environments=["prod", "  "]).status_code == 400


def test_oversized_environment_name_refused(client):
    assert _create(client, environments=["x" * 65]).status_code == 400


def test_environments_survive_an_unrelated_update(client):
    _create(client, environments=["prod"])
    r = client.put("/v1/agents/registry/payments-bot",
                   json={"name": "renamed"}, headers=_hdr())
    assert r.json()["agent"]["environments"] == ["prod"]


def test_governance_lists_environments(client):
    _create(client, environments=["staging"])
    agents = client.get("/v1/governance/agents", headers=_hdr()).json()["agents"]
    assert agents[0]["environments"] == ["staging"]
