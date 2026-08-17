"""Administrative actions name the human who took them.

This is the point of portal SSO. Everything before it was plumbing: sessions
that identify a person are worth nothing if the audit still says
`tenant:acme`, which answers "which organisation" rather than "who" — and
"who granted this agent production credentials" is the first question of an
access review.

Two rules run through all of it, and both are about not fabricating:

  * a KEY-authenticated write leaves created_by EMPTY rather than falling back
    to the tenant. "created_by: tenant:acme" on every row is attribution in
    shape only, and it would bury the rows that name a real person.
  * the audit records the SUBJECT, not the email. An email can be reassigned
    inside a directory; years later dana@acme.com may be a different person.

Spec: docs/spec-portal-sso.md PR 5
"""
import pytest
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_agents_registry as reg
import api.routes_governance as gov
import api.routes_tenant_self as tenant_self
import core.auth as auth
from storage import policy_store, portal_sessions as ps, tenant_store as ts

TENANT = "acme"
API_KEY = "sk-key-aaaaaaaaaaaaaaaaaaaa"
CLAIMS = {"sub": "3f9c-dana", "email": "dana@acme.com", "name": "Dana Okoro",
          "issuer": "https://keycloak.internal/realms/acme"}

audit: list = []


@pytest.fixture
def store(monkeypatch):
    data: dict = {}
    for mod in (ts, policy_store):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
        monkeypatch.setattr(mod, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    ts.add_api_key(TENANT, API_KEY)
    audit.clear()
    return data


class _KeyAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = (request.headers.get("X-API-Key") or "").strip()
        if key:
            request.state.tenant_id = TENANT
            request.state.api_key_hash = ts._hash_key(key)
        return await call_next(request)


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setattr(reg, "get_tenant_from_api_key", lambda r: TENANT)
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda r: TENANT)
    monkeypatch.setattr(gov, "_activity_index", lambda t: {})
    monkeypatch.setattr(tenant_self, "get_tenant",
                        lambda t: {"tenant_id": t, "name": t})
    # Returns the stored config in production; the bare in-memory store has no
    # tenant record so the real one returns None and the handler 500s before
    # reaching the audit call this test is about.
    monkeypatch.setattr(tenant_self, "set_tenant_policies",
                        lambda t, **kw: {"tenant_id": t, "input_guardrails": {},
                                         "output_guardrails": {}})
    monkeypatch.setattr(tenant_self, "log_admin_action",
                        lambda **kw: audit.append(kw) or {})
    app = FastAPI()
    app.add_middleware(_KeyAuth)
    for r in (reg.router, gov.router, tenant_self.router):
        app.include_router(r)
    return TestClient(app)


@pytest.fixture
def session(store):
    return ps.create_session(TENANT, CLAIMS, is_admin=True)


def _as_user(client, sid):
    client.cookies.set(auth.PORTAL_COOKIE_NAME, sid)
    return {}


def _as_key(client):
    client.cookies.clear()
    return {"X-API-Key": API_KEY}


def _create_agent(client, headers, agent_id="payments-bot"):
    return client.post("/v1/agents/registry", headers=headers, json={
        "agent_id": agent_id, "name": agent_id, "tools": ["read_logs"]})


# ── the audit actor ──────────────────────────────────────────────────────


def test_a_signed_in_human_is_the_actor(client, session):
    _as_user(client, session)
    client.put("/v1/tenant/me/policies", json={"input_guardrails": {}})
    assert audit and audit[-1]["actor"] == "user:3f9c-dana"


def test_a_key_still_records_the_tenant(client):
    """Unchanged for every caller that is not signed in, which is all of them
    until SSO is configured."""
    client.put("/v1/tenant/me/policies", headers=_as_key(client),
               json={"input_guardrails": {}})
    assert audit and audit[-1]["actor"] == f"tenant:{TENANT}"


def test_the_actor_is_the_subject_not_the_email(store):
    """An email can be reassigned inside a directory. Years later
    dana@acme.com may be somebody else entirely, and an audit trail that
    cannot tell is not an audit trail."""
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    req = SimpleNamespace(cookies={auth.PORTAL_COOKIE_NAME: sid},
                          state=SimpleNamespace())
    actor = auth.audit_actor(req, TENANT)
    assert actor == "user:3f9c-dana"
    assert "dana@acme.com" not in actor


def test_the_email_is_still_recorded_as_metadata(store):
    """Legibility: a reviewer should not have to resolve an opaque subject."""
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    req = SimpleNamespace(cookies={auth.PORTAL_COOKIE_NAME: sid},
                          state=SimpleNamespace())
    meta = auth.audit_actor_metadata(req)
    assert meta["actor_kind"] == "user"
    assert meta["actor_email"] == "dana@acme.com"
    assert meta["actor_issuer"] == CLAIMS["issuer"]


def test_key_metadata_claims_nothing(store):
    req = SimpleNamespace(cookies={}, state=SimpleNamespace(tenant_id=TENANT))
    assert auth.audit_actor_metadata(req) == {"actor_kind": "api_key"}


# ── created_by on registry entries ───────────────────────────────────────


def test_a_human_registration_records_created_by(client, session):
    r = _create_agent(client, _as_user(client, session))
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["created_by"] == "user:3f9c-dana"


def test_a_key_registration_leaves_created_by_empty(client):
    """Empty, NOT tenant:acme. A fallback would put attribution-shaped text on
    every row while carrying no information, and would bury the rows that name
    a real person."""
    r = _create_agent(client, _as_key(client), agent_id="ci-bot")
    assert r.json()["agent"]["created_by"] == ""


def test_an_update_records_who_changed_it(client, session):
    _create_agent(client, _as_key(client))
    _as_user(client, session)
    r = client.put("/v1/agents/registry/payments-bot", json={"name": "renamed"})
    assert r.json()["agent"]["updated_by"] == "user:3f9c-dana"


def test_a_key_update_does_not_erase_a_real_updated_by(client, session):
    """Overwriting a real answer with an empty string is worse than leaving it
    stale: the record would claim nobody has ever touched this agent."""
    _create_agent(client, _as_user(client, session))
    r = client.put("/v1/agents/registry/payments-bot",
                   headers=_as_key(client), json={"name": "renamed"})
    assert r.json()["agent"]["updated_by"] == "user:3f9c-dana"


def test_created_by_survives_an_update(client, session):
    _create_agent(client, _as_user(client, session))
    r = client.put("/v1/agents/registry/payments-bot",
                   headers=_as_key(client), json={"name": "renamed"})
    assert r.json()["agent"]["created_by"] == "user:3f9c-dana"


# ── governance surfaces it ───────────────────────────────────────────────


def test_governance_lists_created_by(client, session):
    _create_agent(client, _as_user(client, session))
    agents = client.get("/v1/governance/agents").json()["agents"]
    entry = next(a for a in agents if a["agent_id"] == "payments-bot")
    assert entry["created_by"] == "user:3f9c-dana"


def test_governance_created_by_is_empty_not_missing(client):
    """The portal renders this directly; None would print as "null"."""
    _create_agent(client, _as_key(client), agent_id="legacy-bot")
    agents = client.get("/v1/governance/agents").json()["agents"]
    assert agents[0]["created_by"] == ""


def test_an_entry_written_before_this_existed_still_reads(client, store):
    """Every registry entry in every deployment predates these fields."""
    import json
    store[f"agents:{TENANT}"] = json.dumps(
        {"old-bot": {"agent_id": "old-bot", "name": "Old", "tools": []}})
    agents = client.get("/v1/governance/agents").json()["agents"]
    assert agents[0]["created_by"] == "" and agents[0]["updated_by"] == ""


# ── the review campaign reviewer ─────────────────────────────────────────


def test_a_campaign_records_the_authenticated_reviewer(client, session):
    _as_user(client, session)
    r = client.post("/v1/governance/reviews", json={"name": "Q3 review"})
    assert r.status_code in (200, 201), r.text
    body = r.json().get("campaign", r.json())
    assert body["created_by"] == "user:3f9c-dana"
    assert body["reviewer_verified"] is True


def test_a_claimed_reviewer_cannot_override_the_real_one(client, session):
    """A reviewer taken from the request body is not a reviewer. The value of
    a campaign record is that somebody accountable looked at it."""
    _as_user(client, session)
    r = client.post("/v1/governance/reviews",
                    json={"name": "Q3", "reviewer": "someone-else"})
    body = r.json().get("campaign", r.json())
    assert body["created_by"] == "user:3f9c-dana"


def test_a_key_campaign_keeps_the_old_behaviour(client):
    """Campaigns created with an API key must keep working exactly as before,
    and must be marked as unverified so the two are distinguishable."""
    r = client.post("/v1/governance/reviews", headers=_as_key(client),
                    json={"name": "Q3", "reviewer": "dana"})
    body = r.json().get("campaign", r.json())
    assert body["created_by"] == "dana"
    assert body["reviewer_verified"] is False


# ── nothing on the guard path learned about any of this ──────────────────


def test_the_guard_path_does_not_attribute_to_a_human():
    import inspect
    from guardrails.agentic import rbac_guard
    for name in ("audit_actor", "acting_user_sub", "portal_principal"):
        assert name not in inspect.getsource(rbac_guard)
