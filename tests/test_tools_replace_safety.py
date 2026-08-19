"""PUT /v1/tenant/me/tools is a full replace, so an empty body must not clear it.

This is a regression test for an incident, not a hypothetical. An engineer
probing the published partner spec sent an empty body to this endpoint,
received 200, and cleared sixty tool definitions from a live tenant. The
handler read `body.get("tools", [])`, so an absent key became an empty list and
the empty list was written.

Two things made it possible, and both had to be true:

  * the published spec offered no example, so "send an empty body and see" was
    the reasonable first move
  * the handler treated "you said nothing" and "delete everything" as the same
    request

Absent and empty are now different answers. Clearing is still possible - it is
a legitimate operation - but it has to be stated rather than defaulted into.

Spec: memo item 14, promoted to P0 after the incident.
"""
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import api.routes_tenant_self as rts

TOOL = {"type": "function", "function": {"name": "read_logs"}}


@pytest.fixture
def client(monkeypatch):
    store: dict = {}

    monkeypatch.setattr(rts, "_require_tenant", lambda request: "acme")
    monkeypatch.setattr(rts, "_get_redis", lambda: None)
    monkeypatch.setattr(rts, "log_admin_action", lambda **kw: None)
    monkeypatch.setattr(rts, "_actor", lambda request, tenant_id: "test")

    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_fallback_store", store)

    app = FastAPI()
    app.include_router(rts.router)
    c = TestClient(app)
    c.store = store
    return c


def _catalogue(client):
    import json
    raw = client.store.get("tool_definitions:acme")
    return json.loads(raw) if raw else None


# ── the incident ─────────────────────────────────────────────────────────


def test_empty_body_does_not_clear_the_catalogue(client):
    """The exact request that destroyed sixty tools."""
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    assert len(_catalogue(client)) == 1

    r = client.put("/v1/tenant/me/tools", json={})
    assert r.status_code == 422
    assert len(_catalogue(client)) == 1, "catalogue was cleared by an empty body"


def test_the_refusal_explains_the_blast_radius(client):
    """A 422 saying 'invalid' teaches nothing. The caller needs to know this
    endpoint replaces everything, which is the fact they did not have."""
    detail = client.put("/v1/tenant/me/tools", json={}).json()["detail"].lower()
    assert "replaces" in detail
    assert "confirm_delete_all" in detail


def test_missing_tools_key_is_rejected_even_with_other_fields(client):
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    r = client.put("/v1/tenant/me/tools", json={"note": "unrelated"})
    assert r.status_code == 422
    assert len(_catalogue(client)) == 1


# ── clearing is still possible, just deliberate ──────────────────────────


def test_empty_list_alone_is_refused(client):
    """An explicit [] is closer to intent than an absent key, but it is also
    what an example or a serialiser default produces. Still not enough."""
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    r = client.put("/v1/tenant/me/tools", json={"tools": []})
    assert r.status_code == 422
    assert len(_catalogue(client)) == 1


def test_empty_list_with_confirmation_clears(client):
    """Deliberate clearing must keep working - this is a safety rail, not a
    removed capability."""
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    r = client.put("/v1/tenant/me/tools",
                   json={"tools": [], "confirm_delete_all": True})
    assert r.status_code == 200
    assert _catalogue(client) == []


# ── the normal path is unchanged ─────────────────────────────────────────


def test_replacing_with_a_real_list_still_works(client):
    r = client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    assert r.status_code == 200
    assert r.json()["tool_count"] == 1
    assert r.json()["tool_names"] == ["read_logs"]


def test_replace_is_still_a_replace(client):
    """Not a merge. The safety rail must not have quietly changed the
    semantics of the endpoint into something else."""
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    other = {"type": "function", "function": {"name": "restart_service"}}
    client.put("/v1/tenant/me/tools", json={"tools": [other]})
    names = [t["function"]["name"] for t in _catalogue(client)]
    assert names == ["restart_service"]


def test_a_non_list_is_rejected(client):
    for bad in ({"tools": "read_logs"}, {"tools": {"function": {}}}, {"tools": 3}):
        r = client.put("/v1/tenant/me/tools", json=bad)
        assert r.status_code == 422, bad


def test_malformed_tool_still_rejected(client):
    r = client.put("/v1/tenant/me/tools", json={"tools": [{"type": "function"}]})
    assert r.status_code == 422
    assert "function.name" in r.json()["detail"]


def test_nothing_is_written_when_validation_fails(client):
    """A partial write would be worse than a refusal: the caller sees an error
    and the catalogue has changed anyway."""
    client.put("/v1/tenant/me/tools", json={"tools": [TOOL]})
    client.put("/v1/tenant/me/tools",
               json={"tools": [TOOL, {"type": "function"}]})
    names = [t["function"]["name"] for t in _catalogue(client)]
    assert names == ["read_logs"]
