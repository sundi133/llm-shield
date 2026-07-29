"""Policy profile CRUD on the admin plane (fleet control plane, phase 1).

A profile is a named policy bundle SecOps authors once and binds to many MCP
servers. These tests cover CRUD, the id rule, and the enforcement note that
keeps the console honest about which fields actually gate traffic.

Tenant comes from verified request.state, never the body — same property
tests/test_mcp_admin_console.py pins for the rest of this router.
"""

from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from storage import mcp_policy_store as pstore

_PREFIXES = ("mcp_profile:", "mcp_profiles:")
_H = {"X-Test-Tenant": "acme"}


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIXES)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


@pytest.fixture
def client():
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(admin.router)
    return TestClient(app)


_BODY = {
    "description": "third-party SaaS MCP servers",
    "tools": {"allow": ["list_jobs"], "deny": ["delete_account"]},
    "dlp": {"sanitize_as": "public"},
    "result_scanning": {"enabled": True, "action": "block"},
}


def test_create_get_list_delete(client):
    r = client.put("/v1/tenant/me/mcp/profiles/saas-untrusted", json=_BODY, headers=_H)
    assert r.status_code == 200
    assert r.json()["status"] == "created"

    r = client.get("/v1/tenant/me/mcp/profiles/saas-untrusted", headers=_H)
    assert r.status_code == 200
    prof = r.json()["profile"]
    assert prof["tools"]["allow"] == ["list_jobs"]
    assert prof["dlp"]["sanitize_as"] == "public"
    assert r.json()["bound_routes"] == []

    r = client.get("/v1/tenant/me/mcp/profiles", headers=_H)
    assert r.json()["count"] == 1

    r = client.delete("/v1/tenant/me/mcp/profiles/saas-untrusted", headers=_H)
    assert r.status_code == 200
    assert client.get("/v1/tenant/me/mcp/profiles/saas-untrusted", headers=_H).status_code == 404


def test_update_reports_updated_not_created(client):
    client.put("/v1/tenant/me/mcp/profiles/p", json=_BODY, headers=_H)
    r = client.put("/v1/tenant/me/mcp/profiles/p", json={"description": "v2"}, headers=_H)
    assert r.json()["status"] == "updated"
    assert r.json()["profile"]["description"] == "v2"


def test_list_names_the_controls_and_their_limits(client):
    """If the API stayed silent an operator could assume every stored field was
    gating. The note names what IS enforced and where each control stops."""
    note = client.get("/v1/tenant/me/mcp/profiles", headers=_H).json()["enforcement_note"]
    assert "tools.allow" in note
    assert "inprocess backend only" in note
    assert "gates discovery, not invocation" in note


def test_delete_blocked_while_bound(client):
    """Silently unbinding servers would drop their policy without anyone asking."""
    client.put("/v1/tenant/me/mcp/profiles/p", json=_BODY, headers=_H)
    pstore.bind_route("acme", "p", "higgsfield")

    r = client.delete("/v1/tenant/me/mcp/profiles/p", headers=_H)
    assert r.status_code == 409
    assert "higgsfield" in r.json()["detail"]
    assert pstore.get_profile("acme", "p") is not None

    pstore.unbind_route("acme", "p", "higgsfield")
    assert client.delete("/v1/tenant/me/mcp/profiles/p", headers=_H).status_code == 200


def test_get_reports_bound_routes(client):
    client.put("/v1/tenant/me/mcp/profiles/p", json=_BODY, headers=_H)
    pstore.bind_route("acme", "p", "vendor-x")
    pstore.bind_route("acme", "p", "higgsfield")
    r = client.get("/v1/tenant/me/mcp/profiles/p", headers=_H)
    assert r.json()["bound_routes"] == ["higgsfield", "vendor-x"]


def test_unknown_profile_404s(client):
    assert client.get("/v1/tenant/me/mcp/profiles/nope", headers=_H).status_code == 404
    assert client.delete("/v1/tenant/me/mcp/profiles/nope", headers=_H).status_code == 404


@pytest.mark.parametrize("bad", ["has:colon", "-leading", "x" * 65])
def test_invalid_profile_id_rejected(client, bad):
    """Profile ids land in Redis keys, same as route names, so they share the rule."""
    r = client.put(f"/v1/tenant/me/mcp/profiles/{bad}", json=_BODY, headers=_H)
    assert r.status_code == 422
    assert pstore.get_profile("acme", bad) is None


def test_profile_id_with_slash_cannot_reach_the_handler(client):
    """A '/' splits the path, so it can never arrive as a profile_id at all.
    Asserted separately because the rejection is routing, not validation."""
    r = client.put("/v1/tenant/me/mcp/profiles/has/slash", json=_BODY, headers=_H)
    assert r.status_code == 404
    assert pstore.list_profiles("acme") == []


def test_unknown_field_rejected(client):
    """Accepting an unrecognized key would let an operator believe a control is
    configured when nothing will ever read it."""
    r = client.put("/v1/tenant/me/mcp/profiles/p",
                   json={**_BODY, "totally_made_up": {"x": 1}}, headers=_H)
    assert r.status_code == 422


def test_requires_tenant(client):
    assert client.get("/v1/tenant/me/mcp/profiles").status_code == 401
    assert client.put("/v1/tenant/me/mcp/profiles/p", json=_BODY).status_code == 401


def test_tenant_isolation(client):
    client.put("/v1/tenant/me/mcp/profiles/p", json=_BODY, headers=_H)
    other = {"X-Test-Tenant": "other"}
    assert client.get("/v1/tenant/me/mcp/profiles/p", headers=other).status_code == 404
    assert client.get("/v1/tenant/me/mcp/profiles", headers=other).json()["count"] == 0
    # A delete from the wrong tenant must not touch the owner's profile.
    client.delete("/v1/tenant/me/mcp/profiles/p", headers=other)
    assert client.get("/v1/tenant/me/mcp/profiles/p", headers=_H).status_code == 200
