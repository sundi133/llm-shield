"""Binding a server to a policy profile (fleet control plane, phase 2).

Binding is a sub-resource rather than a field on the server PUT: that PUT
replaces the whole document, so editing policy through it would force the
operator to re-send the upstream's credentials every time.

Phase 2 materializes effective policy onto the route. Nothing reads it yet, and
these tests pin that the API says so.
"""

from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from storage import mcp_gateway_store as gstore
from storage import mcp_policy_store as pstore

_PREFIXES = ("mcp_profile:", "mcp_profiles:", "mcp_gateway:")
_H = {"X-Test-Tenant": "acme"}
_PROFILE = {"description": "saas", "tools": {"allow": ["list_jobs"]},
            "dlp": {"role_ceiling": "public"}}


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


def _server(route="higgsfield", **extra):
    cfg = {"route": route, "transport": "http", "url": "https://u/mcp"}
    cfg.update(extra)
    gstore.set_upstream("acme", route, cfg)
    return cfg


def _profile(client, profile_id="saas", body=None):
    r = client.put(f"/v1/tenant/me/mcp/profiles/{profile_id}",
                   json=body or _PROFILE, headers=_H)
    assert r.status_code == 200
    return r.json()["profile"]


# ── binding ──────────────────────────────────────────────────────────


def test_bind_materializes_policy_and_indexes_route(client):
    _server()
    prof = _profile(client)

    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas"}, headers=_H)
    assert r.status_code == 200

    cfg = gstore.get_upstream("acme", "higgsfield")
    assert cfg["profile_id"] == "saas"
    assert cfg["effective_policy"]["tools"]["allow"] == ["list_jobs"]
    assert cfg["effective_rev"] == prof["rev"]
    assert pstore.list_bound_routes("acme", "saas") == ["higgsfield"]


def test_bind_states_enforcement_is_not_wired_yet(client):
    _server()
    _profile(client)
    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas"}, headers=_H)
    assert "not yet" in r.json()["enforcement_note"]


def test_bind_applies_overrides(client):
    _server()
    _profile(client)
    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas",
                         "overrides": {"dlp": {"role_ceiling": "admin"}}},
                   headers=_H)
    eff = r.json()["server"]["effective_policy"]
    assert eff["dlp"]["role_ceiling"] == "admin"   # override wins
    assert eff["tools"]["allow"] == ["list_jobs"]  # profile survives


def test_bind_preserves_upstream_config_and_redacts(client):
    """Binding must not disturb the connection details, and must not echo them."""
    _server(headers={"Authorization": "Bearer s3cret"})
    _profile(client)
    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas"}, headers=_H)
    assert "s3cret" not in r.text
    assert gstore.get_upstream("acme", "higgsfield")["headers"] == {
        "Authorization": "Bearer s3cret"}


def test_rebind_moves_the_route_between_indexes(client):
    """A dangling entry in the old profile's index would make its next write try
    to recompute a route it no longer governs."""
    _server()
    _profile(client, "saas")
    _profile(client, "internal", {"description": "internal"})

    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "saas"}, headers=_H)
    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "internal"}, headers=_H)

    assert pstore.list_bound_routes("acme", "saas") == []
    assert pstore.list_bound_routes("acme", "internal") == ["higgsfield"]


def test_unbind_clears_policy_and_index(client):
    _server()
    _profile(client)
    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "saas"}, headers=_H)

    r = client.delete("/v1/tenant/me/mcp/servers/higgsfield/binding", headers=_H)
    assert r.status_code == 200
    cfg = gstore.get_upstream("acme", "higgsfield")
    for k in ("profile_id", "overrides", "effective_policy", "effective_rev"):
        assert k not in cfg
    assert cfg["url"] == "https://u/mcp"  # server itself survives
    assert pstore.list_bound_routes("acme", "saas") == []


def test_unbind_unbound_route_404s(client):
    _server()
    assert client.delete("/v1/tenant/me/mcp/servers/higgsfield/binding",
                         headers=_H).status_code == 404


def test_bind_unknown_route_or_profile_404s(client):
    _profile(client)
    assert client.put("/v1/tenant/me/mcp/servers/nope/binding",
                      json={"profile_id": "saas"}, headers=_H).status_code == 404
    _server()
    assert client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                      json={"profile_id": "nope"}, headers=_H).status_code == 404


def test_bind_rejects_unknown_fields(client):
    _server()
    _profile(client)
    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas", "typo_field": 1}, headers=_H)
    assert r.status_code == 422


def test_bind_requires_tenant(client):
    _server()
    assert client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                      json={"profile_id": "saas"}).status_code == 401


def test_cannot_bind_another_tenants_server(client):
    gstore.set_upstream("victim", "higgsfield", {"route": "higgsfield",
                                                 "transport": "http", "url": "u"})
    _profile(client)
    r = client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
                   json={"profile_id": "saas"}, headers=_H)
    assert r.status_code == 404
    assert "profile_id" not in gstore.get_upstream("victim", "higgsfield")


# ── fan-out on profile write ─────────────────────────────────────────


def test_profile_write_fans_out_to_bound_routes(client):
    for route in ("higgsfield", "vendor-x"):
        _server(route)
    _profile(client)
    for route in ("higgsfield", "vendor-x"):
        client.put(f"/v1/tenant/me/mcp/servers/{route}/binding",
                   json={"profile_id": "saas"}, headers=_H)

    r = client.put("/v1/tenant/me/mcp/profiles/saas",
                   json={**_PROFILE, "tools": {"allow": ["list_jobs", "generate_image"]}},
                   headers=_H)
    assert sorted(r.json()["fanout"]["updated"]) == ["higgsfield", "vendor-x"]
    assert "warning" not in r.json()

    for route in ("higgsfield", "vendor-x"):
        cfg = gstore.get_upstream("acme", route)
        assert cfg["effective_policy"]["tools"]["allow"] == ["list_jobs", "generate_image"]


def test_fanout_preserves_per_route_overrides(client):
    """A fleet-wide profile edit must not silently discard a route's exception."""
    _server()
    _profile(client)
    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "saas",
                     "overrides": {"dlp": {"role_ceiling": "admin"}}}, headers=_H)

    client.put("/v1/tenant/me/mcp/profiles/saas",
               json={**_PROFILE, "tools": {"allow": ["x"]}}, headers=_H)

    eff = gstore.get_upstream("acme", "higgsfield")["effective_policy"]
    assert eff["tools"]["allow"] == ["x"]              # new profile value
    assert eff["dlp"]["role_ceiling"] == "admin"       # override still applied


def test_partial_fanout_warns_and_shows_drift(client):
    _server("live")
    _profile(client)
    client.put("/v1/tenant/me/mcp/servers/live/binding",
               json={"profile_id": "saas"}, headers=_H)
    pstore.bind_route("acme", "saas", "ghost")  # indexed but never created

    r = client.put("/v1/tenant/me/mcp/profiles/saas",
                   json={**_PROFILE, "tools": {"allow": ["x"]}}, headers=_H)
    assert r.json()["fanout"]["missing"] == ["ghost"]
    assert "stale" in r.json()["warning"]


# ── inventory reporting ──────────────────────────────────────────────


def test_inventory_reports_drift(client):
    _server()
    _profile(client)
    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "saas"}, headers=_H)

    inv = client.get("/v1/tenant/me/mcp/inventory", headers=_H).json()
    assert inv["drifted_server_count"] == 0

    # Advance the profile without fanning out, simulating a partial failure.
    pstore.set_profile("acme", "saas", {"tools": {"allow": ["changed"]}})
    inv = client.get("/v1/tenant/me/mcp/inventory", headers=_H).json()
    assert inv["drifted_server_count"] == 1
    assert inv["servers"][0]["drift"] is True


def test_inventory_unbound_server_never_drifts(client):
    _server()
    inv = client.get("/v1/tenant/me/mcp/inventory", headers=_H).json()
    assert inv["servers"][0]["drift"] is False
    assert inv["drifted_server_count"] == 0


# ── deleting a server cleans its index entry ─────────────────────────


def test_delete_server_unbinds_so_profile_stays_deletable(client):
    """A deleted route left in the index would 409 profile deletion forever,
    naming a route that no longer exists."""
    _server()
    _profile(client)
    client.put("/v1/tenant/me/mcp/servers/higgsfield/binding",
               json={"profile_id": "saas"}, headers=_H)

    assert client.delete("/v1/tenant/me/mcp/servers/higgsfield",
                         headers=_H).status_code == 200
    assert pstore.list_bound_routes("acme", "saas") == []
    assert client.delete("/v1/tenant/me/mcp/profiles/saas", headers=_H).status_code == 200
