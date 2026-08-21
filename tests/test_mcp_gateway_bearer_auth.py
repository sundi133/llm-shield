"""A tenant key sent as a bearer token must authenticate, and an anonymous
call must be refused with a 401 challenge rather than a 200.

Both halves come from one live failure. A partner (JumpCloud AI Gateway) pasted
a tenant key into their MCP client, which sends credentials in Authorization per
the MCP authorization spec. Shield read tenant keys only from X-API-Key and
accepted Authorization only as a Shield-issued JWT, so no tenant resolved. It
then answered HTTP 200 carrying the JSON-RPC error, because JSONResponse
defaults to 200.

The client therefore saw a successful HTTP response with no tools and displayed
an empty connector. Observed from both ends at once:

    Railway:  POST /gateway/bank-mcp/mcp HTTP/1.1" 200 OK   from 136.64.167.222
    Claude:   "This connector has no tools available."

Neither end said "authenticate". That is the failure these tests prevent: not
that auth was refused, but that the refusal was indistinguishable from success.

Spec: docs/spec-mcp-gateway-bearer-auth.md
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as gw
import api.routes_mcp_server as ms

TENANT = "acme"
KEY = "acme_live_key"
JWT_SHAPED = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln"


@pytest.fixture(autouse=True)
def _default_env(monkeypatch):
    monkeypatch.delenv("SHIELD_MCP_AUTH_CHALLENGE", raising=False)
    monkeypatch.delenv("SHIELD_PUBLIC_BASE_URL", raising=False)


@pytest.fixture
def store(monkeypatch):
    """Resolve exactly one key; record every lookup so we can assert on them."""
    seen = []

    def _resolve(key):
        seen.append(key)
        return TENANT if key == KEY else ""

    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key", _resolve, raising=False)
    return seen


def _identity(headers: dict):
    """Run _resolve_identity against a request carrying `headers`."""
    app = FastAPI()
    captured = {}

    @app.get("/probe")
    async def probe(request: Request):
        captured["out"] = ms._resolve_identity(request)
        return {}

    TestClient(app).get("/probe", headers=headers)
    return captured["out"]


# ── the bearer fallback ──────────────────────────────────────────────────


def test_a_tenant_key_as_a_bearer_token_resolves(store):
    """The whole point. An MCP client sends its credential in Authorization."""
    tenant_id, _, _ = _identity({"Authorization": f"Bearer {KEY}"})
    assert tenant_id == TENANT


def test_bearer_and_x_api_key_agree(store):
    via_header = _identity({"X-API-Key": KEY})[0]
    via_bearer = _identity({"Authorization": f"Bearer {KEY}"})[0]
    assert via_header == via_bearer == TENANT


def test_x_api_key_wins_when_both_are_present(store):
    tenant_id, _, _ = _identity(
        {"X-API-Key": KEY, "Authorization": "Bearer something-else"})
    assert tenant_id == TENANT
    assert "something-else" not in store, (
        "the bearer was consulted even though X-API-Key already resolved")


def test_a_jwt_shaped_bearer_is_never_probed_as_an_api_key(store):
    """A malformed or expired token must fail as a token. Retrying it as an API
    key would send a JWT to the key store and muddy the failure."""
    _identity({"Authorization": f"Bearer {JWT_SHAPED}"})
    assert JWT_SHAPED not in store


def test_an_invalid_jwt_shaped_bearer_resolves_no_tenant(store):
    tenant_id, _, _ = _identity({"Authorization": f"Bearer {JWT_SHAPED}"})
    assert tenant_id == ""


def test_an_unknown_bearer_resolves_no_tenant(store):
    tenant_id, _, _ = _identity({"Authorization": "Bearer not-a-real-key"})
    assert tenant_id == ""


def test_no_authorization_header_resolves_no_tenant(store):
    assert _identity({})[0] == ""


def test_a_store_error_fails_closed(monkeypatch):
    """A store outage must not admit an unauthenticated caller to a guarded
    route. Failing open here would be worse than the bug being fixed."""
    def _boom(key):
        raise RuntimeError("redis down")

    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key", _boom, raising=False)
    assert _identity({"Authorization": f"Bearer {KEY}"})[0] == ""


def test_bearer_caller_gets_the_same_agent_fallback(store):
    """Bearer auth resolves a tenant, not an agent. It must land on the same
    mcp-agent fallback an X-API-Key caller does, or tool grants would differ
    depending on which header was used."""
    _, agent_bearer, _ = _identity({"Authorization": f"Bearer {KEY}"})
    _, agent_header, _ = _identity({"X-API-Key": KEY})
    assert agent_bearer == agent_header == "mcp-agent"


# ── the 401 challenge ────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch):
    """Gateway app whose identity resolution always refuses."""
    monkeypatch.setattr(gw, "_resolve_identity", lambda request: ("", "", ""))
    app = FastAPI()
    app.include_router(gw.router)
    return TestClient(app)


def _rpc(client, method="tools/list"):
    return client.post("/gateway/r1/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": method})


def test_unauthenticated_returns_401_not_200(client):
    """THE regression guard. A 200 reads as success, so the client reports an
    empty server instead of an auth failure."""
    assert _rpc(client).status_code == 401


def test_the_401_carries_a_www_authenticate_challenge(client):
    hdr = _rpc(client).headers.get("WWW-Authenticate", "")
    assert 'Bearer realm="mcp"' in hdr
    assert "/.well-known/oauth-protected-resource" in hdr


def test_the_challenge_uses_the_public_base_url(monkeypatch, client):
    """Behind a proxy the advertised host must be the public one, or a client
    follows the challenge to an unreachable address."""
    monkeypatch.setenv("SHIELD_PUBLIC_BASE_URL", "https://api.example.com/")
    hdr = _rpc(client).headers.get("WWW-Authenticate", "")
    assert "https://api.example.com/.well-known/oauth-protected-resource" in hdr


def test_the_body_is_still_the_same_json_rpc_error(client):
    """The status changes; the payload does not. A caller parsing the body
    keeps working."""
    body = _rpc(client).json()
    assert body["error"]["code"] == -32001
    assert "unauthenticated" in body["error"]["message"]


def test_the_escape_hatch_restores_the_200(monkeypatch, client):
    """Rollback is an env flip, not a rebuild."""
    monkeypatch.setenv("SHIELD_MCP_AUTH_CHALLENGE", "off")
    r = _rpc(client)
    assert r.status_code == 200
    assert "WWW-Authenticate" not in r.headers


@pytest.mark.parametrize("value", ["0", "off", "false", "no", "OFF"])
def test_escape_hatch_accepts_the_usual_spellings(monkeypatch, client, value):
    monkeypatch.setenv("SHIELD_MCP_AUTH_CHALLENGE", value)
    assert _rpc(client).status_code == 200


def test_other_json_rpc_errors_still_return_200(monkeypatch):
    """The status change is scoped to the auth branch. A protocol-level error
    on an authenticated connection is not a transport failure."""
    monkeypatch.setattr(gw, "_resolve_identity",
                        lambda request: (TENANT, "mcp-agent", ""))
    app = FastAPI()
    app.include_router(gw.router)
    r = TestClient(app).post(
        "/gateway/r1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "no/such/method"})
    assert r.status_code == 200
    assert "error" in r.json()
