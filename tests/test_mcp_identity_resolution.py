"""Tests for MCP identity resolution and OAuth protected-resource discovery.

Covers the additive identity layer on the Guardrail MCP server:
- _resolve_identity reads X-Agent-Key / X-User-Role headers and resolves the
  tenant from X-API-Key,
- _oauth_claims validates a Shield-issued OAuth access token (and ignores a
  non-Shield bearer such as a proxy token),
- the RFC 9728 /.well-known/oauth-protected-resource endpoint.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

import api.routes_mcp_server as mcp
from api.routes_mcp_server import _resolve_identity, _oauth_claims
from core.oauth.authz_server import issue_access_token


class _Req:
    """Minimal stand-in for a Starlette Request."""
    def __init__(self, headers=None, state=None):
        self.headers = Headers(headers or {})
        if state is not None:
            self.state = state


def test_defaults_to_mcp_agent_when_no_identity():
    tenant, agent, role = _resolve_identity(_Req())
    assert tenant == ""
    assert agent == "mcp-agent"
    assert role == ""


def test_reads_agent_and_role_headers():
    req = _Req({"x-agent-key": "support-bot", "x-user-role": "reader"})
    tenant, agent, role = _resolve_identity(req)
    assert agent == "support-bot"
    assert role == "reader"


def test_resolves_tenant_from_api_key(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: "acme" if k == "sk-acme" else "")
    tenant, agent, role = _resolve_identity(_Req({"x-api-key": "sk-acme"}))
    assert tenant == "acme"


def test_oauth_bearer_yields_tenant_and_developer():
    token = issue_access_token(
        client_id="cursor", scope="shield", tenant_id="acme", user_sub="dev@acme.com")
    claims = _oauth_claims(f"Bearer {token}")
    assert claims is not None
    assert claims["tenant_id"] == "acme"
    assert claims["sub"] == "dev@acme.com"

    tenant, agent, _ = _resolve_identity(_Req({"authorization": f"Bearer {token}"}))
    assert tenant == "acme"
    assert agent == "oauth:dev@acme.com"


def test_non_shield_bearer_is_ignored():
    # A proxy token (not a Shield JWT) must not break X-API-Key auth.
    assert _oauth_claims("Bearer rpa_some_opaque_proxy_token") is None
    tenant, agent, _ = _resolve_identity(_Req({"authorization": "Bearer rpa_opaque"}))
    assert tenant == ""
    assert agent == "mcp-agent"


def test_state_takes_precedence_over_headers():
    from types import SimpleNamespace
    st = SimpleNamespace(tenant_id="from-state", agent_key="state-agent", user_role="admin")
    req = _Req({"x-agent-key": "hdr-agent", "x-user-role": "reader"}, state=st)
    tenant, agent, role = _resolve_identity(req)
    assert (tenant, agent, role) == ("from-state", "state-agent", "admin")


def test_protected_resource_metadata(monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_BASE_URL", "https://mcp.example.com")
    from api.routes_oauth import router as oauth_router
    app = FastAPI()
    app.include_router(oauth_router)
    client = TestClient(app)

    r = client.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == "https://mcp.example.com"
    assert body["authorization_servers"] == ["https://mcp.example.com"]
    assert body["bearer_methods_supported"] == ["header"]
