"""The two OAuth discovery documents must advertise the SAME public host.

Regression guard: the authorization-server metadata used to honour only
SHIELD_OAUTH_ISSUER_URL while the protected-resource metadata honoured
SHIELD_PUBLIC_BASE_URL. An operator who set only SHIELD_PUBLIC_BASE_URL behind a
proxy then got a correct protected-resource but an AS metadata still advertising
the internal request host, so MCP client registration/authorize failed. One
variable must configure both.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_oauth import router as oauth_router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(oauth_router)
    return TestClient(app)


def _as(client):
    return client.get("/.well-known/oauth-authorization-server").json()


def _pr(client):
    return client.get("/.well-known/oauth-protected-resource").json()


def test_public_base_url_configures_both_documents(client, monkeypatch):
    monkeypatch.delenv("SHIELD_OAUTH_ISSUER_URL", raising=False)
    monkeypatch.setenv("SHIELD_PUBLIC_BASE_URL", "https://gw.example.com")
    a, p = _as(client), _pr(client)
    # AS metadata now uses the public host for every endpoint.
    assert a["registration_endpoint"] == "https://gw.example.com/oauth/register"
    assert a["authorization_endpoint"] == "https://gw.example.com/oauth/authorize"
    assert a["token_endpoint"] == "https://gw.example.com/oauth/token"
    # And it agrees with the protected-resource metadata's advertised AS host.
    assert p["authorization_servers"][0] == "https://gw.example.com"


def test_issuer_url_still_takes_precedence(client, monkeypatch):
    monkeypatch.setenv("SHIELD_OAUTH_ISSUER_URL", "https://issuer.example.com")
    monkeypatch.setenv("SHIELD_PUBLIC_BASE_URL", "https://other.example.com")
    assert _as(client)["registration_endpoint"] == "https://issuer.example.com/oauth/register"


def test_falls_back_to_request_host_when_unset(client, monkeypatch):
    monkeypatch.delenv("SHIELD_OAUTH_ISSUER_URL", raising=False)
    monkeypatch.delenv("SHIELD_PUBLIC_BASE_URL", raising=False)
    # Unchanged behaviour: the request's own base URL.
    assert _as(client)["registration_endpoint"] == "http://testserver/oauth/register"
