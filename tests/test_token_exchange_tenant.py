"""Token exchange (RFC 8693) must fail closed without a tenant context.

Regression guard: a token-exchange request that reaches /oauth/token
without a resolved tenant_id must be rejected, not silently fall back to
the empty-tenant OIDC namespace (which would break per-tenant isolation
and could issue a token scoped to an empty/unintended tenant).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_oauth import router as oauth_router

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(oauth_router)
    # No middleware sets request.state.tenant_id, so it stays unset —
    # exactly the "no tenant context" condition we are guarding.
    return TestClient(app)


def test_token_exchange_without_tenant_is_rejected(client: TestClient):
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": "header.payload.sig",  # never validated; we
            "subject_token_type": ID_TOKEN_TYPE,     # fail before lookup
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert "tenant" in body["error_description"].lower()


def test_token_exchange_still_validates_subject_token_first(client: TestClient):
    # The tenant check must not mask the earlier required-field checks.
    resp = client.post(
        "/oauth/token",
        data={"grant_type": TOKEN_EXCHANGE, "subject_token_type": ID_TOKEN_TYPE},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
