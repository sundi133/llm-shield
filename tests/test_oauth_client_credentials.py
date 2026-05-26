"""Tests for the OAuth 2.1 `client_credentials` grant (autonomous M2M)."""

from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "11" * 32)

from core.oauth.authz_server import build_server_metadata, exchange_client_credentials
from storage.oauth_store import (
    OAuthClient,
    clear_all_for_tests,
    hash_client_secret,
    save_client,
)


def _make_client(
    *,
    client_id: str = "shield-test",
    secret: str = "s3cret",
    grants=("client_credentials",),
    scope: str = "shield guardrails",
    public: bool = False,
) -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_name="Test",
        client_secret_hash="" if public else hash_client_secret(secret),
        grant_types=list(grants),
        token_endpoint_auth_method="none" if public else "client_secret_post",
        scope=scope,
        tenant_id="t1",
    )


@pytest.fixture(autouse=True)
def _reset_store():
    clear_all_for_tests()
    yield
    clear_all_for_tests()


def test_metadata_advertises_client_credentials():
    md = build_server_metadata("https://shield.example")
    assert "client_credentials" in md["grant_types_supported"]


def test_happy_path_issues_token_without_refresh():
    asyncio.run(save_client(_make_client()))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test", client_secret="s3cret", scope="shield"
        )
    )
    assert "access_token" in res
    assert res["token_type"] == "Bearer"
    assert res["scope"] == "shield"
    assert "refresh_token" not in res, "RFC 6749 §4.4.3 forbids refresh tokens"


def test_unknown_client_rejected():
    res = asyncio.run(
        exchange_client_credentials(client_id="nope", client_secret="x", scope="shield")
    )
    assert res["error"] == "invalid_client"


def test_wrong_secret_rejected():
    asyncio.run(save_client(_make_client()))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test", client_secret="bad", scope="shield"
        )
    )
    assert res["error"] == "invalid_client"


def test_public_client_cannot_use_grant():
    asyncio.run(save_client(_make_client(public=True)))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test", client_secret="anything", scope="shield"
        )
    )
    assert res["error"] == "invalid_client"


def test_disallowed_grant_for_client():
    asyncio.run(save_client(_make_client(grants=("authorization_code",))))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test", client_secret="s3cret", scope="shield"
        )
    )
    assert res["error"] == "unauthorized_client"


def test_scope_intersection_with_registered():
    asyncio.run(save_client(_make_client(scope="shield guardrails")))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test",
            client_secret="s3cret",
            scope="shield admin",  # admin not registered
        )
    )
    assert res["scope"] == "shield"


def test_empty_scope_intersection_rejected():
    asyncio.run(save_client(_make_client(scope="shield")))
    res = asyncio.run(
        exchange_client_credentials(
            client_id="shield-test", client_secret="s3cret", scope="admin"
        )
    )
    assert res["error"] == "invalid_scope"
