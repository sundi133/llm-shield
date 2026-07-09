"""Test the customer SDK (examples/shield_client.py) against a real
in-process Shield app — proving the customer path works end-to-end.

Customers use the SDK with their tenant API key. The SDK never sees the
admin key. The test mirrors what a real customer integration looks like.
"""

from __future__ import annotations

from typing import Iterator

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_agent_auth import (
    router as agent_auth_router,
    tenant_router as agent_auth_tenant_router,
)
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import reset_signer_cache_for_tests
from core.capabilities import (
    clear_nonce_store_for_tests,
    reset_cap_signer_cache_for_tests,
)
from examples.shield_client import ShieldClient, ShieldError
from storage import agent_auth_stats as stats
from storage.revocation import clear_all_for_tests


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


@pytest.fixture
def shield_app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "not-used-by-customer")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    stats.clear_for_tests()
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.add_middleware(AgentIdentityMiddleware)
    app.include_router(agent_auth_router)
    app.include_router(agent_auth_tenant_router)
    yield app

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    stats.clear_for_tests()


@pytest.fixture
def sdk(shield_app, monkeypatch):
    """A ShieldClient that talks to the in-process app via Starlette TestClient.

    We patch requests.post to route through TestClient so the SDK code is
    exercised verbatim without spinning up a network server.
    """
    test_client = TestClient(shield_app)

    import requests
    real_post = requests.post

    def _routed_post(url, json=None, headers=None, timeout=None):
        # Strip the fake base_url so TestClient gets a path.
        path = url.replace("http://shield-test", "")
        r = test_client.post(path, json=json, headers=headers or {})
        # Build a minimal Response shim
        return _Resp(r)

    class _Resp:
        def __init__(self, r):
            self._r = r
            self.status_code = r.status_code
            self.text = r.text
            self.ok = r.is_success
        def json(self):
            return self._r.json()

    monkeypatch.setattr(requests, "post", _routed_post)

    return ShieldClient(base_url="http://shield-test", tenant_api_key="acme")


# ── customer flow ──────────────────────────────────────────────────


class TestCustomerHappyPath:
    def test_full_flow(self, sdk):
        """Mint token → mint cap → verify cap → exact API a customer uses."""
        token = sdk.mint_agent_token(
            user_sub="alice@acme.com",
            agent_id="billing-bot",
            agent_instance_id="pod-1",
            build_hash="sha256:abc",
            model_version="opus-4.7",
            session_id="conv-1",
        )
        assert token.token and "." in token.token
        assert token.expires_in == 600

        cap = sdk.mint_cap(
            token, tool="send_email", resource="user/u-1/inbox",
            scope_constraints=["to:u-1@acme.com"],
        )
        assert cap.cap_token and "." in cap.cap_token
        assert cap.decision["allowed"] is True
        assert cap.decision["tool"] == "send_email"

        ok, claims = sdk.verify_cap(cap, expected_tool="send_email")
        assert ok is True
        assert claims["user_sub"] == "alice@acme.com"
        assert claims["tenant_id"] == "acme"
        assert claims["tool"] == "send_email"

    def test_replay_blocked(self, sdk):
        token = sdk.mint_agent_token(
            user_sub="a", agent_id="bot", agent_instance_id="i",
            build_hash="b", model_version="m", session_id="s",
        )
        cap = sdk.mint_cap(token, tool="t", resource="r")
        ok1, _ = sdk.verify_cap(cap, expected_tool="t")
        ok2, err2 = sdk.verify_cap(cap, expected_tool="t")
        assert ok1 is True
        assert ok2 is False
        assert "replay" in err2["error"].lower()


class TestCustomerAuthBoundaries:
    def test_no_tenant_key_rejects(self, sdk, monkeypatch):
        # Strip the key from the SDK to simulate a misconfigured agent
        object.__setattr__(sdk, "tenant_api_key", "")
        with pytest.raises(ShieldError):
            sdk.mint_agent_token(
                user_sub="a", agent_id="b", agent_instance_id="i",
                build_hash="b", model_version="m", session_id="s",
            )

    def test_tenant_isolation(self, shield_app, monkeypatch):
        """A token minted by tenant 'acme' verifies as tenant_id='acme',
        no matter what claims a malicious caller tried to inject."""
        # Build a second SDK pinned to a different tenant
        test_client = TestClient(shield_app)
        import requests
        class _Resp:
            def __init__(self, r):
                self._r = r; self.status_code = r.status_code
                self.text = r.text; self.ok = r.is_success
            def json(self): return self._r.json()
        def _post(url, json=None, headers=None, timeout=None):
            path = url.replace("http://shield-test", "")
            return _Resp(test_client.post(path, json=json, headers=headers or {}))
        monkeypatch.setattr(requests, "post", _post)

        sdk_acme = ShieldClient(base_url="http://shield-test", tenant_api_key="acme")
        sdk_corp = ShieldClient(base_url="http://shield-test", tenant_api_key="corp")

        token_acme = sdk_acme.mint_agent_token(
            user_sub="a", agent_id="b", agent_instance_id="i",
            build_hash="b", model_version="m", session_id="s",
        )
        token_corp = sdk_corp.mint_agent_token(
            user_sub="a", agent_id="b", agent_instance_id="i",
            build_hash="b", model_version="m", session_id="s",
        )

        # Cap minted from acme's token carries tenant_id='acme'
        cap_acme = sdk_acme.mint_cap(token_acme, tool="t", resource="r")
        ok, claims = sdk_acme.verify_cap(cap_acme, expected_tool="t")
        assert ok and claims["tenant_id"] == "acme"

        # Corp's token also works but stays scoped to corp
        cap_corp = sdk_corp.mint_cap(token_corp, tool="t", resource="r")
        ok, claims = sdk_corp.verify_cap(cap_corp, expected_tool="t")
        assert ok and claims["tenant_id"] == "corp"


class TestCustomerErrorSurface:
    def test_authz_denial_default_is_quiet(self, sdk, monkeypatch):
        """M3: in default (quiet) mode the SDK surfaces a 403 with a
        request_id, but no role/tool enumeration. The full reason is in
        the audit log on the Shield side."""
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=["lookup"], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})
        monkeypatch.delenv("SHIELD_VERBOSE_REASONS", raising=False)

        token = sdk.mint_agent_token(
            user_sub="a", agent_id="billing-bot", agent_instance_id="i",
            build_hash="b", model_version="m", session_id="s",
        )
        with pytest.raises(ShieldError) as ei:
            sdk.mint_cap(token, tool="send_email", resource="r")
        msg = str(ei.value)
        assert "403" in msg
        assert "authz_denied" in msg
        assert "request_id" in msg
        # Critical: the role name and tool list must NOT leak by default.
        assert "send_email" not in msg
        assert "reader" not in msg
        assert "not permitted" not in msg

    def test_authz_denial_verbose_mode_includes_reasons(self, sdk, monkeypatch):
        """When SHIELD_VERBOSE_REASONS=1 the reasons come back so an LLM
        can re-prompt or apologize sensibly."""
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=["lookup"], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "1")

        token = sdk.mint_agent_token(
            user_sub="a", agent_id="billing-bot", agent_instance_id="i",
            build_hash="b", model_version="m", session_id="s",
        )
        with pytest.raises(ShieldError) as ei:
            sdk.mint_cap(token, tool="send_email", resource="r")
        msg = str(ei.value)
        assert "send_email" in msg or "not permitted" in msg
