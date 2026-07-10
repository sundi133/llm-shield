"""Cap-gated tool executor (examples/sandbox/tool_executor.py) — the L3
boundary from docs/spec-sandbox-guardrails.md.

What must hold (spec §8):
  * the real tool body runs ONLY after the cap for exactly that tool +
    resource verifies; verify burns the nonce, so a replay is denied;
  * a cap minted for tool A cannot run tool B; resource X cannot act on Y;
  * fail closed with no fail-open option: Shield unreachable or non-2xx
    means no execution, and a DLP failure withholds the result;
  * result DLP redaction is applied before anything returns to the sandbox.

Cap lifecycle tests run against the real agent-auth routers in-process
(ASGITransport, real Ed25519 signing + nonce store). DLP behaviors use
httpx.MockTransport. Async is driven with asyncio.run() (no pytest-asyncio),
matching tests/test_mcp_server_example.py.
"""

from __future__ import annotations

import asyncio
from typing import Iterator

import httpx
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
from examples.sandbox.tool_executor import CapGatedExecutor, Denied
from examples.shield_client import ShieldClient
from storage import agent_auth_stats as stats
from storage.revocation import clear_all_for_tests

TENANT_KEY = "acme"


def run(coro):
    return asyncio.run(coro)


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


@pytest.fixture
def shield_app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "not-used-by-executor")
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
def sdk(shield_app, monkeypatch) -> ShieldClient:
    """ShieldClient routed through TestClient — used to mint token + caps
    exactly like the in-sandbox runtime would."""
    test_client = TestClient(shield_app)

    class _Resp:
        def __init__(self, r):
            self._r = r
            self.status_code = r.status_code
            self.text = r.text
            self.ok = r.is_success

        def json(self):
            return self._r.json()

    def _routed_post(url, json=None, headers=None, timeout=None):
        path = url.replace("http://shield-test", "")
        return _Resp(test_client.post(path, json=json, headers=headers or {}))

    import requests
    monkeypatch.setattr(requests, "post", _routed_post)
    return ShieldClient(base_url="http://shield-test", tenant_api_key=TENANT_KEY)


def make_executor(shield_app, **kwargs) -> CapGatedExecutor:
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=shield_app))
    return CapGatedExecutor("http://shield-test", client=client, **kwargs)


def mint_cap(sdk: ShieldClient, tool: str, resource: str):
    token = sdk.mint_agent_token(
        user_sub="alice@acme.com",
        agent_id="sandbox-bot",
        agent_instance_id="sbx-1",
        build_hash="sha256:abc",
        model_version="claude-opus-4-8",
        session_id="conv-1",
    )
    return sdk.mint_cap(token, tool=tool, resource=resource)


class _Recorder:
    """A registered tool body that records its invocations."""

    def __init__(self, result: str = "done"):
        self.calls: list = []
        self.result = result

    async def __call__(self, **params):
        self.calls.append(params)
        return self.result


# ── cap lifecycle against the real verify path ──────────────────────


class TestCapLifecycle:
    def test_valid_cap_executes_and_returns_result(self, shield_app, sdk):
        send = _Recorder("[email] sent")
        ex = make_executor(shield_app)
        ex.register_tool("send_email", send, resource_arg="to")
        cap = mint_cap(sdk, "send_email", "u1@acme.com")

        out = run(ex.execute("send_email", cap.cap_token, {"to": "u1@acme.com"}))

        assert out == "[email] sent"
        assert send.calls == [{"to": "u1@acme.com"}]

    def test_replay_is_denied_tool_runs_once(self, shield_app, sdk):
        send = _Recorder()
        ex = make_executor(shield_app)
        ex.register_tool("send_email", send, resource_arg="to")
        cap = mint_cap(sdk, "send_email", "u1@acme.com")

        async def scenario():
            await ex.execute("send_email", cap.cap_token, {"to": "u1@acme.com"})
            with pytest.raises(Denied, match="replay") as exc:
                await ex.execute("send_email", cap.cap_token, {"to": "u1@acme.com"})
            assert exc.value.stage == "verify"

        run(scenario())
        assert len(send.calls) == 1  # the nonce burned on first use

    def test_cap_for_tool_a_cannot_run_tool_b(self, shield_app, sdk):
        delete = _Recorder()
        ex = make_executor(shield_app)
        ex.register_tool("delete_account", delete, resource_arg="account_id")
        cap = mint_cap(sdk, "send_email", "u1@acme.com")  # minted for tool A

        with pytest.raises(Denied) as exc:
            run(ex.execute("delete_account", cap.cap_token, {"account_id": "a-1"}))
        assert exc.value.stage == "verify"
        assert delete.calls == []

    def test_cap_resource_x_cannot_act_on_resource_y(self, shield_app, sdk):
        delete = _Recorder()
        ex = make_executor(shield_app)
        ex.register_tool("delete_account", delete, resource_arg="account_id")
        cap = mint_cap(sdk, "delete_account", "acct-1")

        with pytest.raises(Denied) as exc:
            run(ex.execute("delete_account", cap.cap_token, {"account_id": "acct-2"}))
        assert exc.value.stage == "verify"
        assert delete.calls == []

    def test_tampered_cap_is_denied(self, shield_app, sdk):
        send = _Recorder()
        ex = make_executor(shield_app)
        ex.register_tool("send_email", send, resource_arg="to")
        cap = mint_cap(sdk, "send_email", "u1@acme.com")

        with pytest.raises(Denied):
            run(ex.execute("send_email", cap.cap_token[:-4] + "AAAA", {"to": "u1@acme.com"}))
        assert send.calls == []

    def test_unknown_tool_denied_before_any_network(self, shield_app):
        ex = make_executor(shield_app)
        with pytest.raises(Denied) as exc:
            run(ex.execute("not_registered", "whatever", {}))
        assert exc.value.stage == "unknown_tool"


# ── fail closed + result DLP (mocked Shield) ────────────────────────


def _valid_verify(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"valid": True, "claims": {"tool": "t"}})


def make_mock_executor(handler, **kwargs) -> CapGatedExecutor:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return CapGatedExecutor("http://shield.test", client=client, **kwargs)


class TestFailClosedAndDLP:
    def test_shield_unreachable_denies_and_never_runs(self):
        tool = _Recorder()

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("shield down")

        ex = make_mock_executor(handler)
        ex.register_tool("t", tool)
        with pytest.raises(Denied) as exc:
            run(ex.execute("t", "cap", {}))
        assert exc.value.stage == "verify"
        assert tool.calls == []

    def test_verify_5xx_denies(self):
        tool = _Recorder()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        ex = make_mock_executor(handler)
        ex.register_tool("t", tool)
        with pytest.raises(Denied) as exc:
            run(ex.execute("t", "cap", {}))
        assert exc.value.stage == "verify"
        assert tool.calls == []

    def test_dlp_redaction_applied_to_result(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/shield/cap/verify":
                return _valid_verify(request)
            assert request.url.path == "/v1/shield/tool/output"
            assert request.headers["X-API-Key"] == TENANT_KEY
            return httpx.Response(
                200, json={"action": "pass", "sanitized_output": "ssn=[REDACTED]"}
            )

        ex = make_mock_executor(handler, tenant_key=TENANT_KEY)
        ex.register_tool("t", _Recorder("ssn=123-45-6789"))
        assert run(ex.execute("t", "cap", {})) == "ssn=[REDACTED]"

    def test_dlp_block_withholds_result(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/shield/cap/verify":
                return _valid_verify(request)
            return httpx.Response(200, json={"action": "block", "message": "PII egress"})

        ex = make_mock_executor(handler, tenant_key=TENANT_KEY)
        ex.register_tool("t", _Recorder("ssn=123-45-6789"))
        with pytest.raises(Denied, match="PII egress") as exc:
            run(ex.execute("t", "cap", {}))
        assert exc.value.stage == "output"

    def test_dlp_transport_failure_withholds_result(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/shield/cap/verify":
                return _valid_verify(request)
            return httpx.Response(503)

        ex = make_mock_executor(handler, tenant_key=TENANT_KEY)
        ex.register_tool("t", _Recorder())
        with pytest.raises(Denied) as exc:
            run(ex.execute("t", "cap", {}))
        assert exc.value.stage == "output"

    def test_without_tenant_key_dlp_is_skipped_verify_still_gates(self):
        paths: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            return _valid_verify(request)

        ex = make_mock_executor(handler)  # no tenant_key configured
        ex.register_tool("t", _Recorder("raw"))
        assert run(ex.execute("t", "cap", {})) == "raw"
        assert paths == ["/v1/shield/cap/verify"]  # no DLP round-trip

    def test_verify_sends_no_tenant_secret(self):
        seen_headers: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/shield/cap/verify":
                seen_headers.append(dict(request.headers))
                return _valid_verify(request)
            return httpx.Response(200, json={"action": "pass", "sanitized_output": "x"})

        ex = make_mock_executor(handler, tenant_key=TENANT_KEY)
        ex.register_tool("t", _Recorder())
        run(ex.execute("t", "cap", {}))
        assert "x-api-key" not in seen_headers[0]  # bearer-of-cap needs no secret
