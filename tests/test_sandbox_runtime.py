"""In-sandbox runtime (examples/sandbox/agent_runtime.py) — the L1
cooperative layer + L3 cap request flow from docs/spec-sandbox-guardrails.md.

What must hold (spec §8, task 3):
  * the runtime boots from the exact env contract the broker injects and
    authenticates with ONLY the agent token — no request it makes ever
    carries a tenant key;
  * a cap-mint denial (or Shield down) raises BEFORE the executor callable
    is invoked — the sandbox cannot even ask the executor without a cap;
  * cooperative checks fail closed by default; SHIELD_FAIL_OPEN=1 is the
    explicit opt-out and never applies to the cap path;
  * oversized payloads are truncated before send;
  * a near-expiry / rejected token re-mints through the broker-side hook
    exactly once; a revoked instance's runtime is dead.

Cap lifecycle tests run against the real agent-auth routers in-process
(ASGITransport, real Ed25519 signing + nonce store). Failure modes use
httpx.MockTransport. Async is driven with asyncio.run() (no pytest-asyncio),
matching tests/test_sandbox_tool_executor.py.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
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
from examples.mcp_server.shield_guard import MAX_INPUT_CHARS, Blocked, ShieldGuard
from examples.sandbox.agent_runtime import CapDenied, SandboxRuntime, _jwt_exp
from examples.sandbox.broker import SandboxBroker, SandboxProvider, SandboxSpec
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


class _EnvCaptureProvider(SandboxProvider):
    """Records the env the broker would inject — the runtime's boot contract."""

    name = "fake"

    def __init__(self):
        self.envs: list[dict] = []

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        self.envs.append(dict(env))
        return f"sbx-{len(self.envs)}"

    def terminate(self, provider_id: str) -> None:
        pass


@pytest.fixture
def shield_app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "not-used-by-runtime")
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
def routed_requests(shield_app, monkeypatch):
    """Route requests.post through TestClient so the broker runs verbatim."""
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


@pytest.fixture
def sandbox_env(routed_requests, shield_app) -> dict:
    """Launch through the real broker and hand back the injected env —
    exactly what a process inside the sandbox would see."""
    provider = _EnvCaptureProvider()
    broker = SandboxBroker(
        shield_base_url="http://shield-test",
        tenant_api_key=TENANT_KEY,
        provider=provider,
        gateway_base_url="http://gateway.internal/v1",
        retry_backoff_seconds=0,
    )
    broker.launch(
        SandboxSpec(
            agent_id="billing-bot",
            user_sub="alice@acme.com",
            build_hash="sha256:abc",
            model_version="claude-opus-4-8",
            session_id="conv-1",
        )
    )
    env = provider.envs[0]
    env["_broker"] = broker  # for revocation tests; never read by from_env
    return env


def asgi_client(shield_app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=shield_app))


def make_runtime_from_env(shield_app, env, **kwargs) -> SandboxRuntime:
    return SandboxRuntime.from_env(env, client=asgi_client(shield_app), **kwargs)


def fake_jwt(exp: float) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode()
    return f"eyJhbGciOiJub25lIn0.{payload.rstrip('=')}.sig"


class _RecorderCall:
    """Stand-in for the executor invocation (e.g. an MCP tool call)."""

    def __init__(self, result: str = "done"):
        self.calls: list = []
        self.result = result

    def __call__(self, tool: str, params: dict):
        self.calls.append((tool, dict(params)))
        return self.result


# ── boot: the broker env contract, and nothing less ─────────────────


class TestFromEnv:
    def test_boots_from_broker_env_and_mints_a_real_cap(self, shield_app, sandbox_env):
        rt = make_runtime_from_env(shield_app, sandbox_env)
        assert rt.agent_id == "billing-bot"
        assert rt.agent_instance_id.startswith("billing-bot-")
        assert rt.session_id == "conv-1"

        cap = run(rt.request_cap("send_email", "u1@acme.com"))
        assert cap.cap_token
        assert cap.decision["allowed"] is True

    def test_missing_credential_refuses_to_run(self):
        with pytest.raises(RuntimeError, match="refusing to run ungoverned"):
            SandboxRuntime.from_env({"SHIELD_BASE_URL": "http://shield-test"})
        with pytest.raises(RuntimeError, match="refusing to run ungoverned"):
            SandboxRuntime.from_env({"SHIELD_AGENT_TOKEN": "tok"})

    def test_fail_open_env_is_honored_for_l1_only(self, shield_app, sandbox_env):
        rt = make_runtime_from_env(
            shield_app, dict(sandbox_env, SHIELD_FAIL_OPEN="1")
        )
        assert rt.guard.fail_open is True
        rt2 = make_runtime_from_env(shield_app, sandbox_env)
        assert rt2.guard.fail_open is False


# ── no tenant key, ever ──────────────────────────────────────────────


class TestNoTenantKey:
    def test_every_request_carries_only_the_agent_token(self):
        seen: list[tuple[str, dict]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((request.url.path, dict(request.headers)))
            if request.url.path == "/v1/shield/cap/mint":
                return httpx.Response(
                    200,
                    json={"cap_token": "cap", "expires_in": 30,
                          "decision": {"allowed": True}},
                )
            if request.url.path == "/v1/shield/tool/output":
                return httpx.Response(
                    200, json={"action": "pass", "sanitized_output": "x"}
                )
            return httpx.Response(200, json={"allowed": True, "action": "pass"})

        rt = SandboxRuntime(
            "http://shield.test",
            "agent-token-abc",
            agent_id="billing-bot",
            session_id="conv-1",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )

        async def scenario():
            await rt.request_cap("send_email", "u1@acme.com")
            await rt.check_tool("search_kb", {"q": "hi"}, user_role="analyst")
            await rt.screen_input({"q": "hi"})
            await rt.sanitize_output("search_kb", "result")

        run(scenario())
        assert len(seen) == 4
        for path, headers in seen:
            assert headers.get("x-agent-token") == "agent-token-abc", path
            assert "x-api-key" not in headers, path
            assert "authorization" not in headers, path


# ── L3: cap flow, denial before the executor ever runs ──────────────


class TestCapFlow:
    def test_minted_cap_is_handed_to_the_executor_call(self, shield_app, sandbox_env):
        rt = make_runtime_from_env(shield_app, sandbox_env)
        call = _RecorderCall("[email] sent")

        out = run(
            rt.guarded_tool_call(
                call, "send_email",
                {"to": "u1@acme.com", "subject": "hi"},
                resource="u1@acme.com",
            )
        )

        assert out == "[email] sent"
        (tool, params), = call.calls
        assert tool == "send_email"
        assert params["to"] == "u1@acme.com"
        cap_token = params["cap_token"]

        # The cap is real and single-use: first verify burns the nonce.
        async def verify():
            async with asgi_client(shield_app) as c:
                body = {"cap_token": cap_token, "expected_tool": "send_email"}
                first = await c.post("http://s/v1/shield/cap/verify", json=body)
                second = await c.post("http://s/v1/shield/cap/verify", json=body)
                return first.json(), second.json()

        first, second = run(verify())
        assert first["valid"] is True
        assert second["valid"] is False

    def test_denial_never_invokes_the_executor(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403, json={"detail": {"error": "authz_denied", "request_id": "r1"}}
            )

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        call = _RecorderCall()
        with pytest.raises(CapDenied) as exc:
            run(rt.guarded_tool_call(call, "send_email", {"to": "x"}, resource="x"))
        assert exc.value.stage == "policy"
        assert call.calls == []

    def test_verbose_denial_surfaces_reasons(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={"detail": {"error": "authz_denied",
                                 "reasons": ["role 'viewer' lacks send_email"]}},
            )

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(CapDenied, match="lacks send_email") as exc:
            run(rt.request_cap("send_email", "x"))
        assert exc.value.reasons == ["role 'viewer' lacks send_email"]

    def test_approval_required_surfaces_the_hitl_request(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={"detail": {"reason": "approval_required",
                                 "request_id": "apr-1",
                                 "required_approvals": 1,
                                 "expires_at": "2026-07-10T00:00:00Z"}},
            )

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(CapDenied, match="approval required") as exc:
            run(rt.request_cap("delete_account", "acct-1"))
        assert exc.value.stage == "policy"
        assert exc.value.approval["request_id"] == "apr-1"

    def test_shield_down_denies_even_with_fail_open(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("shield down")

        rt = SandboxRuntime(
            "http://shield.test", "tok", fail_open=True,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        call = _RecorderCall()
        with pytest.raises(CapDenied) as exc:
            run(rt.guarded_tool_call(call, "t", {}, resource="r"))
        assert exc.value.stage == "unavailable"
        assert call.calls == []

    def test_mint_5xx_denies(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(CapDenied) as exc:
            run(rt.request_cap("t", "r"))
        assert exc.value.stage == "unavailable"

    def test_revoked_instance_cannot_mint(self, shield_app, sandbox_env):
        rt = make_runtime_from_env(shield_app, sandbox_env)
        run(rt.request_cap("send_email", "u1@acme.com"))  # alive before revoke

        broker: SandboxBroker = sandbox_env["_broker"]
        broker._client.revoke_instance(rt.agent_instance_id)

        with pytest.raises(CapDenied) as exc:
            run(rt.request_cap("send_email", "u1@acme.com"))
        assert exc.value.stage == "auth"


# ── L1: cooperative checks fail closed, cap payload size ────────────


class TestCooperativeChecks:
    def test_shield_down_fails_closed_by_default(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("shield down")

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(Blocked) as exc:
            run(rt.check_tool("search_kb", {}, user_role="analyst"))
        assert exc.value.stage == "unavailable"

    def test_fail_open_lets_l1_through_when_shield_is_down(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("shield down")

        rt = SandboxRuntime(
            "http://shield.test", "tok", fail_open=True,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        run(rt.check_tool("search_kb", {}, user_role="analyst"))  # no raise
        run(rt.screen_input({"q": "hi"}))

    def test_rbac_block_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"allowed": False, "action": "block",
                      "guardrail_results": [{"passed": False,
                                             "message": "role not permitted"}]},
            )

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(Blocked, match="role not permitted") as exc:
            run(rt.check_tool("send_email", {}, user_role="viewer"))
        assert exc.value.stage == "rbac"

    def test_oversized_args_truncated_before_send(self):
        sizes: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            sizes.append(len(json.loads(request.content)["message"]))
            return httpx.Response(200, json={"action": "pass", "safe": True})

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        run(rt.screen_input({"blob": "A" * (MAX_INPUT_CHARS * 3)}))
        assert sizes == [MAX_INPUT_CHARS]


# ── token lifecycle: proactive re-mint through the broker hook ──────


class TestTokenRefresh:
    def test_jwt_exp_parsing(self):
        assert _jwt_exp(fake_jwt(1234.0)) == 1234.0
        assert _jwt_exp("not-a-jwt") is None
        assert _jwt_exp("a.!!!.c") is None

    def test_needs_refresh_near_expiry(self):
        soon = SandboxRuntime(
            "http://s", fake_jwt(time.time() + 10),
            client=httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200))),
        )
        assert soon.needs_refresh() is True  # inside the 30 s margin
        fresh = SandboxRuntime(
            "http://s", fake_jwt(time.time() + 300),
            client=httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200))),
        )
        assert fresh.needs_refresh() is False
        opaque = SandboxRuntime(
            "http://s", "opaque-token",
            client=httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200))),
        )
        assert opaque.needs_refresh() is False  # server remains authoritative

    def test_near_expiry_remints_and_uses_the_new_token(self):
        old, new = fake_jwt(time.time() + 5), fake_jwt(time.time() + 300)
        tokens_seen: list[str] = []
        remints: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            tokens_seen.append(request.headers["x-agent-token"])
            return httpx.Response(
                200, json={"cap_token": "cap", "expires_in": 30,
                           "decision": {"allowed": True}},
            )

        rt = SandboxRuntime(
            "http://shield.test", old,
            remint=lambda: (remints.append(1), new)[1],
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        run(rt.request_cap("t", "r"))
        assert remints == [1]
        assert tokens_seen == [new]
        assert rt.guard.agent_token == new  # L1 checks follow the fresh token

    def test_rejected_token_retries_once_after_remint(self):
        old, new = "opaque-old", fake_jwt(time.time() + 300)
        attempts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            tok = request.headers["x-agent-token"]
            attempts.append(tok)
            if tok == old:
                return httpx.Response(
                    401, json={"error": "invalid_agent_token", "detail": "expired"}
                )
            return httpx.Response(
                200, json={"cap_token": "cap", "expires_in": 30,
                           "decision": {"allowed": True}},
            )

        rt = SandboxRuntime(
            "http://shield.test", old, remint=lambda: new,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        cap = run(rt.request_cap("t", "r"))
        assert cap.cap_token == "cap"
        assert attempts == [old, new]

    def test_rejected_token_without_hook_is_an_auth_denial(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, json={"error": "invalid_agent_token", "detail": "revoked"}
            )

        rt = SandboxRuntime(
            "http://shield.test", "tok",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        with pytest.raises(CapDenied) as exc:
            run(rt.request_cap("t", "r"))
        assert exc.value.stage == "auth"


# ── shield_guard: the additive agent-token credential mode ──────────


class TestShieldGuardAgentTokenMode:
    def test_agent_token_only_headers(self):
        g = ShieldGuard(
            base_url="http://s", agent_token="tok", agent_id="billing-bot"
        )
        h = g._headers()
        assert h["X-Agent-Token"] == "tok"
        assert "X-API-Key" not in h

    def test_tenant_key_mode_unchanged(self):
        g = ShieldGuard(base_url="http://s", tenant_key="acme", agent_id="a")
        h = g._headers()
        assert h["X-API-Key"] == "acme"
        assert "X-Agent-Token" not in h

    def test_no_credential_raises(self):
        with pytest.raises(ValueError, match="credential"):
            ShieldGuard(base_url="http://s", agent_id="a")
