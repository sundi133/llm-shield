"""Sandbox broker (examples/sandbox/broker.py) against a real in-process
Shield app — proving the L0 identity boundary from docs/spec-sandbox-guardrails.md.

What must hold (spec §8):
  * launch mints an instance-bound token and injects ONLY that credential;
  * the tenant API key can never enter a sandbox, by key name or by value;
  * mint denial or exhausted retries -> NO sandbox (fail closed);
  * revoke kills the instance's tokens/caps so a live token stops working;
  * the Modal adapter defaults to block_network and honors cidr_allowlist.

Network is never touched: requests.post is routed through TestClient, and
the Modal SDK is faked in sys.modules.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace
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
from examples.sandbox.broker import (
    BrokerError,
    MintFailure,
    ModalProvider,
    SandboxBroker,
    SandboxProvider,
    SandboxSpec,
    _is_transient,
)
from examples.shield_client import ShieldClient, ShieldError
from storage import agent_auth_stats as stats
from storage.revocation import clear_all_for_tests

TENANT_KEY = "acme"


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


class FakeProvider(SandboxProvider):
    name = "fake"

    def __init__(self):
        self.launches: list = []
        self.terminated: list = []
        self.terminate_raises = False

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        self.launches.append((spec, dict(env)))
        return f"sbx-{len(self.launches)}"

    def terminate(self, provider_id: str) -> None:
        if self.terminate_raises:
            raise RuntimeError("provider API down")
        self.terminated.append(provider_id)


@pytest.fixture
def shield_app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "not-used-by-broker")
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
    """Route requests.post through TestClient so broker + SDK run verbatim."""
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
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def broker(routed_requests, provider) -> SandboxBroker:
    b = SandboxBroker(
        shield_base_url="http://shield-test",
        tenant_api_key=TENANT_KEY,
        provider=provider,
        gateway_base_url="http://gateway.internal/v1",
        retry_backoff_seconds=0,
    )
    b._sleep = lambda _s: None
    return b


def _spec(**overrides) -> SandboxSpec:
    base = dict(
        agent_id="billing-bot",
        user_sub="alice@acme.com",
        build_hash="sha256:abc",
        model_version="claude-opus-4-8",
        session_id="conv-1",
    )
    base.update(overrides)
    return SandboxSpec(**base)


# ── L0: launch mints an instance-bound token, injects only that ────


class TestLaunch:
    def test_launch_injects_token_and_urls_never_tenant_key(self, broker, provider):
        handle = broker.launch(_spec())

        assert handle.provider == "fake"
        assert handle.provider_id == "sbx-1"
        assert handle.agent_instance_id.startswith("billing-bot-")
        assert handle.token_expires_in == 300  # sandbox-hardened short TTL

        _spec_seen, env = provider.launches[0]
        assert env["SHIELD_AGENT_TOKEN"] and "." in env["SHIELD_AGENT_TOKEN"]
        assert env["SHIELD_BASE_URL"] == "http://shield-test"
        assert env["SHIELD_AGENT_INSTANCE_ID"] == handle.agent_instance_id
        assert env["OPENAI_BASE_URL"] == "http://gateway.internal/v1"
        assert TENANT_KEY not in env.values()

    def test_instance_ids_unique_per_launch(self, broker, provider):
        h1, h2 = broker.launch(_spec()), broker.launch(_spec())
        assert h1.agent_instance_id != h2.agent_instance_id

    def test_minted_token_actually_works_for_caps(self, broker, provider):
        """The injected token is a real, usable credential (not a stub)."""
        broker.launch(_spec())
        _s, env = provider.launches[0]
        sdk = ShieldClient(base_url="http://shield-test", tenant_api_key=TENANT_KEY)
        cap = sdk.mint_cap(
            SimpleNamespace(
                header={"X-Agent-Token": env["SHIELD_AGENT_TOKEN"]},
            ),
            tool="send_email",
            resource="user/u-1/inbox",
        )
        assert cap.decision["allowed"] is True

    def test_extra_env_cannot_override_shield_vars(self, broker, provider):
        broker.launch(_spec(extra_env={"SHIELD_BASE_URL": "http://evil"}))
        _s, env = provider.launches[0]
        assert env["SHIELD_BASE_URL"] == "http://shield-test"


# ── the tenant key can never enter a sandbox ────────────────────────


class TestSecretGuard:
    def test_tenant_key_value_in_extra_env_refuses_launch(self, broker, provider):
        with pytest.raises(BrokerError, match="tenant API key"):
            broker.launch(_spec(extra_env={"MY_APP_KEY": TENANT_KEY}))
        assert provider.launches == []

    def test_forbidden_env_key_refuses_launch(self, broker, provider):
        with pytest.raises(BrokerError, match="never enter a sandbox"):
            broker.launch(_spec(extra_env={"shield_tenant_key": "anything"}))
        assert provider.launches == []


# ── fail closed: no token, no sandbox ───────────────────────────────


class TestMintFailClosed:
    def test_denial_fails_immediately_no_launch(self, broker, provider, monkeypatch):
        attempts = []

        def _deny(**kwargs):
            attempts.append(1)
            raise ShieldError("403 /v1/tenant/me/agent-auth/agent-token: not registered")

        monkeypatch.setattr(broker._client, "mint_agent_token", _deny)
        with pytest.raises(MintFailure, match="denied"):
            broker.launch(_spec())
        assert len(attempts) == 1  # 4xx is not retried
        assert provider.launches == []

    def test_transient_5xx_retries_then_succeeds(self, broker, provider, monkeypatch):
        real_mint = broker._client.mint_agent_token
        attempts = []

        def _flaky(**kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise ShieldError("503 /v1/tenant/me/agent-auth/agent-token: upstream")
            return real_mint(**kwargs)

        monkeypatch.setattr(broker._client, "mint_agent_token", _flaky)
        handle = broker.launch(_spec())
        assert len(attempts) == 2
        assert handle.provider_id == "sbx-1"

    def test_exhausted_retries_fail_closed(self, broker, provider, monkeypatch):
        import requests as _requests

        def _down(**kwargs):
            raise _requests.ConnectionError("shield unreachable")

        monkeypatch.setattr(broker._client, "mint_agent_token", _down)
        with pytest.raises(MintFailure, match="after 3 attempts"):
            broker.launch(_spec())
        assert provider.launches == []

    def test_is_transient_classification(self):
        assert _is_transient(ShieldError("503 /p: x")) is True
        assert _is_transient(ShieldError("429 /p: slow down")) is True
        assert _is_transient(ShieldError("403 /p: denied")) is False
        assert _is_transient(ShieldError("400 /p: bad claims")) is False
        assert _is_transient(ShieldError("connection reset")) is True


# ── containment: revoke kills a live credential ─────────────────────


class TestRevoke:
    def test_revoke_kills_tokens_and_terminates(self, broker, provider):
        handle = broker.launch(_spec())
        _s, env = provider.launches[0]
        token_header = SimpleNamespace(
            header={"X-Agent-Token": env["SHIELD_AGENT_TOKEN"]},
        )
        sdk = ShieldClient(base_url="http://shield-test", tenant_api_key=TENANT_KEY)
        # sanity: the credential works before revocation
        sdk.mint_cap(token_header, tool="t", resource="r")

        broker.revoke(handle)

        assert provider.terminated == [handle.provider_id]
        with pytest.raises(ShieldError):
            sdk.mint_cap(token_header, tool="t", resource="r")

    def test_provider_terminate_failure_does_not_mask_revocation(
        self, broker, provider
    ):
        handle = broker.launch(_spec())
        provider.terminate_raises = True
        broker.revoke(handle)  # must not raise: credentials are already dead
        assert provider.terminated == []


# ── Modal adapter: egress posture ───────────────────────────────────


def _fake_modal(monkeypatch, created: list):
    fake = types.ModuleType("modal")
    fake.App = SimpleNamespace(
        lookup=lambda name, create_if_missing=False: f"app:{name}"
    )

    class _Image:
        @staticmethod
        def debian_slim():
            return "img:debian_slim"

        @staticmethod
        def from_registry(ref):
            return f"img:{ref}"

    class _Secret:
        @staticmethod
        def from_dict(d):
            return {"env": dict(d)}

    class _Sandbox:
        @staticmethod
        def create(*args, **kwargs):
            created.append((args, kwargs))
            return SimpleNamespace(object_id="modal-sbx-1")

    fake.Image = _Image
    fake.Secret = _Secret
    fake.Sandbox = _Sandbox
    monkeypatch.setitem(sys.modules, "modal", fake)


class TestModalProvider:
    def test_default_is_block_network(self, monkeypatch):
        created: list = []
        _fake_modal(monkeypatch, created)
        pid = ModalProvider("acme-agents").launch(_spec(), {"A": "1"})
        assert pid == "modal-sbx-1"
        _args, kwargs = created[0]
        assert kwargs["block_network"] is True
        assert "cidr_allowlist" not in kwargs
        assert kwargs["secrets"] == [{"env": {"A": "1"}}]

    def test_egress_cidrs_become_allowlist(self, monkeypatch):
        created: list = []
        _fake_modal(monkeypatch, created)
        ModalProvider("acme-agents", egress_cidrs=["10.1.2.3/32"]).launch(
            _spec(), {}
        )
        _args, kwargs = created[0]
        assert kwargs["cidr_allowlist"] == ["10.1.2.3/32"]
        assert "block_network" not in kwargs

    def test_entrypoint_and_image_forwarded(self, monkeypatch):
        created: list = []
        _fake_modal(monkeypatch, created)
        ModalProvider("acme-agents").launch(
            _spec(image="acme/agent:1.2", entrypoint=("python", "run.py")), {}
        )
        args, kwargs = created[0]
        assert args == ("python", "run.py")
        assert kwargs["image"] == "img:acme/agent:1.2"
