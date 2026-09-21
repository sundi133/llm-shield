"""Sandbox broker — per-sandbox identity (L0) for agents in E2B / Daytona / Modal.

Runs in the CUSTOMER'S TRUSTED PLANE, never inside a sandbox. The broker is
the only component that holds the tenant API key. Each sandbox it launches
receives exactly one credential — a short-lived, instance-bound agent token
(default 300 s) — plus the base URLs it needs:

    SHIELD_AGENT_TOKEN        instance-bound token (the ONLY secret in the box)
    SHIELD_BASE_URL           Shield deployment (cooperative checks + cap mint)
    SHIELD_AGENT_INSTANCE_ID  identity for re-mint / revocation
    SHIELD_AGENT_ID           logical agent identity
    SHIELD_SESSION_ID         conversation/session id
    OPENAI_BASE_URL           egress gateway, so in-sandbox LLM calls are guarded

Fail policy: no token, no sandbox. A mint denial (403, e.g. unregistered
agent) or exhausted retries aborts the launch — we never start a sandbox
that would run ungoverned.

Spec: docs/spec-sandbox-guardrails.md (task 1).
Architecture: docs/sandbox-guardrails-design.md §3-§4 (L0).

Usage:
    provider = ModalProvider("acme-agents",
                             egress_cidrs=["10.1.2.3/32"])  # gateway only
    broker = SandboxBroker(
        shield_base_url="https://shield.acme.com",
        tenant_api_key=os.environ["SHIELD_TENANT_KEY"],     # stays here
        gateway_base_url="https://llm-gateway.acme.internal/v1",
        provider=provider,
    )
    handle = broker.launch(SandboxSpec(
        agent_id="billing-bot", user_sub="alice@acme.com",
        build_hash="sha256:abc...", model_version="claude-opus-4-8",
        session_id=conversation_id,
    ))
    ...
    broker.revoke(handle)   # kills the instance's tokens + caps in <=1 s
"""

from __future__ import annotations

import abc
import dataclasses
import time
import uuid
from typing import Optional, Sequence

import requests

try:  # repo layout: pytest / scripts run from the repo root
    from examples.shield_client import AgentToken, ShieldClient, ShieldError
except ImportError:  # folder copied standalone next to shield_client.py
    from shield_client import AgentToken, ShieldClient, ShieldError  # type: ignore


class BrokerError(Exception):
    """The broker refused or failed to launch/revoke a sandbox."""


class MintFailure(BrokerError):
    """Agent-token mint failed — the sandbox was NOT launched (fail closed)."""


# Env keys that must never be set on a sandbox, whatever their value.
_FORBIDDEN_ENV_KEYS = frozenset({
    "SHIELD_TENANT_KEY",
    "SHIELD_ADMIN_KEY",
    "SHIELD_API_KEY",
    "X_API_KEY",
})


@dataclasses.dataclass(frozen=True)
class SandboxSpec:
    """One launch request. Egress posture is deployment-level and therefore
    lives on the provider adapter, not here."""

    agent_id: str
    user_sub: str
    build_hash: str
    model_version: str
    session_id: str
    image: Optional[str] = None            # provider default when None
    entrypoint: Sequence[str] = ()         # provider default when empty
    extra_env: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class SandboxHandle:
    agent_instance_id: str
    provider: str
    provider_id: str                       # provider-specific sandbox id
    token_expires_in: int


class SandboxProvider(abc.ABC):
    """One adapter per sandbox vendor."""

    name: str = "abstract"

    @abc.abstractmethod
    def launch(self, spec: SandboxSpec, env: dict) -> str:
        """Start a sandbox with ``env`` injected; return the provider's id."""

    @abc.abstractmethod
    def terminate(self, provider_id: str) -> None:
        """Stop the sandbox. Best effort — revocation is the real kill."""


class ModalProvider(SandboxProvider):
    """Modal adapter. Egress posture (design doc §6):

    * ``egress_cidrs=None`` (default) -> ``block_network=True``: compute-only.
      The sandbox reaches nothing, including Shield; use for pure code
      execution where results return via the provider API.
    * ``egress_cidrs=[...]`` -> Modal ``cidr_allowlist``: allow ONLY the
      egress gateway / Shield addresses. This is what makes the L2 gateway
      genuinely non-bypassable on Modal.

    ``modal`` is imported lazily so this module (and its tests) need no
    provider SDK installed.
    """

    name = "modal"

    def __init__(
        self,
        app_name: str,
        *,
        egress_cidrs: Optional[Sequence[str]] = None,
        default_image: Optional[str] = None,
        timeout_seconds: int = 600,
    ):
        self.app_name = app_name
        self.egress_cidrs = list(egress_cidrs) if egress_cidrs is not None else None
        self.default_image = default_image
        self.timeout_seconds = timeout_seconds

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        import modal  # example-local dep; never in root requirements

        app = modal.App.lookup(self.app_name, create_if_missing=True)
        image_ref = spec.image or self.default_image
        image = (
            modal.Image.from_registry(image_ref)
            if image_ref
            else modal.Image.debian_slim()
        )
        kwargs = {
            "app": app,
            "image": image,
            "timeout": self.timeout_seconds,
            "secrets": [modal.Secret.from_dict(dict(env))],
        }
        if self.egress_cidrs is None:
            kwargs["block_network"] = True
        else:
            kwargs["cidr_allowlist"] = list(self.egress_cidrs)
        sandbox = modal.Sandbox.create(*tuple(spec.entrypoint), **kwargs)
        return sandbox.object_id

    def terminate(self, provider_id: str) -> None:
        import modal

        modal.Sandbox.from_id(provider_id).terminate()


def _is_transient(err: ShieldError) -> bool:
    """Retry only transient Shield failures (5xx / 429); policy denials
    (403 unregistered agent, 400 bad claims) must surface immediately.
    ShieldError messages start with the HTTP status; if unparseable we
    treat the failure as transient and let the retry budget decide."""
    try:
        status = int(str(err).split(" ", 1)[0])
    except (ValueError, IndexError):
        return True
    return status >= 500 or status == 429


class SandboxBroker:
    """Holds the tenant key; launches sandboxes that never see it."""

    def __init__(
        self,
        shield_base_url: str,
        tenant_api_key: Optional[str] = None,
        provider: Optional[SandboxProvider] = None,
        *,
        gateway_base_url: Optional[str] = None,
        token_ttl_seconds: int = 300,
        mint_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
        auth_token: Optional[str] = None,
    ):
        if provider is None:
            raise BrokerError("a SandboxProvider is required")
        self._client = ShieldClient(
            base_url=shield_base_url,
            tenant_api_key=tenant_api_key,
            auth_token=auth_token,
        )
        self.provider = provider
        self.gateway_base_url = (
            gateway_base_url.rstrip("/") if gateway_base_url else None
        )
        self.token_ttl_seconds = token_ttl_seconds
        self.mint_retries = max(1, mint_retries)
        self.retry_backoff_seconds = retry_backoff_seconds
        self._sleep = time.sleep  # injectable for tests

    # ── launch ──────────────────────────────────────────────────────

    def launch(self, spec: SandboxSpec) -> SandboxHandle:
        """Mint an instance-bound token, then start the sandbox with it.

        Ordering matters: identity first, sandbox second. A sandbox is never
        started without its token (fail closed, spec §7)."""
        agent_instance_id = f"{spec.agent_id}-{uuid.uuid4().hex[:12]}"
        token = self.mint_token(spec, agent_instance_id)
        env = self._sandbox_env(spec, agent_instance_id, token)
        provider_id = self.provider.launch(spec, env)
        return SandboxHandle(
            agent_instance_id=agent_instance_id,
            provider=self.provider.name,
            provider_id=provider_id,
            token_expires_in=token.expires_in,
        )

    def mint_token(self, spec: SandboxSpec, agent_instance_id: str) -> AgentToken:
        """Mint (or re-mint, when the runtime nears expiry) the instance-bound
        agent token. Transient failures retry with linear backoff; denials
        raise immediately."""
        last: Optional[Exception] = None
        for attempt in range(1, self.mint_retries + 1):
            try:
                return self._client.mint_agent_token(
                    user_sub=spec.user_sub,
                    agent_id=spec.agent_id,
                    agent_instance_id=agent_instance_id,
                    build_hash=spec.build_hash,
                    model_version=spec.model_version,
                    session_id=spec.session_id,
                    ttl_seconds=self.token_ttl_seconds,
                )
            except ShieldError as e:
                if not _is_transient(e):
                    raise MintFailure(f"agent-token mint denied: {e}") from e
                last = e
            except requests.RequestException as e:
                last = e
            if attempt < self.mint_retries:
                self._sleep(self.retry_backoff_seconds * attempt)
        raise MintFailure(
            f"agent-token mint failed after {self.mint_retries} attempts: {last}"
        ) from last

    # ── contain ─────────────────────────────────────────────────────

    def revoke(self, handle: SandboxHandle, *, terminate: bool = True) -> None:
        """Kill every token + cap for the instance (<=1 s propagation), then
        best-effort terminate the sandbox itself."""
        self._client.revoke_instance(handle.agent_instance_id)
        if terminate:
            try:
                self.provider.terminate(handle.provider_id)
            except Exception:
                # Credentials are already dead; a zombie sandbox can compute
                # but cannot act. Don't mask the successful revocation.
                pass

    # ── env assembly ────────────────────────────────────────────────

    def _sandbox_env(
        self, spec: SandboxSpec, agent_instance_id: str, token: AgentToken
    ) -> dict:
        env = dict(spec.extra_env)
        env.update(
            {
                "SHIELD_AGENT_TOKEN": token.token,
                "SHIELD_BASE_URL": self._client.base_url,
                "SHIELD_AGENT_INSTANCE_ID": agent_instance_id,
                "SHIELD_AGENT_ID": spec.agent_id,
                "SHIELD_SESSION_ID": spec.session_id,
            }
        )
        if self.gateway_base_url:
            env["OPENAI_BASE_URL"] = self.gateway_base_url
        self._assert_no_tenant_secret(env)
        return env

    def _assert_no_tenant_secret(self, env: dict) -> None:
        """Refuse to launch rather than leak: no forbidden key names, and no
        value equal to the tenant API key, may enter a sandbox."""
        for key, value in env.items():
            if key.upper() in _FORBIDDEN_ENV_KEYS:
                raise BrokerError(
                    f"refusing to launch: env key {key!r} must never enter a sandbox"
                )
            if (
                isinstance(value, str)
                and value
                and value == self._client.tenant_api_key
            ):
                raise BrokerError(
                    f"refusing to launch: env {key!r} contains the tenant API key"
                )
