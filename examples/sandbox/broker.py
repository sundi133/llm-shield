"""Sandbox broker — per-sandbox identity (L0) for agents in Modal / K8s Agent
Sandbox / E2B / Daytona.

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


def _dns1123(value: str, *, max_len: int = 63) -> str:
    """Sanitize to a Kubernetes-safe name segment (lowercase alnum + '-')."""
    safe = "".join(c if c.isalnum() else "-" for c in value.lower())
    safe = safe.strip("-") or "sbx"
    return safe[:max_len].rstrip("-") or "sbx"


def _egress_network_policy(
    name: str,
    namespace: str,
    pod_selector_labels: dict,
    *,
    egress_cidrs: Optional[Sequence[str]] = None,
    gateway_pod_selector: Optional[dict] = None,
    allow_dns: bool = True,
) -> dict:
    """Build a deny-by-default egress ``NetworkPolicy`` manifest.

    Mirrors ``ModalProvider``'s ``egress_cidrs`` posture using the
    Kubernetes-native primitive: no rule at all -> every egress packet from
    a matching pod is dropped (CNI-dependent, e.g. Cilium/Calico — design
    doc §6). ``gateway_pod_selector`` additionally allows an in-cluster
    egress gateway by label instead of a fixed CIDR, which is the common
    case when the gateway also runs in this cluster.

    Pure and side-effect free so it can be unit-tested and reused by the
    live kind-cluster proof without a real API client.
    """
    egress: list = []
    if allow_dns:
        egress.append(
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                        },
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }
                ],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            }
        )
    if gateway_pod_selector:
        egress.append({"to": [{"podSelector": {"matchLabels": gateway_pod_selector}}]})
    if egress_cidrs:
        egress.append({"to": [{"ipBlock": {"cidr": c}} for c in egress_cidrs]})
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": dict(pod_selector_labels)},
            "policyTypes": ["Egress"],
            "egress": egress,
        },
    }


class K8sAgentSandboxProvider(SandboxProvider):
    """Kubernetes SIG [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/)
    adapter (``agents.x-k8s.io/v1beta1``). The on-prem/in-VPC answer: strong
    egress lockdown via a Kubernetes ``NetworkPolicy`` (deny-by-default +
    allowlist, CNI-dependent) instead of a vendor firewall setting, so the
    L2 non-bypassability claim holds in-cluster (design doc §6).

    Warm-pool constraint (spec §7): pods in a ``SandboxWarmPool`` exist
    *before* they are claimed, so the per-instance token must be delivered
    at claim time — never baked into a ``SandboxTemplate``/warm-pool image,
    where every pod in the pool would share it. This adapter delivers it as
    a **per-claim Secret**, referenced by the claim's pod via
    ``valueFrom.secretKeyRef`` — never as a literal value on the claim spec.

    Thin by design (spec §9 task 5): the CRD is ``v1beta1`` and may churn.
    ``kubernetes`` (the generic client, not a project-specific SDK) is
    imported lazily so this module needs no cluster access to import or
    unit-test. API clients (``core_v1``/``networking_v1``/``custom_objects``)
    can be injected directly for tests; when omitted, real ones are built
    from the ambient kubeconfig / in-cluster config on first use.
    """

    name = "k8s-agent-sandbox"

    GROUP = "agents.x-k8s.io"
    VERSION = "v1beta1"
    PLURAL = "sandboxclaims"

    def __init__(
        self,
        namespace: str,
        warm_pool_name: str,
        *,
        egress_cidrs: Optional[Sequence[str]] = None,
        gateway_pod_selector: Optional[dict] = None,
        allow_dns: bool = True,
        core_v1=None,
        networking_v1=None,
        custom_objects=None,
    ):
        self.namespace = namespace
        self.warm_pool_name = warm_pool_name
        self.egress_cidrs = list(egress_cidrs) if egress_cidrs is not None else None
        self.gateway_pod_selector = gateway_pod_selector
        self.allow_dns = allow_dns
        self._core_v1 = core_v1
        self._networking_v1 = networking_v1
        self._custom_objects = custom_objects

    def _clients(self):
        if self._core_v1 is None or self._networking_v1 is None or self._custom_objects is None:
            import kubernetes  # example-local dep; never in root requirements

            try:
                kubernetes.config.load_incluster_config()
            except kubernetes.config.ConfigException:
                kubernetes.config.load_kube_config()
            self._core_v1 = self._core_v1 or kubernetes.client.CoreV1Api()
            self._networking_v1 = self._networking_v1 or kubernetes.client.NetworkingV1Api()
            self._custom_objects = self._custom_objects or kubernetes.client.CustomObjectsApi()
        return self._core_v1, self._networking_v1, self._custom_objects

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        core_v1, networking_v1, custom_objects = self._clients()
        instance_id = env.get("SHIELD_AGENT_INSTANCE_ID") or spec.agent_id
        claim_name = f"sbx-{_dns1123(instance_id)}"
        labels = {"agents.x-k8s.io/claim": claim_name}

        core_v1.create_namespaced_secret(
            namespace=self.namespace,
            body={
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": claim_name, "namespace": self.namespace},
                "stringData": dict(env),
            },
        )
        networking_v1.create_namespaced_network_policy(
            namespace=self.namespace,
            body=_egress_network_policy(
                claim_name,
                self.namespace,
                labels,
                egress_cidrs=self.egress_cidrs,
                gateway_pod_selector=self.gateway_pod_selector,
                allow_dns=self.allow_dns,
            ),
        )
        claim_body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "SandboxClaim",
            "metadata": {"name": claim_name, "namespace": self.namespace, "labels": labels},
            "spec": {
                "warmPoolRef": {"name": self.warm_pool_name},
                "additionalPodMetadata": {"labels": labels},
                "env": [
                    {"name": key, "valueFrom": {"secretKeyRef": {"name": claim_name, "key": key}}}
                    for key in env
                ],
            },
        }
        custom_objects.create_namespaced_custom_object(
            group=self.GROUP,
            version=self.VERSION,
            namespace=self.namespace,
            plural=self.PLURAL,
            body=claim_body,
        )
        return f"{self.namespace}/{claim_name}"

    def terminate(self, provider_id: str) -> None:
        core_v1, networking_v1, custom_objects = self._clients()
        namespace, claim_name = provider_id.split("/", 1)
        custom_objects.delete_namespaced_custom_object(
            group=self.GROUP,
            version=self.VERSION,
            namespace=namespace,
            plural=self.PLURAL,
            name=claim_name,
        )
        networking_v1.delete_namespaced_network_policy(name=claim_name, namespace=namespace)
        core_v1.delete_namespaced_secret(name=claim_name, namespace=namespace)


class E2BProvider(SandboxProvider):
    """[E2B](https://e2b.dev) adapter.

    E2B does not offer a guaranteed outbound firewall today (design doc
    §6, "partial" posture) — there is deliberately no ``egress_cidrs``
    knob here that would imply otherwise. Egress control for E2B sandboxes
    comes from the gateway `base_url` configuration (L2) plus the
    cap-gated tool executor (L3), which is bypass-proof regardless of
    network posture; the residual read-only-egress risk is documented in
    spec §5 and must ship in the README verbatim.

    ``e2b`` is imported lazily so this module (and its tests) need no
    provider SDK installed.
    """

    name = "e2b"

    def __init__(
        self,
        *,
        default_template: Optional[str] = None,
        timeout_seconds: int = 600,
    ):
        self.default_template = default_template
        self.timeout_seconds = timeout_seconds

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        from e2b import Sandbox as E2BSandbox  # example-local dep; never in root requirements

        sandbox = E2BSandbox.create(
            template=spec.image or self.default_template,
            envs=dict(env),
            timeout=self.timeout_seconds,
        )
        if spec.entrypoint:
            sandbox.commands.run(" ".join(spec.entrypoint), background=True)
        return sandbox.sandbox_id

    def terminate(self, provider_id: str) -> None:
        from e2b import Sandbox as E2BSandbox

        E2BSandbox.kill(provider_id)


class DaytonaProvider(SandboxProvider):
    """[Daytona](https://daytona.io) adapter.

    Daytona's egress posture is runner/network-policy dependent (design
    doc §6, "partial") — same as E2B, there is no ``egress_cidrs`` knob
    here. Rely on the gateway (L2) + cap-gated executor (L3) as the hard
    boundary; the residual read-only-egress risk is documented in spec §5.

    ``daytona`` is imported lazily so this module (and its tests) need no
    provider SDK installed.
    """

    name = "daytona"

    def __init__(
        self,
        *,
        default_snapshot: Optional[str] = None,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        self.default_snapshot = default_snapshot
        self.api_key = api_key
        self.api_url = api_url
        self._client = None

    def _daytona(self):
        if self._client is None:
            from daytona import Daytona, DaytonaConfig  # example-local dep

            config = DaytonaConfig(api_key=self.api_key, api_url=self.api_url)
            self._client = Daytona(config)
        return self._client

    def launch(self, spec: SandboxSpec, env: dict) -> str:
        from daytona import CreateSandboxFromSnapshotParams

        params = CreateSandboxFromSnapshotParams(
            snapshot=spec.image or self.default_snapshot,
            env_vars=dict(env),
        )
        sandbox = self._daytona().create(params)
        if spec.entrypoint:
            sandbox.process.exec(" ".join(spec.entrypoint), env=dict(env))
        return sandbox.id

    def terminate(self, provider_id: str) -> None:
        sandbox = self._daytona().get(provider_id)
        sandbox.delete()


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
