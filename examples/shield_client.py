"""Minimal customer SDK for Shield's agent AuthN/AuthZ.

This is what a customer drops into their agent runtime. Three calls:

    client = ShieldClient(base_url="https://shield.acme.com",
                          tenant_api_key=os.environ["SHIELD_TENANT_KEY"])

    # ── once per agent process (or every ~10 min) ───────────────────
    token = client.mint_agent_token(
        user_sub="alice@acme.com",
        agent_id="billing-bot",
        agent_instance_id=f"{socket.gethostname()}-{os.getpid()}",
        build_hash="sha256:abc...",     # your CI fills this in
        model_version="claude-opus-4.7",
        session_id=conversation_id,
    )

    # ── before every tool call (caps are one-shot, ≤60s) ───────────
    cap = client.mint_cap(token, tool="send_email",
                          resource=f"user/{user_id}/inbox")

    # The cap is what you pass to the tool. The tool side verifies it:
    valid, claims = client.verify_cap(cap, expected_tool="send_email")
    if not valid:
        raise PermissionError("cap rejected")
    # ... execute the action ...

Customers do NOT have the admin key. All endpoints used here are
authenticated by the tenant API key, the same one used elsewhere.

The SDK is pure stdlib + `requests` so it works in any Python ≥ 3.9
without extra deps beyond what an agent app already has.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Optional

import requests


class ShieldError(Exception):
    """Raised when Shield rejects a call or the response is malformed."""


@dataclasses.dataclass(frozen=True)
class AgentToken:
    """A short-lived signed agent token. Keep it in memory; don't log it."""
    token: str
    expires_in: int

    @property
    def header(self) -> dict:
        return {"X-Agent-Token": self.token}


@dataclasses.dataclass(frozen=True)
class Capability:
    """A single-use, ≤60s capability for one tool + resource."""
    cap_token: str
    expires_in: int
    decision: dict  # {allowed, reasons, agent_id, role, tool, resource}


class ShieldClient:
    """Talks to a Shield deployment with the tenant API key.

    For RunPod deployments, also pass the RunPod auth token:
        client = ShieldClient(
            base_url="https://xxx.api.runpod.ai",
            tenant_api_key="your-tenant-key",
            auth_token="rpa_xxx",  # or set RUNPOD_TOKEN env
        )
    """

    def __init__(
        self,
        base_url: str,
        tenant_api_key: Optional[str] = None,
        auth_token: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.tenant_api_key = tenant_api_key or os.environ.get("SHIELD_TENANT_KEY", "")
        if not self.tenant_api_key:
            raise ShieldError(
                "tenant API key required (set SHIELD_TENANT_KEY or pass tenant_api_key)"
            )
        # RunPod / proxy auth token (Authorization: Bearer)
        self.auth_token = auth_token or os.environ.get("RUNPOD_TOKEN", "")
        self.timeout = timeout

    # ── private ─────────────────────────────────────────────────────

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = {"Content-Type": "application/json", "X-API-Key": self.tenant_api_key}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        if extra:
            h.update(extra)
        return h

    def _post(self, path: str, body: dict, extra_headers: Optional[dict] = None) -> dict:
        r = requests.post(
            f"{self.base_url}{path}",
            json=body, headers=self._headers(extra_headers),
            timeout=self.timeout,
        )
        if not r.ok:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise ShieldError(f"{r.status_code} {path}: {detail}")
        return r.json()

    # ── AuthN ───────────────────────────────────────────────────────

    def mint_agent_token(
        self,
        *,
        user_sub: str,
        agent_id: str,
        agent_instance_id: str,
        build_hash: str,
        model_version: str,
        session_id: str,
        parent_agent_id: Optional[str] = None,
        ttl_seconds: int = 600,
    ) -> AgentToken:
        """Exchange the tenant API key for a signed agent token.

        Call this:
          * at agent process startup, and
          * whenever the previous token is within ~30s of expiry.

        The token is bound to the tenant resolved from the API key —
        you cannot mint a token for a different tenant.
        """
        body = {
            "user_sub": user_sub,
            "agent_id": agent_id,
            "agent_instance_id": agent_instance_id,
            "build_hash": build_hash,
            "model_version": model_version,
            "session_id": session_id,
            "ttl_seconds": ttl_seconds,
        }
        if parent_agent_id:
            body["parent_agent_id"] = parent_agent_id
        data = self._post("/v1/tenant/me/agent-auth/agent-token", body)
        return AgentToken(token=data["agent_token"], expires_in=data["expires_in"])

    # ── AuthZ ───────────────────────────────────────────────────────

    def mint_cap(
        self,
        token: AgentToken,
        *,
        tool: str,
        resource: str,
        scope_constraints: Optional[list[str]] = None,
        clearance_max: str = "public",
        ttl_seconds: int = 30,
        data_scope: Optional[str] = None,
    ) -> Capability:
        """Ask Shield to authorize ONE specific tool call.

        Returns a single-use cap. If the AuthZ policy denies, raises
        ShieldError(403) with the reasons — surface those to the user.
        """
        body: dict = {
            "tool": tool,
            "resource": resource,
            "clearance_max": clearance_max,
            "ttl_seconds": ttl_seconds,
            "scope_constraints": list(scope_constraints or []),
        }
        if data_scope:
            body["data_scope"] = data_scope
        data = self._post("/v1/shield/cap/mint", body, extra_headers=token.header)
        return Capability(
            cap_token=data["cap_token"],
            expires_in=data["expires_in"],
            decision=data["decision"],
        )

    def revoke_instance(self, agent_instance_id: str) -> dict:
        """Self-service revoke: kill every token + cap for one agent instance.

        Ownership is enforced server-side — a tenant can only revoke
        instances it minted (403/404 otherwise). Propagates in <=1s.
        """
        return self._post(
            "/v1/tenant/me/agent-auth/revoke",
            {"agent_instance_id": agent_instance_id},
        )

    def verify_cap(
        self,
        cap: "str | Capability",
        *,
        expected_tool: str,
        expected_resource: Optional[str] = None,
    ) -> tuple[bool, dict]:
        """Tool-server side: verify a cap before executing the action.

        Returns (valid, claims_or_error_dict). Burns the nonce on first
        use; a second call with the same cap returns valid=False
        ('cap replay detected').
        """
        cap_str = cap.cap_token if isinstance(cap, Capability) else cap
        body = {"cap_token": cap_str, "expected_tool": expected_tool}
        if expected_resource is not None:
            body["expected_resource"] = expected_resource
        # /cap/verify does NOT require the tenant key — it's the tool
        # server's path, gated by the cap itself. But RunPod proxy
        # still needs the auth token.
        verify_headers = {"Content-Type": "application/json"}
        if self.auth_token:
            verify_headers["Authorization"] = f"Bearer {self.auth_token}"
        r = requests.post(
            f"{self.base_url}/v1/shield/cap/verify",
            json=body, headers=verify_headers,
            timeout=self.timeout,
        )
        if not r.ok:
            raise ShieldError(f"{r.status_code} /v1/shield/cap/verify: {r.text}")
        data = r.json()
        if data.get("valid"):
            return True, data.get("claims") or {}
        return False, {"error": data.get("error", "unknown")}
