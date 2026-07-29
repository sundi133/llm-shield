"""HTTP enforcement backend for the MCP proxy/gateway.

Implements the same surface as ``core.mcp.enforcement`` (the in-process pipeline)
but delegates to Shield's guard endpoints over HTTP:

    enforce_tool_call     -> POST /v1/shield/tool/check    (RBAC + input policy)
    sanitize_tool_result  -> POST /v1/shield/tool/output   (output DLP)
    filter_tools_for_role -> local (cosmetic; call-time RBAC is authoritative)

This is what makes a **thin-edge gateway** possible: the gateway holds no models
or guard state, just forwards to a central Shield data plane. Because both
backends return the exact decision/sanitize shapes ``MCPProxy`` expects, swapping
one for the other changes only *where* enforcement runs, never *what* it decides.

Reuses the request shapes from examples/mcp_server/shield_guard.py. Fail policy:
default fail-closed (block on transport error); set ``fail_open=True`` to allow.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

_MAX_OUTPUT_CHARS = 50_000


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _reason(data: dict, default: str) -> str:
    for g in data.get("guardrail_results") or []:
        if not g.get("passed", True):
            return g.get("message") or default
    return data.get("message") or default


class HTTPEnforcer:
    """Enforcement backend that calls Shield's guard endpoints.

    Args:
        base_url: Shield data-plane base URL.
        tenant_key: tenant API key sent as X-API-Key (per-tenant creds come in the
            gateway config layer; a single key can be passed here for one tenant).
        auth_token: optional bearer for a proxied Shield (RunPod etc.).
        fail_open: on transport error, allow (True) or block (False, default).
        client: injectable httpx.AsyncClient (tests pass a MockTransport client).
    """

    def __init__(
        self,
        *,
        base_url: str,
        tenant_key: str = "",
        auth_token: str = "",
        timeout: float = 10.0,
        fail_open: bool = False,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.tenant_key = tenant_key
        self.auth_token = auth_token
        self.fail_open = fail_open
        self._client = client or httpx.AsyncClient(timeout=timeout)

    def _headers(self, *, tenant_id: Optional[str], agent_key: str, user_role: Optional[str]) -> dict:
        h = {"Content-Type": "application/json"}
        if self.tenant_key:
            h["X-API-Key"] = self.tenant_key
        if tenant_id:
            h["X-Tenant-ID"] = tenant_id
        if agent_key:
            h["X-Agent-Key"] = agent_key
        if user_role:
            h["X-User-Role"] = user_role
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    async def enforce_tool_call(
        self,
        name: str,
        arguments: dict,
        *,
        agent_key: str,
        user_role: Optional[str],
        tenant_id: Optional[str],
        tenant_config: Optional[dict] = None,
        session_id: Optional[str] = None,
        workflow: Optional[str] = None,
        confirmation_token: Optional[str] = None,
        route: Optional[str] = None,
    ) -> dict:
        """Map POST /v1/shield/tool/check to the MCPProxy decision shape.

        ``session_id`` comes from a verified agent-token claim upstream; it was
        previously hardcoded to "", which silently disabled the session-scoped
        guards (confirmation, per-session rate limits) on the thin-edge path.
        ``workflow`` / ``confirmation_token`` come from the request's _meta and
        map onto the fields ToolCheckRequest already exposes.

        ``route`` names the MCP server the call is bound for, so the central
        Shield can scope the kill switch to it. Sent as an extra body field: a
        deployment running an older data plane ignores the unknown key and keeps
        applying the fleet-wide kill switch, so the two can roll independently.
        """
        try:
            r = await self._client.post(
                f"{self.base_url}/v1/shield/tool/check",
                json={"agent_key": agent_key, "tool_name": name,
                      "tool_params": arguments or {}, "user_role": user_role or "",
                      "session_id": session_id or "",
                      "workflow": workflow or None,
                      "confirmation_token": confirmation_token or None,
                      "route": route or None},
                headers=self._headers(tenant_id=tenant_id, agent_key=agent_key, user_role=user_role),
            )
            r.raise_for_status()
            d = r.json()
        except Exception as e:
            return self._unavailable_decision(str(e))

        allowed = bool(d.get("allowed", True)) and d.get("action") != "block"
        return {
            "allowed": allowed,
            "action": d.get("action", "pass"),
            "mode": d.get("mode", "enforce"),
            "would_block": d.get("would_block", []),
            "risk": d.get("risk", "low"),
            "results": d.get("guardrail_results", []),
            "reason": _reason(d, "not permitted by policy") if not allowed else "",
        }

    async def sanitize_tool_result(
        self,
        name: str,
        raw: Any,
        *,
        agent_key: str,
        tenant_id: Optional[str],
        user_role: Optional[str],
    ) -> dict:
        """Map POST /v1/shield/tool/output to {blocked, sanitized_output}."""
        text = _as_text(raw)[:_MAX_OUTPUT_CHARS]
        try:
            r = await self._client.post(
                f"{self.base_url}/v1/shield/tool/output",
                json={"tool_name": name, "tool_output": text, "agent_key": agent_key},
                headers=self._headers(tenant_id=tenant_id, agent_key=agent_key, user_role=user_role),
            )
            r.raise_for_status()
            d = r.json()
        except Exception:
            # Fail-open returns the raw output; fail-closed blocks it.
            return {"blocked": not self.fail_open, "sanitized_output": raw if self.fail_open else None}

        if d.get("action") == "block":
            return {"blocked": True, "sanitized_output": None}
        return {"blocked": False, "sanitized_output": d.get("sanitized_output", text)}

    def filter_tools_for_role(
        self, tools: list[dict], *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]
    ) -> list[dict]:
        # tools/list filtering is cosmetic (call-time RBAC is authoritative). The
        # HTTP backend keeps the full list; the router layer may add registry-based
        # filtering later without weakening the call-time gate.
        return list(tools)

    def _unavailable_decision(self, err: str) -> dict:
        if self.fail_open:
            return {"allowed": True, "action": "pass", "mode": "enforce",
                    "would_block": [], "risk": "low", "results": [],
                    "reason": f"Shield unavailable (fail-open): {err}"}
        return {"allowed": False, "action": "block", "mode": "enforce",
                "would_block": [], "risk": "high", "results": [],
                "reason": f"Shield unavailable (fail-closed): {err}"}

    async def aclose(self) -> None:
        await self._client.aclose()
