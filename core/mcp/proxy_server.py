"""MCP proxy orchestration — transport-agnostic.

``MCPProxy`` is the protocol-aware mediator: it sits between an MCP client and
one upstream MCP server and applies Shield on the two security-critical methods:

  - list_tools(): fetch upstream tools, (optionally) scan descriptions for
    poisoning, RBAC-filter to what the role may use, annotate risk.
  - call_tool():  enforce via the guard pipeline; on allow, forward upstream and
    sanitize the result; on block, return an MCP error instead of executing.

The upstream is injected (``UpstreamClient``) so this logic is fully unit-tested
with a fake upstream. The real transport adapter (mcp SDK stdio/SSE/HTTP) is
``connect_upstream`` below and is the only part that needs a live MCP server —
verify it against a real upstream, not in unit tests.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional, Protocol

from core.mcp.enforcement import (
    enforce_tool_call, sanitize_tool_result, filter_tools_for_role,
)


class UpstreamClient(Protocol):
    """Minimal surface the proxy needs from an upstream MCP server."""
    async def list_tools(self) -> list[dict]: ...
    async def call_tool(self, name: str, arguments: dict) -> Any: ...


# Optional sink for recording decisions to audit/SIEM. Kept injectable so the
# proxy logic has no hard dependency on the audit infra (and stays testable).
DecisionSink = Callable[[dict], Awaitable[None]]


class MCPProxy:
    def __init__(
        self,
        upstream: UpstreamClient,
        *,
        on_decision: Optional[DecisionSink] = None,
        scan_descriptions: bool = False,
    ):
        self._upstream = upstream
        self._on_decision = on_decision
        self._scan_descriptions = scan_descriptions

    async def list_tools(
        self, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]
    ) -> list[dict]:
        tools = await self._upstream.list_tools()
        if self._scan_descriptions:
            tools = await self._scan_for_poisoning(tools)
        return filter_tools_for_role(
            tools, agent_key=agent_key, user_role=user_role, tenant_id=tenant_id
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict,
        *,
        agent_key: str,
        user_role: Optional[str],
        tenant_id: Optional[str],
        tenant_config: Optional[dict] = None,
    ) -> dict:
        """Returns an MCP-style result dict:
        {content: [...], isError: bool, shield: <decision>}.
        """
        decision = await enforce_tool_call(
            name, arguments, agent_key=agent_key, user_role=user_role,
            tenant_id=tenant_id, tenant_config=tenant_config,
        )
        await self._record({"phase": "call", "tool": name, "agent_key": agent_key,
                            "tenant_id": tenant_id, **decision})

        if not decision["allowed"]:
            return _error(f"Blocked by Shield: {decision['reason']}", decision)

        raw = await self._upstream.call_tool(name, arguments)

        san = await sanitize_tool_result(
            name, raw, agent_key=agent_key, tenant_id=tenant_id, user_role=user_role
        )
        if san["blocked"]:
            return _error("Output blocked by Shield data policy", decision)

        return {
            "content": [{"type": "text", "text": _as_text(san["sanitized_output"])}],
            "isError": False,
            "shield": decision,
        }

    async def _scan_for_poisoning(self, tools: list[dict]) -> list[dict]:
        """Flag tools whose description looks like an injection/poisoning attempt.

        Reuses the adversarial-prompt guard on each tool description. Annotates
        (does not drop) so the operator decides — and it's surfaced in discovery.
        """
        try:
            from guardrails.input.adversarial_detection import AdversarialDetectionGuardrail
        except Exception:
            return tools
        guard = AdversarialDetectionGuardrail()
        out = []
        for t in tools:
            desc = t.get("description") or ""
            annotated = dict(t)
            if desc:
                try:
                    r = await guard.check(desc, {})
                    if not r.passed:
                        annotated["x-shield-poisoning"] = r.message
                except Exception:
                    pass
            out.append(annotated)
        return out

    async def _record(self, event: dict) -> None:
        if self._on_decision:
            try:
                await self._on_decision(event)
            except Exception:
                pass


def _error(message: str, decision: dict) -> dict:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
        "shield": decision,
    }


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    import json
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


# ─────────────────────────────────────────────────────────────────────
# Live transport adapter — REQUIRES a running upstream MCP server.
# Not exercised by unit tests; verify against a real server (e.g. on RunPod).
# Pin the `mcp` SDK version to match mcp/votal_shield_server.py.
# ─────────────────────────────────────────────────────────────────────

async def connect_upstream(config: dict) -> "UpstreamClient":  # pragma: no cover
    """Build an UpstreamClient from a server config.

    config = {"transport": "stdio"|"sse"|"http", "command"/"url": ..., ...}

    Implementation note: wrap an mcp.client ClientSession so list_tools() and
    call_tool() proxy to the upstream. Kept as an explicit integration seam —
    implement against the pinned mcp client API and test live.
    """
    raise NotImplementedError(
        "connect_upstream: implement with the mcp client SDK against a live "
        "upstream server, then validate end-to-end. The MCPProxy logic above "
        "is transport-agnostic and already unit-tested with a fake upstream."
    )
