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

# Default enforcement backend: the in-process guard pipeline. Kept as a module
# reference so MCPProxy(enforcer=None) is byte-identical to the historical
# behavior. An alternate backend (e.g. core.mcp.http_enforcer.HTTPEnforcer, which
# calls Shield's guard endpoints over HTTP) can be injected without changing this
# file — both run the SAME checks, so the two enforcement paths can't drift.
from core.mcp import enforcement as _inprocess_enforcement
from core.mcp.enforcement import (
    description_scan_for,
    drop_flagged_tools,
    filter_tools_by_floor,
    tool_floor_decision,
)


class UpstreamClient(Protocol):
    """Minimal surface the proxy needs from an upstream MCP server."""
    async def list_tools(self) -> list[dict]: ...
    async def call_tool(self, name: str, arguments: dict) -> Any: ...


class Enforcer(Protocol):
    """Pluggable Shield enforcement backend.

    The in-process ``core.mcp.enforcement`` module satisfies this structurally
    (it exposes these three names at module level), and so does any object with
    the same surface — e.g. an HTTP backend for a thin-edge gateway.
    """
    async def enforce_tool_call(
        self, name: str, arguments: dict, *, agent_key: str, user_role: Optional[str],
        tenant_id: Optional[str], tenant_config: Optional[dict],
        session_id: Optional[str] = None, workflow: Optional[str] = None,
        confirmation_token: Optional[str] = None, route: Optional[str] = None,
        policy: Optional[dict] = None,
    ) -> dict: ...
    async def sanitize_tool_result(
        self, name: str, raw: Any, *, agent_key: str, tenant_id: Optional[str],
        user_role: Optional[str], policy: Optional[dict] = None,
    ) -> dict: ...
    def filter_tools_for_role(
        self, tools: list[dict], *, agent_key: str, user_role: Optional[str],
        tenant_id: Optional[str],
    ) -> list[dict]: ...


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
        enforcer: Optional[Enforcer] = None,
        policy: Optional[dict] = None,
        route: Optional[str] = None,
    ):
        self._upstream = upstream
        # Which MCP server this proxy fronts. Scopes the kill switch so one
        # compromised server can be isolated without disabling that tool name
        # everywhere. Fixed for the life of the proxy — the pool is keyed on it.
        self._route = route
        self._on_decision = on_decision
        self._scan_descriptions = scan_descriptions
        # Server-scoped policy floor, resolved on write and denormalized onto the
        # route config. Applied HERE rather than inside the enforcer on purpose:
        # the floor is deterministic and identity-independent, so running it at
        # the proxy layer makes it apply to every enforcement backend — including
        # the HTTP one — without changing that backend's wire format.
        self._policy = policy or None
        # None -> in-process pipeline (unchanged default). Inject to relocate
        # enforcement (e.g. HTTP to a central Shield) without touching this class.
        self._enforcer: Enforcer = enforcer or _inprocess_enforcement

    def set_policy(self, policy: Optional[dict]) -> None:
        """Refresh the server-scoped floor on an already-constructed proxy.

        stdio upstreams are pooled across requests, so a policy baked in at
        construction would keep enforcing a superseded revision until the pool
        cycled. The gateway re-reads route config on every call and pushes it
        here, preserving the property that config is always re-read even though
        the connection is not.
        """
        self._policy = policy or None

    async def list_tools(
        self, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]
    ) -> list[dict]:
        tools = await self._upstream.list_tools()
        # Policy overrides the route's static scan_descriptions flag, so a
        # profile can turn description scanning on for every untrusted server at
        # once instead of route by route.
        scan_cfg = description_scan_for(self._policy)
        if scan_cfg["enabled"] if scan_cfg else self._scan_descriptions:
            tools = await self._scan_for_poisoning(tools)
            if scan_cfg and scan_cfg["hide_flagged"]:
                tools = drop_flagged_tools(tools)
        # Floor first: a tool this server may never expose should not be
        # advertised to anyone, whatever role the caller claims.
        tools = filter_tools_by_floor(tools, self._policy)
        return self._enforcer.filter_tools_for_role(
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
        session_id: Optional[str] = None,
        workflow: Optional[str] = None,
        confirmation_token: Optional[str] = None,
    ) -> dict:
        """Returns an MCP-style result dict:
        {content: [...], isError: bool, shield: <decision>}.

        ``session_id`` is forwarded to the enforcer to scope confirmation tokens
        and per-session rate limits; it must originate from a verified claim.
        ``workflow`` / ``confirmation_token`` come from the request's _meta.
        """
        # The server-scoped floor runs before the guard chain and before any
        # upstream connection: a barred tool must not reach the vendor at all,
        # and the decision needs no LLM call to make.
        barred = tool_floor_decision(self._policy, name)
        if barred is not None:
            decision = {
                "allowed": False, "action": "block", "mode": "enforce",
                "would_block": ["mcp_tool_floor"], "risk": "low", "reason": barred,
                "results": [{
                    "guardrail": "mcp_tool_floor", "passed": False, "action": "block",
                    "message": barred,
                    # Administrative, like the kill switch: an operator who barred
                    # a tool on this server expects it barred, and monitor mode is
                    # a dry-run for detection heuristics, not for that decision.
                    "details": {"administrative": True, "tool_name": name},
                }],
            }
            await self._record({"phase": "call", "tool": name, "agent_key": agent_key,
                                "tenant_id": tenant_id, **decision})
            return _error(f"Blocked by Shield: {barred}", decision)

        decision = await self._enforcer.enforce_tool_call(
            name, arguments, agent_key=agent_key, user_role=user_role,
            tenant_id=tenant_id, tenant_config=tenant_config,
            session_id=session_id, workflow=workflow,
            confirmation_token=confirmation_token, route=self._route,
            policy=self._policy,
        )
        await self._record({"phase": "call", "tool": name, "agent_key": agent_key,
                            "tenant_id": tenant_id, **decision})

        if not decision["allowed"]:
            return _error(f"Blocked by Shield: {decision['reason']}", decision)

        # Materialize any vault secret references in the arguments, bound to this
        # tool (destination = tool name). No-op unless the vault is enabled.
        arguments = _materialize_mcp_args(tenant_id, name, arguments)

        raw = await self._upstream.call_tool(name, arguments)

        # Re-tokenize any secret the upstream echoed back before it reaches the model.
        raw = _retokenize_mcp(tenant_id, raw)

        san = await self._enforcer.sanitize_tool_result(
            name, raw, agent_key=agent_key, tenant_id=tenant_id, user_role=user_role,
            policy=self._policy,
        )
        if san["blocked"]:
            return _error("Output blocked by Shield data policy", decision)

        return {
            "content": [{"type": "text", "text": _as_text(san["sanitized_output"])}],
            "isError": False,
            "shield": decision,
        }

    # ── resources ────────────────────────────────────────────────────

    async def list_resources(self, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]) -> list[dict]:
        """Passthrough (v1): forward the upstream's resource list. Room for a
        per-route allowlist filter later; the gateway never blocks a listing it
        has no policy for."""
        return await self._upstream.list_resources()

    async def list_resource_templates(self, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]) -> list[dict]:
        return await self._upstream.list_resource_templates()

    async def read_resource(self, uri: str, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]) -> dict:
        """Fetch a resource and DLP-sanitize its content (it can carry PII/secrets,
        same as a tool result). Returns {contents, blocked, reason}."""
        raw = await self._upstream.read_resource(uri)
        contents = raw.get("contents", []) if isinstance(raw, dict) else (raw or [])
        out: list[dict] = []
        for block in contents:
            text = block.get("text") if isinstance(block, dict) else None
            if text is not None:
                # Resource content gets the same DLP posture as a tool result:
                # it can carry the same PII, and an untrusted server should not
                # get a softer floor just because the bytes arrived via
                # resources/read.
                san = await self._enforcer.sanitize_tool_result(
                    uri, text, agent_key=agent_key, tenant_id=tenant_id,
                    user_role=user_role, policy=self._policy)
                if san["blocked"]:
                    return {"blocked": True,
                            "reason": "Resource content blocked by Shield data policy",
                            "contents": []}
                block = {**block, "text": _as_text(san["sanitized_output"])}
            out.append(block)
        return {"blocked": False, "contents": out}

    # ── prompts ──────────────────────────────────────────────────────

    async def list_prompts(self, *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]) -> list[dict]:
        return await self._upstream.list_prompts()

    async def get_prompt(self, name: str, arguments: Optional[dict], *, agent_key: str, user_role: Optional[str], tenant_id: Optional[str]) -> dict:
        """Passthrough (v1). Injection-screening of the returned prompt is a
        flagged follow-up."""
        return await self._upstream.get_prompt(name, arguments or {})

    async def _scan_for_poisoning(self, tools: list[dict]) -> list[dict]:
        """Flag tools whose description looks like an injection/poisoning attempt.

        Reuses the adversarial-prompt guard on each tool description. Annotates
        (does not drop) so the operator decides — and it's surfaced in discovery.
        """
        try:
            # The guardrail's registered `name` is "adversarial_detection", but the
            # module is `adversarial` and the class is `AdversarialGuardrail`. Using
            # the name as an import path (as this once did) raised ImportError that
            # the except-clause swallowed, silently no-op'ing the whole scan.
            from guardrails.input.adversarial import AdversarialGuardrail
        except Exception:
            return tools
        guard = AdversarialGuardrail()
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


def _materialize_mcp_args(tenant_id: Optional[str], name: str, arguments: dict) -> dict:
    """Substitute vault secret references in MCP tool arguments, bound to this tool.

    Destination and tool scope are both the tool ``name``. Safe on any error: the
    inert placeholder is forwarded rather than a real value (no leak)."""
    try:
        from core.secret_vault import materialize_obj
        return materialize_obj(tenant_id, arguments, name, tool_id=name)
    except Exception:  # e.g. key backend unavailable — forward inert, never leak
        return arguments


def _retokenize_mcp(tenant_id: Optional[str], raw: Any) -> Any:
    """Scrub any echoed secret value from an MCP result before the model sees it."""
    try:
        from core.secret_vault import retokenize
        return retokenize(tenant_id, raw)
    except Exception:
        return raw


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
# Live transport adapter (core/mcp/upstream.py). Connects to a real upstream
# MCP server via the official `mcp` client SDK. The adapter's normalization
# logic is unit-tested with a fake session; full transport is verified against
# a live server.
# ─────────────────────────────────────────────────────────────────────

from core.mcp.upstream import connect_upstream, MCPUpstream  # noqa: E402,F401


async def proxy_for(config: dict, **proxy_kwargs) -> "MCPProxy":
    """Convenience: connect to an upstream and wrap it in an MCPProxy.

    Caller is responsible for ``await proxy._upstream.aclose()`` on shutdown.
    """
    upstream = await connect_upstream(config)
    return MCPProxy(upstream, **proxy_kwargs)
