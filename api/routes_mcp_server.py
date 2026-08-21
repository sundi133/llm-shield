"""MCP Server endpoint — exposes Shield guardrails via Model Context Protocol.

Implements MCP over SSE so any MCP-compatible client (Claude Desktop,
Cursor, Windsurf, Claude Code) can connect directly with just a URL.

This router runs on the DATA PLANE (core/app.py), where the guardrail
models live — the tool handlers call classify()/the guardrails in-process,
so it must not be mounted on the control/admin plane, which has no models
and only proxies. Point MCP clients at the data-plane base URL (set
SHIELD_PUBLIC_BASE_URL so the initialize handshake advertises it).

No SDK required on client side — just add to MCP config:
  {
    "mcpServers": {
      "votal-shield": {
        "url": "https://<your-data-plane-host>/mcp/sse",
        "headers": {
          "X-API-Key": "your-tenant-api-key",
          "Authorization": "Bearer <data-plane-proxy-token>"
        }
      }
    }
  }
"""

import json
import os
import re
import uuid
import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

router = APIRouter(prefix="/mcp", tags=["mcp-server"])


def _public_base_url(request: Request) -> str:
    """Resolve the externally-visible base URL.

    request.base_url reflects the host the app binds to, which behind a
    proxy (RunPod / Railway) is an internal IP:port. Advertising that in
    the MCP `initialize` metadata leaks internal infra, so prefer an
    explicit SHIELD_PUBLIC_BASE_URL, then standard proxy forwarding
    headers, and only fall back to request.base_url as a last resort.
    """
    configured = os.environ.get("SHIELD_PUBLIC_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    fwd_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    if fwd_host:
        proto = request.headers.get("x-forwarded-proto", "https").split(",")[0].strip() or "https"
        return f"{proto}://{fwd_host}".rstrip("/")
    return str(request.base_url).rstrip("/")

# MCP tool definitions
MCP_TOOLS = [
    {
        "name": "shield_check_input",
        "description": (
            "Check a user message against input guardrails "
            "(adversarial detection, toxicity, PII). "
            "Call BEFORE processing any user input."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "User message to check"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "shield_check_output",
        "description": (
            "Check LLM response against output guardrails "
            "(PII leakage, bias, tone). "
            "Call BEFORE returning a response to the user."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {"type": "string", "description": "LLM response to check"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "shield_check_tool",
        "description": (
            "Check if a tool call is authorized (RBAC + kill switch). "
            "Call BEFORE executing any tool: file_write, shell_execute, "
            "database_query, api_call, etc."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool name to check"},
                "arguments": {"type": "object", "description": "Tool arguments", "default": {}},
                "user_role": {"type": "string", "description": "User role", "default": "developer"},
            },
            "required": ["tool_name"],
        },
    },
    {
        "name": "shield_sanitize_output",
        "description": (
            "Sanitize tool output — redact PII, enforce data policies. "
            "Call AFTER tool execution, before using its output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool that produced the output"},
                "output": {"type": "string", "description": "Tool output to sanitize"},
            },
            "required": ["tool_name", "output"],
        },
    },
    {
        "name": "shield_disable_tool",
        "description": "Emergency kill switch — disable a tool globally.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool to disable"},
                "reason": {"type": "string", "description": "Why", "default": "Disabled via MCP"},
            },
            "required": ["tool_name"],
        },
    },
    {
        "name": "shield_enable_tool",
        "description": "Re-enable a previously disabled tool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool to re-enable"},
            },
            "required": ["tool_name"],
        },
    },
]


def _oauth_claims(authorization: str) -> dict | None:
    """Validate a Shield-issued OAuth access token from an Authorization header.

    Returns the claims if the bearer is a valid Shield OAuth access token,
    else None. Safe and additive: a non-Shield bearer (e.g. the RunPod proxy
    token) simply fails verification and yields None, so X-API-Key auth is
    unaffected.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:].strip()
    try:
        from core.jwt_utils import is_jwt_format, decode_jwt
        if not token or not is_jwt_format(token):
            return None
        from core.agent_tokens import get_signer
        claims = decode_jwt(token, get_signer(), audience="shield-oauth")
        if claims.get("token_type") != "access_token":
            return None
        return claims
    except Exception:
        return None


def _bearer_token(authorization: str) -> str:
    """The token from an `Authorization: Bearer <token>` header, else ""."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return ""
    return authorization[7:].strip()


def _resolve_identity(request: Request) -> tuple[str, str, str]:
    """Resolve (tenant_id, agent_key, user_role) for an MCP request.

    Order, each field independently: request.state (set by middleware) ->
    explicit identity headers (X-Agent-Key / X-User-Role) -> tenant via
    X-API-Key -> a Shield OAuth Bearer access token (tenant_id + developer
    sub). Falls back to "mcp-agent" only when no identity is supplied, so
    existing X-API-Key-only callers keep working unchanged.
    """
    tenant_id = agent_key = user_role = ""
    st = getattr(request, "state", None)
    if st is not None:
        tenant_id = getattr(st, "tenant_id", "") or ""
        agent_key = getattr(st, "agent_key", "") or ""
        user_role = getattr(st, "user_role", "") or ""

    h = getattr(request, "headers", None)
    if h is None:
        return tenant_id, (agent_key or "mcp-agent"), user_role
    agent_key = agent_key or h.get("x-agent-key", "").strip()
    user_role = user_role or h.get("x-user-role", "").strip()

    if not tenant_id:
        api_key = h.get("x-api-key", "").strip()
        if api_key:
            try:
                from storage.tenant_store import resolve_tenant_by_api_key
                tenant_id = resolve_tenant_by_api_key(api_key) or ""
            except Exception:
                pass

    if not tenant_id or not agent_key:
        claims = _oauth_claims(h.get("authorization", ""))
        if claims:
            tenant_id = tenant_id or (claims.get("tenant_id") or "")
            sub = claims.get("sub") or ""
            if not agent_key and sub:
                agent_key = f"oauth:{sub}"  # per-developer identity from token subject

    # A tenant API key presented as a bearer token. MCP clients send their
    # credential in Authorization per the MCP authorization spec, and only a
    # Shield-issued JWT resolved above — so a partner pasting a tenant key into
    # an MCP client got no tenant, and (because the gateway answered HTTP 200)
    # saw an empty server rather than an auth error.
    #
    # Not a widening: the same credential with the same authority, read from a
    # second header. Ordering matters — a real JWT resolves via its claims
    # above, and a JWT-shaped bearer is never probed as an API key, so a
    # malformed or expired token fails as a token instead of being retried as
    # something it is not. Spec: docs/spec-mcp-gateway-bearer-auth.md
    if not tenant_id:
        bearer = _bearer_token(h.get("authorization", ""))
        if bearer:
            try:
                from core.jwt_utils import is_jwt_format
                looks_like_jwt = is_jwt_format(bearer)
            except Exception:
                looks_like_jwt = False
            if not looks_like_jwt:
                try:
                    from storage.tenant_store import resolve_tenant_by_api_key
                    tenant_id = resolve_tenant_by_api_key(bearer) or ""
                except Exception:
                    # Fail closed: a store outage must not admit an
                    # unauthenticated caller to a guarded route.
                    tenant_id = ""

    return tenant_id, (agent_key or "mcp-agent"), user_role


# A session_id namespaces Redis keys built as f"confirm:{session_id}:{token}"
# and f"...:sess:{session_id}:...". A ':' in the value makes those ambiguous
# (session "a" + token "b:X" addresses the same key as session "a:b" + token
# "X"), so constrain the charset rather than trusting the minter.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# Every mTLS caller is stamped with this same literal by AgentIdentityMiddleware.
# It is an identity method, not a session: honouring it would put every mTLS
# agent in every tenant into ONE confirmation namespace and ONE per-session
# rate-limit bucket.
_NON_SESSION_VALUES = {"mtls"}


def _resolve_session_id(request: Request) -> str:
    """Resolve the caller's session from its *verified* identity, or "".

    Deliberately reads only ``request.state.identity`` (populated by
    AgentIdentityMiddleware from a signature-verified X-Agent-Token, or by the
    mTLS path). It must NOT fall back to a request header.

    "Verified" here means *signed*, not *authorized*: ``POST /auth/agent-token``
    accepts ``session_id`` verbatim from the request body, so a tenant-key
    holder can choose the value. The charset check below is what keeps a chosen
    value from being a key-injection primitive; it does not make the value
    trustworthy. Treat per-session rate limits as a cooperative control, not a
    boundary against a malicious tenant-key holder.

    Returns "" when no usable session is present — callers treat that as
    "session-scoped guards unavailable", never as a wildcard.
    """
    identity = getattr(getattr(request, "state", None), "identity", None)
    session_id = (getattr(identity, "session_id", "") or "").strip()
    if session_id in _NON_SESSION_VALUES or not _SESSION_ID_RE.match(session_id):
        return ""
    return session_id


def _get_tenant_info(request: Request) -> tuple[str, str]:
    """Back-compat shim: (tenant_id, agent_key). Prefer _resolve_identity."""
    tenant_id, agent_key, _ = _resolve_identity(request)
    return tenant_id, agent_key


def _populate_request_state(request: Request, tenant_id: str, agent_key: str, user_role: str) -> None:
    """Give delegated REST handlers the same tenant context the middleware sets
    on a direct call. /mcp/* bypasses the tenant middleware, so without this the
    classify/tool handlers run with NO tenant_config and default config — which
    is the root of the MCP-vs-REST parity gaps (tenant guardrails + data
    policies never applied)."""
    st = request.state
    if tenant_id:
        if not getattr(st, "tenant_id", None):
            st.tenant_id = tenant_id
        if not getattr(st, "tenant_config", None):
            try:
                from storage.tenant_store import get_tenant
                st.tenant_config = get_tenant(tenant_id)
            except Exception:
                pass
    if agent_key and not getattr(st, "agent_key", None):
        st.agent_key = agent_key
    if user_role and not getattr(st, "user_role", None):
        st.user_role = user_role


def _is_blocked(result: dict) -> bool:
    """A guardrail result is a block if it says so by any signal the direct
    REST responses use: safe=False, action=block, or a failing blocking
    guardrail. (Matches /guardrails/* semantics; avoids defaulting to safe.)"""
    if result.get("safe") is False:
        return True
    if result.get("action") == "block":
        return True
    return any(
        (not g.get("passed", True)) and g.get("action") == "block"
        for g in (result.get("guardrail_results") or [])
    )


async def _handle_tool_call(name: str, arguments: dict, request: Request) -> str:
    """Execute an MCP tool call against Shield endpoints internally.

    Delegates to the SAME handler functions the REST endpoints use, with tenant
    context populated on request.state, so MCP and direct REST stay at parity.
    """
    tenant_id, agent_key, user_role = _resolve_identity(request)
    _populate_request_state(request, tenant_id, agent_key, user_role)

    if name == "shield_check_input":
        try:
            from api.routes_classify import classify
            result = await classify(request, {"message": arguments["message"]})
        except Exception as e:
            return f"ERROR — input check failed: {e}"
        if not _is_blocked(result):
            return "SAFE — all guardrails passed. Proceed with processing."
        triggered = [g for g in result.get("guardrail_results", []) if not g.get("passed", True)]
        names = [g.get("guardrail", "?") for g in triggered]
        reasons = [g.get("message", "") for g in triggered]
        return f"BLOCKED — triggered: {', '.join(names)}. Reasons: {'; '.join(reasons)}. Do NOT proceed."

    elif name == "shield_check_output":
        try:
            from api.routes_classify_output import classify_output
            result = await classify_output(request, {"output": arguments["output"]})
        except Exception as e:
            return f"ERROR — output check failed: {e}"
        sanitized = result.get("sanitized_output")
        if _is_blocked(result):
            return "BLOCKED — output violates guardrails. Do NOT return this to the user."
        if sanitized and sanitized != arguments["output"]:
            return f"SAFE (sanitized) — use this version:\n\n{sanitized}"
        return "SAFE — output passed all guardrails."

    elif name == "shield_check_tool":
        # Parity: delegate to the SAME full pipeline as /v1/shield/tool/check
        # (RBAC + data-access + tool-call validation + kill switch + ...),
        # not just the allowlist.
        try:
            from api.routes_tool import check_tool, ToolCheckRequest
            body = ToolCheckRequest(
                agent_key=agent_key or "mcp-agent",
                tool_name=arguments["tool_name"],
                user_role=arguments.get("user_role") or user_role or None,
                tool_params=arguments.get("arguments") or {},
            )
            result = await check_tool(body, request)
        except Exception as e:
            return f"ERROR — tool check failed: {e}"
        tname = arguments["tool_name"]
        if not result.get("allowed", True):
            triggered = [g for g in result.get("guardrail_results", []) if not g.get("passed", True)]
            reasons = "; ".join(g.get("message", "") for g in triggered) or "policy violation"
            return f"BLOCKED — tool '{tname}': {reasons}. Do NOT execute."
        return f"ALLOWED — tool '{tname}' is authorized. Proceed."

    elif name == "shield_sanitize_output":
        # Parity: delegate to the SAME tool-output DLP as /v1/shield/tool/output
        # (ToolOutputSanitizationGuardrail), not generic output classification.
        try:
            from api.routes_tool import check_tool_output, ToolOutputRequest
            body = ToolOutputRequest(
                tool_name=arguments["tool_name"],
                tool_output=arguments["output"],
                agent_key=agent_key or None,
            )
            result = await check_tool_output(body, request)
        except Exception as e:
            return f"ERROR — output sanitization failed: {e}"
        if not result.get("allowed", True):
            return "BLOCKED — tool output violates data policy. Do NOT use."
        sanitized = result.get("sanitized_output")
        if sanitized is not None and sanitized != arguments["output"]:
            return f"SANITIZED — use this version:\n\n{sanitized}"
        return "CLEAN — no sanitization needed."

    elif name == "shield_disable_tool":
        try:
            from storage.tool_killswitch import disable_tool
            tool_name = arguments["tool_name"]
            reason = arguments.get("reason", "Disabled via MCP")
            disable_tool(tenant_id, tool_name, reason=reason, actor=agent_key or "mcp-client")
            return f"Tool '{tool_name}' has been DISABLED globally."
        except Exception as e:
            return f"ERROR — disable failed: {e}"

    elif name == "shield_enable_tool":
        try:
            from storage.tool_killswitch import enable_tool
            enable_tool(tenant_id, arguments["tool_name"])
            return f"Tool '{arguments['tool_name']}' has been RE-ENABLED."
        except Exception as e:
            return f"ERROR — enable failed: {e}"

    return f"Unknown tool: {name}"


# ── Streamable HTTP transport (MCP 2025-03-26 spec) ──────────────────────

@router.post("/message")
async def mcp_message(request: Request):
    """Handle MCP JSON-RPC messages over HTTP POST.

    This is the Streamable HTTP transport — the recommended MCP transport.
    Client sends JSON-RPC request, server responds with JSON-RPC response.
    """
    body = await request.json()
    method = body.get("method", "")
    msg_id = body.get("id")
    params = body.get("params", {})

    if method == "initialize":
        base_url = _public_base_url(request)
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "votal-shield",
                    "version": "1.0.0",
                    "authorization": {
                        "type": "oauth2",
                        "metadata_url": f"{base_url}/.well-known/oauth-authorization-server",
                    },
                },
            },
        })

    elif method == "notifications/initialized":
        return JSONResponse(content={"jsonrpc": "2.0", "id": msg_id, "result": {}})

    elif method == "tools/list":
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        })

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result_text = await _handle_tool_call(tool_name, arguments, request)
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": result_text}],
            },
        })

    else:
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        })


# ── SSE transport (legacy, for clients that don't support Streamable HTTP) ──

_sse_sessions: dict[str, asyncio.Queue] = {}


@router.get("/sse")
async def mcp_sse(request: Request):
    """SSE endpoint — client connects here, receives a session endpoint URL."""
    session_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    _sse_sessions[session_id] = queue

    # Build the message endpoint URL for this session
    base = str(request.base_url).rstrip("/")
    message_url = f"{base}/mcp/sse/{session_id}/message"

    async def event_stream():
        # First event: tell client where to POST messages
        yield f"event: endpoint\ndata: {message_url}\n\n"
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"event: message\ndata: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _sse_sessions.pop(session_id, None)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/sse/{session_id}/message")
async def mcp_sse_message(session_id: str, request: Request):
    """Receive JSON-RPC message from SSE client, push response to SSE stream."""
    queue = _sse_sessions.get(session_id)
    if not queue:
        return JSONResponse(status_code=404, content={"error": "Session not found"})

    body = await request.json()
    method = body.get("method", "")
    msg_id = body.get("id")
    params = body.get("params", {})

    if method == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "votal-shield", "version": "1.0.0"},
            },
        }
    elif method == "notifications/initialized":
        response = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    elif method == "tools/list":
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        }
    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result_text = await _handle_tool_call(tool_name, arguments, request)
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": result_text}],
            },
        }
    else:
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    await queue.put(response)
    return JSONResponse(content={"ok": True})
