"""MCP Server endpoint — exposes Shield guardrails via Model Context Protocol.

Implements MCP over SSE so any MCP-compatible client (Claude Desktop,
Cursor, Windsurf, Claude Code) can connect directly with just a URL.

No SDK required on client side — just add to MCP config:
  {
    "mcpServers": {
      "votal-shield": {
        "url": "https://shield.votal.ai/mcp/sse",
        "headers": { "X-API-Key": "your-tenant-api-key" }
      }
    }
  }
"""

import json
import uuid
import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

router = APIRouter(prefix="/mcp", tags=["mcp-server"])

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


def _get_tenant_info(request: Request) -> tuple[str, str]:
    """Extract tenant_id and agent_key from request state."""
    tenant_id = ""
    agent_key = "mcp-agent"
    if hasattr(request, "state"):
        tenant_id = getattr(request.state, "tenant_id", "") or ""
        agent_key = getattr(request.state, "agent_key", "mcp-agent") or "mcp-agent"
    return tenant_id, agent_key


async def _handle_tool_call(name: str, arguments: dict, request: Request) -> str:
    """Execute an MCP tool call against Shield endpoints internally."""
    tenant_id, agent_key = _get_tenant_info(request)

    if name == "shield_check_input":
        try:
            from api.routes_classify import classify
            body = {"message": arguments["message"]}
            result = await classify(request, body)
        except Exception as e:
            return f"ERROR — input check failed: {e}"
        safe = result.get("safe", True)
        if safe:
            return "SAFE — all guardrails passed. Proceed with processing."
        triggered = [g for g in result.get("guardrail_results", []) if not g.get("passed")]
        names = [g.get("guardrail", "?") for g in triggered]
        reasons = [g.get("message", "") for g in triggered]
        return f"BLOCKED — triggered: {', '.join(names)}. Reasons: {'; '.join(reasons)}. Do NOT proceed."

    elif name == "shield_check_output":
        try:
            from api.routes_classify_output import classify_output
            body = {"output": arguments["output"]}
            result = await classify_output(request, body)
        except Exception as e:
            return f"ERROR — output check failed: {e}"
        safe = result.get("safe", True)
        sanitized = result.get("sanitized_output")
        if safe:
            if sanitized and sanitized != arguments["output"]:
                return f"SAFE (sanitized) — use this version:\n\n{sanitized}"
            return "SAFE — output passed all guardrails."
        return "BLOCKED — output violates guardrails. Do NOT return this to the user."

    elif name == "shield_check_tool":
        try:
            from storage.tool_killswitch import is_tool_disabled
            from core.feature_flags import KILLSWITCH_ENABLED

            tool_name = arguments["tool_name"]

            if KILLSWITCH_ENABLED and tenant_id and is_tool_disabled(tenant_id, tool_name):
                return f"BLOCKED — tool '{tool_name}' is disabled via kill switch. Do NOT execute."

            from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
            guard = ToolAllowlistGuardrail()
            context = {
                "tool_name": tool_name,
                "agent_key": agent_key,
                "user_role": arguments.get("user_role", "developer"),
                "tenant_id": tenant_id,
            }
            result = await guard.check("", context)

            # Record so MCP-driven tool checks show in the Guardrail Metrics /
            # Board Report tabs (same store as /v1/shield/tool/check). Resolve the
            # tenant from the API key if middleware didn't set it. Fire-and-forget.
            try:
                rec_tenant = tenant_id
                if not rec_tenant:
                    from storage.tenant_store import resolve_tenant_by_api_key
                    rec_tenant = resolve_tenant_by_api_key(
                        request.headers.get("X-API-Key", "").strip())
                if rec_tenant:
                    from storage.guardrail_metrics import record_results_batch
                    record_results_batch(rec_tenant, [{
                        "guardrail": result.guardrail_name,
                        "passed": result.passed,
                        "action": result.action,
                        "latency_ms": getattr(result, "latency_ms", 0.0) or 0.0,
                    }])
            except Exception:
                pass

            if not result.passed and result.action == "block":
                return f"BLOCKED — tool '{tool_name}': {result.message}. Do NOT execute."
            return f"ALLOWED — tool '{tool_name}' is authorized. Proceed."
        except Exception as e:
            return f"ERROR — tool check failed: {e}"

    elif name == "shield_sanitize_output":
        try:
            from api.routes_classify_output import classify_output
            body = {"output": arguments["output"], "tool_name": arguments["tool_name"]}
            result = await classify_output(request, body)
            sanitized = result.get("sanitized_output", arguments["output"])
            if not result.get("safe", True):
                return "BLOCKED — tool output violates data policy. Do NOT use."
            if sanitized != arguments["output"]:
                return f"SANITIZED — use this version:\n\n{sanitized}"
            return "CLEAN — no sanitization needed."
        except Exception as e:
            return f"ERROR — output sanitization failed: {e}"

    elif name == "shield_disable_tool":
        try:
            from storage.tool_killswitch import disable_tool
            tool_name = arguments["tool_name"]
            reason = arguments.get("reason", "Disabled via MCP")
            disable_tool(tenant_id, tool_name, reason=reason, actor="mcp-client")
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
        base_url = str(request.base_url).rstrip("/")
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
