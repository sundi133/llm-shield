"""MCP gateway server — the endpoint agents point at.

Speaks MCP JSON-RPC over HTTP at ``/gateway/{route}/mcp``. `tools/list` and
`tools/call` are routed through the enforced `MCPGatewayRouter` (RBAC -> input ->
forward -> output); protocol/handshake methods are answered locally. Identity is
resolved from the authenticated connection (never from tool arguments), reusing
``_resolve_identity``.

The heavy lifting (enforcement, upstream transport) lives in core/mcp/*; this file
is just the JSON-RPC bridge, unit-tested with a fake router.
"""

from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from api.routes_mcp_server import _resolve_identity
from core.mcp.gateway import GatewayError
from core.mcp.gateway import router as gateway_router

router = APIRouter(prefix="/gateway", tags=["mcp-gateway-server"])

_PROTOCOL_VERSION = "2024-11-05"
# Notifications carry no id and expect no response body.
_NOTIFICATIONS = {"notifications/initialized", "notifications/cancelled"}


def _ok(rpc_id: Any, result: dict) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _err(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})


async def _dispatch(route: str, body: dict, request: Request):
    method = body.get("method")
    params = body.get("params") or {}
    rpc_id = body.get("id")

    if method in _NOTIFICATIONS:
        return Response(status_code=204)

    tenant_id, agent_key, user_role = _resolve_identity(request)
    if not tenant_id:
        return _err(rpc_id, -32001, "unauthenticated: no tenant resolved from the connection")

    if method == "initialize":
        return _ok(rpc_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "shield-mcp-gateway", "version": "1.0.0"},
        })

    try:
        if method == "tools/list":
            tools = await gateway_router.list_tools(
                tenant_id, route, agent_key=agent_key, user_role=user_role,
            )
            return _ok(rpc_id, {"tools": tools})

        if method == "tools/call":
            name = params.get("name")
            if not name:
                return _err(rpc_id, -32602, "tools/call requires params.name")
            out = await gateway_router.call_tool(
                tenant_id, route, name, params.get("arguments") or {},
                agent_key=agent_key, user_role=user_role,
            )
            # MCPProxy already returns an MCP-shaped result (content + isError).
            return _ok(rpc_id, {"content": out.get("content", []), "isError": out.get("isError", False)})

        return _err(rpc_id, -32601, f"method not supported by the Shield gateway: {method}")
    except GatewayError as e:
        # 404 (no route) -> -32004; server-side -> -32000.
        return _err(rpc_id, -32004 if e.status == 404 else -32000, e.message)


@router.post("/{route}/mcp")
async def gateway_mcp(route: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return _err(None, -32700, "parse error: body is not valid JSON")
    if not isinstance(body, dict):
        return _err(None, -32600, "invalid request: expected a JSON-RPC object")
    return await _dispatch(route, body, request)
