"""MCP gateway server — the endpoint agents point at.

Speaks MCP JSON-RPC over HTTP at ``/gateway/{route}/mcp``. `tools/list` and
`tools/call` are routed through the enforced `MCPGatewayRouter` (RBAC -> input ->
forward -> output); protocol/handshake methods are answered locally. Identity is
resolved from the authenticated connection (never from tool arguments), reusing
``_resolve_identity``.

The heavy lifting (enforcement, upstream transport) lives in core/mcp/*; this file
is just the JSON-RPC bridge, unit-tested with a fake router.
"""

import hashlib
import os
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from api.routes_mcp_server import _resolve_identity, _resolve_session_id
from core.mcp.gateway import GatewayError
from core.mcp.gateway import router as gateway_router

router = APIRouter(prefix="/gateway", tags=["mcp-gateway-server"])

_PROTOCOL_VERSION = "2024-11-05"
# Notifications carry no id and expect no response body.
_NOTIFICATIONS = {"notifications/initialized", "notifications/cancelled"}


def _resources_enabled() -> bool:
    """resources/* + prompts/* passthrough (default on; off -> those return -32601)."""
    return os.getenv("SHIELD_GATEWAY_RESOURCES", "1").strip().lower() not in ("0", "false", "no")


def _ok(rpc_id: Any, result: dict) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _err(rpc_id: Any, code: int, message: str, data: Optional[dict] = None) -> JSONResponse:
    err: dict = {"code": code, "message": message}
    if data:
        err["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": err})


# JSON-RPC params._meta is the spec's reserved slot for protocol-level data. The
# confirmation token must NOT ride in `arguments`: those are forwarded verbatim
# to the upstream tool, so a token there would show up as a real parameter and
# would perturb any params-hash binding.
_META_CONFIRMATION = "shield/confirmation_token"
_META_WORKFLOW = "shield/workflow"

# Distinct from -32001 (unauthenticated) so a client can tell "supply a token"
# apart from "you are not allowed".
_RPC_CONFIRMATION_REQUIRED = -32002


def _meta(params: dict) -> dict:
    """params._meta, defensively: MCP clients may omit it or send a non-object."""
    meta = params.get("_meta")
    return meta if isinstance(meta, dict) else {}


# _meta values reach a Redis key lookup (confirmation_token) and a list
# comparison (workflow). Bound them so an unbounded caller-supplied string
# cannot grow keys on a Redis-backed state store.
_META_MAX_LEN = 256


def _meta_str(params: dict, key: str) -> Optional[str]:
    value = _meta(params).get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > _META_MAX_LEN:
        return None
    return value


def _confirmation_details(decision: dict) -> dict:
    """Describe a pending confirmation WITHOUT handing back the token.

    The caller here is the agent — the very party the confirmation gates. An
    earlier draft echoed the minted ``confirmation_token`` in this payload, which
    let the agent replay it and approve itself: a mandatory extra round trip
    rather than human-in-the-loop. The REST path models this correctly at
    ``api/routes_tool.py:475``: ``create_approval_request`` returns an opaque
    ``request_id`` and the credential goes to an approver out of band.

    So we return only a correlation handle. The token stays server-side in
    ``confirm:{session_id}:{token}`` until an approver channel delivers it;
    wiring that channel is the follow-up (see the spec's non-goals). Until then
    a sensitive tool over MCP fails closed, which is the correct direction for a
    security control that is not yet complete.
    """
    out: dict = {"action": "pending_confirmation"}
    for r in decision.get("results") or []:
        if r.get("action") == "pending_confirmation":
            d = r.get("details") or {}
            if d.get("expires_in") is not None:
                out["expires_in"] = d["expires_in"]
            # Correlation only: derived from the token, not the token itself,
            # and not accepted back as a credential.
            token = d.get("confirmation_token")
            if token:
                out["request_id"] = hashlib.sha256(
                    f"req:{token}".encode()).hexdigest()[:16]
            break
    return out


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
                session_id=_resolve_session_id(request),
                workflow=_meta_str(params, _META_WORKFLOW),
                confirmation_token=_meta_str(params, _META_CONFIRMATION),
            )
            # A call awaiting human confirmation is a distinct outcome from a
            # denial: surface it as an error carrying the token the client must
            # replay in _meta, rather than as an opaque isError result.
            decision = out.get("shield") or {}
            if decision.get("action") == "pending_confirmation":
                return _err(rpc_id, _RPC_CONFIRMATION_REQUIRED,
                            decision.get("reason") or "human confirmation required",
                            _confirmation_details(decision))
            # MCPProxy already returns an MCP-shaped result (content + isError).
            return _ok(rpc_id, {"content": out.get("content", []), "isError": out.get("isError", False)})

        # resources/* + prompts/* (opt-out via SHIELD_GATEWAY_RESOURCES=0).
        if _resources_enabled():
            if method == "resources/list":
                res = await gateway_router.list_resources(tenant_id, route, agent_key=agent_key, user_role=user_role)
                return _ok(rpc_id, {"resources": res})
            if method == "resources/templates/list":
                res = await gateway_router.list_resource_templates(tenant_id, route, agent_key=agent_key, user_role=user_role)
                return _ok(rpc_id, {"resourceTemplates": res})
            if method == "resources/read":
                uri = params.get("uri")
                if not uri:
                    return _err(rpc_id, -32602, "resources/read requires params.uri")
                out = await gateway_router.read_resource(tenant_id, route, uri, agent_key=agent_key, user_role=user_role)
                if out.get("blocked"):
                    return _err(rpc_id, -32000, out.get("reason", "resource blocked by Shield"))
                return _ok(rpc_id, {"contents": out.get("contents", [])})
            if method == "prompts/list":
                res = await gateway_router.list_prompts(tenant_id, route, agent_key=agent_key, user_role=user_role)
                return _ok(rpc_id, {"prompts": res})
            if method == "prompts/get":
                name = params.get("name")
                if not name:
                    return _err(rpc_id, -32602, "prompts/get requires params.name")
                out = await gateway_router.get_prompt(tenant_id, route, name, params.get("arguments") or {},
                                                      agent_key=agent_key, user_role=user_role)
                return _ok(rpc_id, out)

        return _err(rpc_id, -32601, f"method not supported by the Shield gateway: {method}")
    except GatewayError as e:
        # 404 (no route) -> -32004; server-side -> -32000.
        return _err(rpc_id, -32004 if e.status == 404 else -32000, e.message)
    except Exception as e:
        # Upstream that doesn't implement a method (or a transport/serialization
        # error) -> a clean JSON-RPC error, never a 500. Include the exception type
        # so the message is never blank.
        detail = f"{type(e).__name__}: {e}".rstrip(": ")
        return _err(rpc_id, -32603, f"error handling {method}: {detail}")


@router.post("/{route}/mcp")
async def gateway_mcp(route: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return _err(None, -32700, "parse error: body is not valid JSON")
    if not isinstance(body, dict):
        return _err(None, -32600, "invalid request: expected a JSON-RPC object")
    return await _dispatch(route, body, request)
