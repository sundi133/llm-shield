"""MCP server management routes for LLM Shield."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.mcp_guard import (
    register_mcp_server,
    get_mcp_server,
    list_mcp_servers,
    MCPGuard,
)
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield/mcp", tags=["mcp"])


class MCPRegisterRequest(BaseModel):
    name: str
    url: str
    tools: list[str] = Field(default_factory=list)
    trust_score: float = 1.0


class MCPCheckRequest(BaseModel):
    mcp_server: str
    tool_name: str
    agent_key: Optional[str] = None


@router.post("/register")
async def register_server(body: MCPRegisterRequest):
    """Register an MCP server with its tools and trust score."""
    register_mcp_server(
        name=body.name,
        url=body.url,
        tools=body.tools,
        trust_score=body.trust_score,
    )
    return {
        "status": "registered",
        "server": {
            "name": body.name,
            "url": body.url,
            "tools": body.tools,
            "trust_score": body.trust_score,
        },
    }


@router.post("/check")
async def check_tool_call(body: MCPCheckRequest, request: Request):
    """Validate a tool call before execution against MCP policies."""
    guard = MCPGuard()
    context = {
        "mcp_server": body.mcp_server,
        "tool_name": body.tool_name,
        "agent_key": body.agent_key,
    }
    result = await guard.check("", context)

    tenant_id = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    await audit_logger.log({
        "agent_key": body.agent_key or "",
        "endpoint": "/v1/shield/mcp/check",
        "input_text": f"mcp_check:{body.mcp_server}/{body.tool_name}",
        "action_taken": result.action,
        "guardrails_triggered": ["mcp_guard"] if not result.passed else [],
        "latency_ms": round(result.latency_ms, 2),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id,
            "user_role": "",
            "stage": "mcp_check",
            "blocked": not result.passed and result.action == "block",
            "block_reason": result.message if not result.passed else None,
            "session_id": "",
            "tool_calls": [{"tool_name": body.tool_name, "rbac": {"allowed": result.passed, "message": result.message}}],
            "tool_call_count": 1,
            "input_guardrails": [{"guardrail": "mcp_guard", "passed": result.passed, "action": result.action, "message": result.message}],
            "output_guardrails": [],
            "usage": {},
        },
    })

    return {
        "allowed": result.passed,
        "action": result.action,
        "message": result.message,
        "details": result.details,
    }


@router.get("/servers")
async def list_servers():
    """List all registered MCP servers."""
    servers = list_mcp_servers()
    return {"servers": servers, "count": len(servers)}
