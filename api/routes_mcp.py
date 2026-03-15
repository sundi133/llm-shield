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
async def check_tool_call(body: MCPCheckRequest):
    """Validate a tool call before execution against MCP policies."""
    guard = MCPGuard()
    context = {
        "mcp_server": body.mcp_server,
        "tool_name": body.tool_name,
        "agent_key": body.agent_key,
    }
    result = await guard.check("", context)
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
