"""MCP (Model Context Protocol) guard — validates tool calls against registered MCP servers."""

from datetime import datetime
from typing import Optional

from core.models import GuardrailResult
from core.rbac import enforcer
from guardrails.base import BaseGuardrail


class MCPServerInfo:
    """In-memory representation of a registered MCP server."""

    def __init__(self, name: str, url: str, tools: list[str], trust_score: float = 1.0):
        self.name = name
        self.url = url
        self.tools = tools
        self.trust_score = trust_score

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "tools": self.tools,
            "trust_score": self.trust_score,
        }


# In-memory registry of MCP servers
_mcp_registry: dict[str, MCPServerInfo] = {}


def register_mcp_server(name: str, url: str, tools: list[str], trust_score: float = 1.0):
    """Register an MCP server in the in-memory registry."""
    _mcp_registry[name] = MCPServerInfo(name=name, url=url, tools=tools, trust_score=trust_score)


def get_mcp_server(name: str) -> Optional[MCPServerInfo]:
    """Get a registered MCP server by name."""
    return _mcp_registry.get(name)


def list_mcp_servers() -> list[dict]:
    """List all registered MCP servers."""
    return [server.to_dict() for server in _mcp_registry.values()]


class MCPGuard(BaseGuardrail):
    """Validates tool calls against registered MCP servers.

    Checks:
    - Is the MCP server registered?
    - Is the tool allowed on that server?
    - Does the agent's role permit the tool?
    - Does the server meet the minimum trust score?

    Settings:
    - require_registration: bool (default: true)
    - min_trust_score: float (default: 0.5)
    """

    name = "mcp_guard"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = datetime.now()
        context = context or {}

        mcp_server_name = context.get("mcp_server")
        tool_name = context.get("tool_name")
        agent_key = context.get("agent_key")

        settings = self.settings
        require_registration = settings.get("require_registration", True)
        min_trust_score = settings.get("min_trust_score", 0.5)

        # If no MCP server specified, skip
        if not mcp_server_name:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No MCP server specified, skipping MCP check",
                latency_ms=round(elapsed, 2),
            )

        # Check if server is registered
        server = get_mcp_server(mcp_server_name)
        if server is None:
            if require_registration:
                elapsed = (datetime.now() - start).total_seconds() * 1000
                return GuardrailResult(
                    passed=False,
                    action=self.configured_action,
                    guardrail_name=self.name,
                    message=f"MCP server '{mcp_server_name}' is not registered",
                    details={"mcp_server": mcp_server_name},
                    latency_ms=round(elapsed, 2),
                )
            else:
                elapsed = (datetime.now() - start).total_seconds() * 1000
                return GuardrailResult(
                    passed=True,
                    action="warn",
                    guardrail_name=self.name,
                    message=f"MCP server '{mcp_server_name}' not registered (registration not required)",
                    latency_ms=round(elapsed, 2),
                )

        # Check trust score
        if server.trust_score < min_trust_score:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"MCP server '{mcp_server_name}' trust score {server.trust_score} "
                    f"is below minimum {min_trust_score}"
                ),
                details={
                    "mcp_server": mcp_server_name,
                    "trust_score": server.trust_score,
                    "min_trust_score": min_trust_score,
                },
                latency_ms=round(elapsed, 2),
            )

        # Check if tool is allowed on this server
        if tool_name and server.tools and tool_name not in server.tools:
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Tool '{tool_name}' is not registered on MCP server '{mcp_server_name}'",
                details={
                    "mcp_server": mcp_server_name,
                    "tool_name": tool_name,
                    "available_tools": server.tools,
                },
                latency_ms=round(elapsed, 2),
            )

        # Check agent role permissions for the tool
        if agent_key and tool_name:
            role = enforcer.resolve_role(agent_key)
            if role and not enforcer.check_tool_access(role, tool_name):
                elapsed = (datetime.now() - start).total_seconds() * 1000
                return GuardrailResult(
                    passed=False,
                    action=self.configured_action,
                    guardrail_name=self.name,
                    message=f"Agent role '{role.name}' is not permitted to use tool '{tool_name}'",
                    details={
                        "role": role.name,
                        "tool_name": tool_name,
                        "mcp_server": mcp_server_name,
                    },
                    latency_ms=round(elapsed, 2),
                )

        elapsed = (datetime.now() - start).total_seconds() * 1000
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="MCP check passed",
            details={"mcp_server": mcp_server_name, "tool_name": tool_name},
            latency_ms=round(elapsed, 2),
        )
