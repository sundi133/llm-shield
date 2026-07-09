"""Votal Shield MCP Server — guardrails as MCP tools.

Exposes Shield guardrails as MCP tools so any MCP-compatible agent
(Claude Desktop, Cursor, Windsurf, OpenDevin) can use them natively.

Setup:
  1. pip install mcp httpx
  2. Set environment variables:
       VOTAL_SHIELD_URL=https://shield.votal.ai
       VOTAL_API_KEY=your-tenant-api-key
       VOTAL_TENANT_ID=your-tenant-id
       VOTAL_AGENT_KEY=coding-agent  (optional, default: mcp-agent)
  3. Add to your MCP client config (e.g. claude_desktop_config.json):
       {
         "mcpServers": {
           "votal-shield": {
             "command": "python",
             "args": ["/path/to/votal_shield_server.py"],
             "env": {
               "VOTAL_SHIELD_URL": "https://shield.votal.ai",
               "VOTAL_API_KEY": "your-tenant-api-key",
               "VOTAL_TENANT_ID": "your-tenant-id"
             }
           }
         }
       }
"""

import os
import json
import httpx
from mcp.server import Server
from mcp.server.stdio import run_server
from mcp.types import Tool, TextContent

SHIELD_URL = os.getenv("VOTAL_SHIELD_URL", "https://shield.votal.ai")
API_KEY = os.getenv("VOTAL_API_KEY", "")
TENANT_ID = os.getenv("VOTAL_TENANT_ID", "")
AGENT_KEY = os.getenv("VOTAL_AGENT_KEY", "mcp-agent")

_client = httpx.Client(
    base_url=SHIELD_URL,
    headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
    timeout=15,
)

server = Server("votal-shield")


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="shield_check_input",
            description=(
                "Check a user message against Votal Shield input guardrails "
                "(adversarial detection, toxicity, PII, etc.). "
                "Call this BEFORE processing any user input."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The user message to check",
                    },
                },
                "required": ["message"],
            },
        ),
        Tool(
            name="shield_check_output",
            description=(
                "Check an LLM response against output guardrails "
                "(PII leakage, bias, tone enforcement). "
                "Call this BEFORE returning a response to the user."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "output": {
                        "type": "string",
                        "description": "The LLM response text to check",
                    },
                },
                "required": ["output"],
            },
        ),
        Tool(
            name="shield_check_tool",
            description=(
                "Check if a tool call is authorized (RBAC + kill switch). "
                "Call this BEFORE executing any tool like file_write, "
                "shell_execute, api_call, database_query, etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool to check (e.g. file_write, shell_execute)",
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Arguments being passed to the tool",
                        "default": {},
                    },
                    "user_role": {
                        "type": "string",
                        "description": "Role of the user (e.g. developer, admin, viewer)",
                        "default": "developer",
                    },
                },
                "required": ["tool_name"],
            },
        ),
        Tool(
            name="shield_sanitize_output",
            description=(
                "Sanitize tool output — redact PII, enforce data policies. "
                "Call this AFTER a tool executes, before using its output."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool that produced the output",
                    },
                    "output": {
                        "type": "string",
                        "description": "The tool's output to sanitize",
                    },
                },
                "required": ["tool_name", "output"],
            },
        ),
        Tool(
            name="shield_disable_tool",
            description=(
                "Emergency kill switch — immediately disable a tool globally. "
                "Use when a tool is causing harm or behaving unexpectedly."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool to disable",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why this tool is being disabled",
                        "default": "Disabled via MCP kill switch",
                    },
                },
                "required": ["tool_name"],
            },
        ),
        Tool(
            name="shield_enable_tool",
            description="Re-enable a previously disabled tool.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool to re-enable",
                    },
                },
                "required": ["tool_name"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "shield_check_input":
            resp = _client.post("/guardrails/input", json={
                "message": arguments["message"],
            })
            result = resp.json()
            safe = result.get("safe", True)
            guardrails = result.get("guardrail_results", [])
            triggered = [g for g in guardrails if not g.get("passed")]

            if safe:
                summary = f"SAFE — {len(guardrails)} guardrails checked, all passed."
            else:
                names = [g.get("guardrail", "?") for g in triggered]
                reasons = [g.get("message", "") for g in triggered]
                summary = (
                    f"BLOCKED — triggered: {', '.join(names)}.\n"
                    f"Reasons: {'; '.join(reasons)}\n\n"
                    "Do NOT proceed with this input."
                )

            return [TextContent(type="text", text=summary)]

        elif name == "shield_check_output":
            resp = _client.post("/guardrails/output", json={
                "output": arguments["output"],
            })
            result = resp.json()
            safe = result.get("safe", True)

            if safe:
                sanitized = result.get("sanitized_output")
                if sanitized and sanitized != arguments["output"]:
                    return [TextContent(type="text", text=f"SAFE (sanitized) — use this version:\n\n{sanitized}")]
                return [TextContent(type="text", text="SAFE — output passed all guardrails.")]
            else:
                triggered = [g for g in result.get("guardrail_results", []) if not g.get("passed")]
                names = [g.get("guardrail", "?") for g in triggered]
                return [TextContent(type="text", text=f"BLOCKED — output violates: {', '.join(names)}. Do NOT return this to the user.")]

        elif name == "shield_check_tool":
            resp = _client.post("/v1/shield/tool/check", json={
                "tool_name": arguments["tool_name"],
                "agent_key": AGENT_KEY,
                "user_role": arguments.get("user_role", "developer"),
                "tenant_id": TENANT_ID,
                "arguments": arguments.get("arguments", {}),
            })
            result = resp.json()
            allowed = result.get("allowed", True)

            if allowed:
                return [TextContent(type="text", text=f"ALLOWED — tool '{arguments['tool_name']}' is authorized. Proceed.")]
            else:
                msg = result.get("message", "Not authorized")
                return [TextContent(type="text", text=f"BLOCKED — tool '{arguments['tool_name']}': {msg}. Do NOT execute this tool.")]

        elif name == "shield_sanitize_output":
            resp = _client.post("/v1/shield/tool/output", json={
                "tool_name": arguments["tool_name"],
                "output": arguments["output"],
                "agent_key": AGENT_KEY,
                "tenant_id": TENANT_ID,
            })
            result = resp.json()
            sanitized = result.get("sanitized_output", arguments["output"])
            safe = result.get("safe", True)

            if not safe:
                return [TextContent(type="text", text=f"BLOCKED — tool output violates data policy. Do NOT use this output.")]
            if sanitized != arguments["output"]:
                return [TextContent(type="text", text=f"SANITIZED — use this version:\n\n{sanitized}")]
            return [TextContent(type="text", text="CLEAN — no sanitization needed.")]

        elif name == "shield_disable_tool":
            resp = _client.post(
                f"/v1/shield/tools/{arguments['tool_name']}/disable",
                json={
                    "tenant_id": TENANT_ID,
                    "reason": arguments.get("reason", "Disabled via MCP"),
                },
            )
            return [TextContent(type="text", text=f"Tool '{arguments['tool_name']}' has been DISABLED globally.")]

        elif name == "shield_enable_tool":
            resp = _client.post(
                f"/v1/shield/tools/{arguments['tool_name']}/enable",
                json={"tenant_id": TENANT_ID},
            )
            return [TextContent(type="text", text=f"Tool '{arguments['tool_name']}' has been RE-ENABLED.")]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Shield error: {str(e)}")]


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_server(server))
