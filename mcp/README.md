# Votal Shield MCP Server

Connect any MCP-compatible AI agent to Votal Shield guardrails. No SDK, no install — just a URL.

## Quick Start (30 seconds)

Add this to your MCP client config and you're done:

```json
{
  "mcpServers": {
    "votal-shield": {
      "url": "https://shield.votal.ai/mcp/sse",
      "headers": {
        "X-API-Key": "your-tenant-api-key"
      }
    }
  }
}
```

That's it. No `pip install`, no `npm install`, no local process.

## Where to add the config

| Client | Config file |
|--------|------------|
| **Claude Desktop** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Code** | `.mcp.json` in your project root |
| **Cursor** | `.cursor/mcp.json` in your project root |
| **Windsurf** | `.windsurf/mcp.json` in your project root |

## Available Tools

Once connected, your agent gets these tools automatically:

| Tool | When to call | What it does |
|------|-------------|--------------|
| `shield_check_input` | Before processing user input | Adversarial detection, toxicity, PII check |
| `shield_check_output` | Before returning LLM response | PII leakage, bias, tone enforcement |
| `shield_check_tool` | Before executing any tool | RBAC + kill switch authorization |
| `shield_sanitize_output` | After tool execution | PII redaction, data policy enforcement |
| `shield_disable_tool` | Emergency | Kill switch — disable a tool globally |
| `shield_enable_tool` | Recovery | Re-enable a disabled tool |

## Example Flow

```
User: "Delete all customer records from the database"

Agent:
  1. shield_check_input("Delete all customer records...")
     → BLOCKED: adversarial detection triggered
     → Agent refuses the request

User: "Show me customer John Smith's order history"

Agent:
  1. shield_check_input("Show me customer John Smith's...")
     → SAFE
  2. shield_check_tool("database_query", {query: "SELECT * FROM orders..."})
     → ALLOWED
  3. database_query executes → returns results with SSN, email
  4. shield_sanitize_output("database_query", results)
     → SANITIZED: SSN and email redacted
  5. Agent returns sanitized results to user
```

## Transports

The server supports two MCP transports:

| Transport | URL | Use when |
|-----------|-----|----------|
| **Streamable HTTP** (recommended) | `POST /mcp/message` | Client supports MCP 2025-03-26 spec |
| **SSE** (legacy) | `GET /mcp/sse` | Older clients that use SSE transport |

Both are built into the Shield API — no separate server to run.

## Self-hosted

If you run Shield on your own infrastructure:

```json
{
  "mcpServers": {
    "votal-shield": {
      "url": "https://your-shield-server.com/mcp/sse",
      "headers": {
        "X-API-Key": "your-api-key"
      }
    }
  }
}
```
