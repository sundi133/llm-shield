---
title: "Memory MCP Server MCP security rating"
description: "Security scan of the Memory MCP Server MCP server: 25/100 (high-risk). Tool poisoning, over-broad permissions, and prompt-injection checks by shield-mcp."
layout: default
parent: MCP Registry
permalink: /registry/memory/
---

# Memory MCP Server MCP security rating

**Score: 25/100** (high-risk) &middot; 3 high findings

- Homepage: <https://github.com/modelcontextprotocol/servers/tree/main/src/memory>
- Repository: `modelcontextprotocol/servers`
- Last scanned: 2026-08-31T12:30:16.615150+00:00
- Surface: 9 tools, 1 resources, 0 prompts

## Findings

| severity | category | where | detail |
|---|---|---|---|
| high | over-broad-permission | tool `delete_entities` | Tool name implies a dangerous capability (delete). |
| high | over-broad-permission | tool `delete_observations` | Tool name implies a dangerous capability (delete). |
| high | over-broad-permission | tool `delete_relations` | Tool name implies a dangerous capability (delete). |

## Scan it yourself

```bash
npx @votal/mcp-scan stdio:npx -y @modelcontextprotocol/server-memory
```
