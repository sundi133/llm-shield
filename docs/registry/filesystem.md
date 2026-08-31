---
title: "Filesystem MCP Server MCP security rating"
description: "Security scan of the Filesystem MCP Server MCP server: 75/100 (minor). Tool poisoning, over-broad permissions, and prompt-injection checks by shield-mcp."
layout: default
parent: MCP Registry
permalink: /registry/filesystem/
---

# Filesystem MCP Server MCP security rating

**Score: 75/100** (minor) &middot; 1 high finding

- Homepage: <https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem>
- Repository: `modelcontextprotocol/servers`
- Last scanned: 2026-08-31T12:29:52.469766+00:00
- Surface: 14 tools, 0 resources, 0 prompts

## Findings

| severity | category | where | detail |
|---|---|---|---|
| high | over-broad-permission | tool `write_file` | Tool name implies a dangerous capability (write_file). |

## Scan it yourself

```bash
npx @votal/mcp-scan stdio:npx -y @modelcontextprotocol/server-filesystem /tmp
```
