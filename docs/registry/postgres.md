---
title: "PostgreSQL MCP Server MCP security rating"
description: "Security scan of the PostgreSQL MCP Server MCP server: 100/100 (clean). Tool poisoning, over-broad permissions, and prompt-injection checks by shield-mcp."
layout: default
parent: MCP Registry
permalink: /registry/postgres/
---

# PostgreSQL MCP Server MCP security rating

**Score: 100/100** (clean) &middot; no findings

- Homepage: <https://github.com/modelcontextprotocol/servers/tree/main/src/postgres>
- Repository: `modelcontextprotocol/servers`
- Last scanned: 2026-08-31T12:30:05.294218+00:00
- Surface: 1 tools, 0 resources, 0 prompts

No findings from the offline scan.

## Scan it yourself

```bash
npx @votal/mcp-scan stdio:npx -y @modelcontextprotocol/server-postgres postgresql://localhost/postgres
```
