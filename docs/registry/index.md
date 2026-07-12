---
title: "MCP Registry"
description: "Security ratings for public MCP servers, scored 0 to 100 from shield-mcp scans of tool poisoning, over-broad permissions, and hidden prompt-injection."
layout: default
nav_order: 21
has_children: true
permalink: /registry/
---

# MCP security registry

Security ratings for public [Model Context Protocol](https://modelcontextprotocol.io) servers, scored 0 to 100 by [shield-mcp](/mcp-scanner/). Each server is scanned for tool poisoning, over-broad permissions, and hidden prompt-injection in its tool, resource, and prompt metadata.

Checking a server you are about to add? Scan it yourself in one line:

```bash
npx @votal/mcp-scan stdio:'npx -y some-mcp-server'
```

## How servers are scored

| band | score | meaning |
|---|---|---|
| clean | 90 to 100 | no findings, or only minor ones |
| minor | 70 to 89 | low-impact issues to review |
| review | 40 to 69 | notable issues; read the findings before connecting |
| high-risk | 0 to 39 | tool poisoning or a hidden injection was found |
| unrated | n/a | could not be scanned, or exposes no tools |

Ratings are generated from real scans of a curated, version-pinned list and are refreshed on a schedule. To add a server, open a PR against `registry/servers.yaml`.

## Rated servers

No servers have been scanned yet. Ratings appear here after the first scan run.
