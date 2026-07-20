---
title: MCP gateway (small-team edition)
layout: default
nav_order: 22
permalink: /mcp-gateway-lite/
description: A single docker run that fronts your MCP servers with a role-to-tool allowlist and logs every tool call. No Redis, no portal, no tenant keys.
---

# MCP gateway: small-team edition
{: .no_toc }

One `docker run` that fronts one or more MCP servers, enforces a role to tool
allowlist, and logs every tool call as JSON. Configured by a single file. No
Redis, no admin portal, no tenant API keys.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## When to use this

Use the [MCP scanner](/mcp-scanner/) to check a server *before* you connect it;
use this gateway to govern it *while it runs*. This edition is for a small team
that wants an allowlist and an audit trail without deploying the multi-tenant
platform gateway.

## Quick start

Write a `gateway.yaml`:

```yaml
team: acme
log: { format: json, path: "-" }
routes:
  - route: files
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    isolation_ack: true
rbac:
  roles:
    reader: { allowed_tools: ["read_file", "list_directory"] }
  agents:
    coding-agent: reader
```

Run it:

```bash
docker run -p 8080:8080 \
  -v $PWD/gateway.yaml:/etc/mcp-gateway/gateway.yaml \
  shield-mcp-gateway
# or: docker compose -f docker-compose.gateway.yml up
```

Point your agent at `http://localhost:8080/gateway/files/mcp`, sending its
identity as headers:

```
X-Agent-Key: coding-agent
X-User-Role: reader
```

A call to `read_file` passes; a call to `delete_file` is blocked and logged.

## What it enforces

- **Allowlist.** Each agent maps to a role; each role lists `allowed_tools`
  (empty means all) and `denied_tools`. A call outside the allowlist is blocked
  before it reaches the upstream. Identity comes from the connection headers,
  never from tool arguments.
- **Logging.** Every decision is one JSON line to stdout (or a file): tool, agent,
  allowed, action, reason, risk. Ship it to your log stack.
- **Description scanning.** With `scan_descriptions: true`, poisoned tool
  descriptions are annotated on `tools/list`.

## Stronger enforcement (opt-in)

The base chain above (allowlist, validation, logging) runs by default. Three more
guards — per-tool/global **rate limiting**, **tool-use conditions** (time windows,
required workflow, role), and **human-in-the-loop confirmation** for sensitive
tools — turn on with one env var:

```bash
-e SHIELD_MCP_TOOL_PARITY=1   # off by default; 1/true/yes/on enables
```

Rate limiting and tool-use conditions key on the agent from `X-Agent-Key`, so they
work on this header-based gateway.

**One honest limitation.** HITL confirmation is scoped to a per-session agent
identity, which the header-only path does not carry. So on this edition it
reports `session_unavailable` on a sensitive call rather than gating it — visibly,
not silently. To get real HITL confirmation, give agents a verified Shield agent
token (which carries a session) via the `http` enforcement backend below, or use
the platform gateway.

## Enforcement modes

The default image is slim and runs on CPU: the allowlist and logging need no
model. Model-grade output DLP and prompt-injection detection are opt-in by
pointing a route at a Shield backend:

```yaml
    enforcement_backend: http
    shield_url: "https://shield.example.com"
    shield_tenant_key: "..."
```

## Important: non-bypassability

The gateway only governs traffic that flows through it. Your upstream MCP server
MUST accept connections **only** from the gateway (localhost, firewall, or mTLS).
A route with `isolation_ack: false` logs a loud warning, because an upstream an
agent can reach directly is not actually governed.

## Configuration reference

| field | meaning |
|---|---|
| `team` | a label for this deployment |
| `log.format` / `log.path` | `json`/`text`; `"-"` for stdout or a file path |
| `routes[].route` | the path segment: `/gateway/<route>/mcp` |
| `routes[].transport` | `stdio` (`command`/`args`/`env`) or `sse`/`http` (`url`/`headers`) |
| `routes[].scan_descriptions` | annotate poisoned tool descriptions |
| `routes[].isolation_ack` | you confirm the upstream only accepts the gateway |
| `routes[].enforcement_backend` | `inprocess` (default) or `http` (Shield backend) |
| `rbac.roles` | role to `allowed_tools` / `denied_tools` |
| `rbac.agents` | `X-Agent-Key` to role |

Set `SHIELD_GATEWAY_FAIL_OPEN=1` to allow a call when enforcement itself errors
(default is fail-closed). Set `SHIELD_MCP_TOOL_PARITY=1` to add rate limiting,
tool-use conditions, and HITL confirmation (see Stronger enforcement).

Source: [`core/mcp/gateway_lite.py`](https://github.com/sundi133/llm-shield/blob/main/core/mcp/gateway_lite.py).
Spec: `docs/spec-mcp-gateway-lite.md`.
