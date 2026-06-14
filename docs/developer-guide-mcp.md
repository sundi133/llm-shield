---
title: Developer Guide — MCP & APIs
layout: default
nav_order: 4
permalink: /developer-guide-mcp/
description: Three ways a developer gives an agent governed tool access — generate a server, proxy an existing one, or call over HTTP.
---

# Developer guide — MCP & APIs
{: .no_toc }

You bring an API (an OpenAPI spec) or an existing MCP server; Shield makes the
agent's access to it **governed** — RBAC, kill switch, output sanitization, audit
— without you writing any enforcement code.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The mental model — three ordered steps

Every path below is the same three steps:

1. **One-time setup** — point the SDK / a generated server / the proxy at Shield.
2. **Per-process agent token** — your agent identifies itself with an `agent_key`,
   registered once with its `role_permissions` (which role may call which tool).
   This is *capability minting*.
3. **Per-action capability check** — every tool call carries `agent_key` +
   `user_role`; Shield allows or blocks it.

Your job is small: pick a path and set the agent identity. The security team owns
the policy.

> **Sandbox:** any API key starting with `sk-test-` resolves to a shared sandbox
> tenant Shield auto-provisions — use it to learn the flow with zero setup, then
> swap in a real tenant key for production.

---

## Which path?

| You have… | Path | What you get |
|---|---|---|
| An OpenAPI spec, you use Claude Desktop / Cursor | **A — codegen** | A real MCP server you own, governed via env vars |
| Existing / third-party MCP servers | **B — transparent proxy** | Governance with no regeneration |
| Your own agent loop, no MCP client | **C — runtime HTTP** | Shield brokers calls over HTTP |

---

## Path A — generate a governed MCP server (codegen)

Generate deployable source from a spec. The RBAC/kill-switch hook is written
into it; it activates only when `SHIELD_URL` is set, so it also runs as a plain
MCP server without Shield.

```bash
SHIELD=http://localhost:8080 ; KEY='X-API-Key: sk-test-demo'

curl -s -X POST "$SHIELD/v1/openapi/generate" -H "$KEY" -H 'Content-Type: application/json' -d '{
  "language":"python", "base_url":"https://api.mycompany.com",
  "include_risky":true, "server_name":"mycompany-mcp",
  "spec": { ...your OpenAPI spec... }
}' | python3 -c "import sys,json;open('server.py','w').write(json.load(sys.stdin)['files']['server.py'])"

pip install mcp httpx
```

`language` accepts `python`, `typescript`, or `both`. `include_risky:false`
(default) emits only read operations — a safe start.

Add it to your MCP client (governance turns on via the `SHIELD_*` env vars):

```json
{ "mcpServers": { "mycompany": {
    "command": "/path/.venv/bin/python", "args": ["/path/server.py"],
    "env": {
      "API_BASE_URL": "https://api.mycompany.com",
      "SHIELD_URL": "https://shield.internal", "SHIELD_API_KEY": "tenant-key",
      "SHIELD_AGENT_KEY": "support-bot",       "SHIELD_USER_ROLE": "reader"
}}}}
```

The generated file is plain source — read it, edit it, commit it. It depends only
on `mcp` + `httpx`, nothing from Shield.

---

## Path B — govern existing MCP servers (transparent proxy)

Put Shield in front of any MCP server. It filters `tools/list` to what the role
may use, enforces every `tools/call`, and sanitizes output — no change to the
upstream server.

```python
from core.mcp.proxy_server import proxy_for

proxy = await proxy_for({"transport": "stdio", "command": "python", "args": ["stripe_server.py"]})
ctx = dict(agent_key="support-bot", user_role="reader", tenant_id="acme")

await proxy.list_tools(**ctx)                       # only tools 'reader' may use
await proxy.call_tool("refund", {...}, **ctx)       # enforced; blocked → never forwarded
await proxy._upstream.aclose()                      # on shutdown
```

Transports: `stdio`, `sse`, `http` (streamable). Requires `pip install mcp`.

---

## Path C — broker calls over HTTP (runtime)

You control the agent loop and just want Shield to gate + execute API calls.

```bash
# once: register the spec
curl -X POST "$SHIELD/v1/openapi/import" -H "$KEY" -d '{"spec":{...},"base_url":"https://api.mycompany.com"}'

# per tool call, from your agent:
curl -X POST "$SHIELD/v1/openapi/call" -H "$KEY" \
  -H "X-Agent-Key: support-bot" -H "X-User-Role: reader" \
  -d '{"tool":"get_account","arguments":{"id":"C-1"}}'
```

Shield enforces, calls the upstream, sanitizes the result, and returns it.

---

## Register your agent (all paths)

Capabilities are minted once per agent. Use the portal, or:

```bash
curl -X POST "$SHIELD/v1/agents/registry" -H "$KEY" -H 'Content-Type: application/json' -d '{
  "agent_id": "support-bot",
  "tools": ["get_account", "refund"],
  "role_permissions": { "reader": ["get_account"], "admin": ["get_account", "refund"] }
}'
```

---

## Gotchas (save yourself an hour)

- **Registration is create-only** — re-posting an existing `agent_id` returns
  `409` and keeps the old permissions. Use a new id or `DELETE` first.
- **State is in-memory without Redis** — restarting Shield wipes imported specs
  and registered agents. Set `REDIS_URL` to persist across restarts.
- **MCP Inspector must use STDIO** for a generated server — set Transport =
  STDIO, Command = your venv python, Arguments = `server.py` (not Streamable
  HTTP + a URL).
- **`server.py` should hang silently** when you run it — that's a stdio server
  waiting on stdin, i.e. it started fine.

---

## Where to next

- [End-to-end lab]({{ "/mcp-e2e-lab/" | relative_url }}) — the full flow, verified
- [Glossary]({{ "/glossary/" | relative_url }}) — shared vocabulary with the security team
- [Policy lifecycle]({{ "/policy-lifecycle/" | relative_url }}) — how monitor → enforce works
