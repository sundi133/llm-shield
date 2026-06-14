---
title: Getting Started (External Developer)
layout: default
nav_order: 1
permalink: /getting-started/
description: Start using Shield with only a URL and an API key — no repository access. Three paths, all verified.
---

# Getting started — external developer
{: .no_toc }

You don't need the Shield repository. With a **Shield URL** and a **tenant API
key**, you can govern an API, an agent, or an MCP client. Everything is
delivered over the API or as self-contained code (public dependencies only).
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Prerequisites (from your platform / security team)
- `SHIELD_URL` — e.g. `https://shield.yourco.com`
- a tenant **API key** (`X-API-Key`)

```bash
SHIELD=https://shield.yourco.com ; KEY='X-API-Key: your-tenant-key'
```

## Which path?

| You have… | Path |
|---|---|
| An API (OpenAPI spec) + use Claude Desktop / Cursor | **A — generate a governed MCP server** |
| Your own agent codebase | **B — the `votal` SDK** |
| Just an MCP client, want guardrails fast | **C — Shield's MCP URL** |

---

## Path A — turn your API into a governed MCP server

**1. Generate** (one call writes the server + a deploy kit to disk):
```bash
curl -s -X POST "$SHIELD/v1/openapi/generate" -H "$KEY" -H 'Content-Type: application/json' -d '{
  "language":"python", "style":"typed", "deploy":true,
  "base_url":"https://api.mycompany.com",
  "spec": '"$(cat my-openapi.json)"'
}' | python3 -c "import sys,json,os; \
  [(os.makedirs(os.path.dirname(n) or '.',exist_ok=True), open(n,'w').write(c)) \
   for n,c in json.load(sys.stdin)['files'].items()]; print('wrote files')"
```

**2. Install deps** (all public — no repo):
```bash
pip install -r requirements.txt          # mcp, httpx, pydantic, uvicorn
```

**3. Run / deploy.** Locally for desktop (stdio), or as a container anywhere
(the kit has Dockerfile / Compose / Cloud Run / Fly / K8s — see the
[Deployment guide]({{ "/deployment-guide/" | relative_url }})):
```bash
# cloud / on-prem (Streamable HTTP on :8080, health at /health)
MCP_TRANSPORT=http API_BASE_URL=https://api.mycompany.com \
SHIELD_URL=$SHIELD SHIELD_API_KEY=your-tenant-key \
SHIELD_AGENT_KEY=my-agent SHIELD_USER_ROLE=reader \
python server.py
```

**4. Connect your MCP client:**
```json
{ "mcpServers": { "mycompany": {
    "url": "https://my-mcp.example.com/mcp"          // deployed (HTTP)
    // — or local stdio —
    // "command": "python", "args": ["server.py"],
    // "env": { "API_BASE_URL": "...", "SHIELD_URL": "...", "SHIELD_API_KEY": "...",
    //          "SHIELD_AGENT_KEY": "my-agent", "SHIELD_USER_ROLE": "reader" }
}}}
```

> **Permissions** (which role may call which tool) are usually set once by your
> platform team. To do it yourself:
> ```bash
> curl -s -X POST "$SHIELD/v1/agents/registry" -H "$KEY" -d \
>  '{"agent_id":"my-agent","tools":["get_account","send_payment"],
>    "role_permissions":{"reader":["get_account"],"admin":["get_account","send_payment"]}}'
> ```

✅ **Verified:** an allowed call reaches your API; a role-blocked call returns
`"Blocked by Shield: Role 'reader' is not allowed to use tool 'send_payment'"`.

---

## Path B — guard an agent you're coding (SDK)

```bash
pip install votal           # public package — no repo
```
```python
from votal import VotalShield

shield = VotalShield(
    shield_url="https://shield.yourco.com",
    api_key="your-tenant-key",
    agent_id="my-agent",
    user_role="reader",
)

# Option 1 — wrap a tool: RBAC check + output sanitization on every call
@shield.protect
@tool
def send_payment(account: str, amount: float) -> str:
    return bank.transfer(account, amount)

# Option 2 — check explicitly
guard = shield.check_tool("send_payment", user_role="reader")
if not guard.allowed:
    raise PermissionError(guard.reason)
```
✅ **Verified:** `shield.health()` is `True`; `check_tool` returns `allowed=True`
for permitted tools and `allowed=False` with a reason for blocked ones.

---

## Path C — guardrail tools in your MCP client (no code)

Add Shield's own MCP server to your client config:
```json
{ "mcpServers": { "shield": {
    "url": "https://shield.yourco.com/mcp",
    "headers": { "X-API-Key": "your-tenant-key" }
}}}
```
Your agent gains tools it can call around its own actions:
`shield_check_input`, `shield_check_output`, `shield_check_tool`,
`shield_sanitize_output`, `shield_disable_tool`, `shield_enable_tool`.

✅ **Verified:** the server identifies as `votal-shield` and lists those six
tools.

---

## Notes
- **No repository access is needed** in any path — you consume the Shield API and
  run self-contained generated code or the public SDK.
- **Governance is optional per run** — omit `SHIELD_URL` (Path A) to run a plain
  MCP server; set it to enforce.
- **Path B requires the `votal` package** to be available to you (PyPI or a wheel
  your platform team provides). Path A needs only public `mcp`/`httpx`/`pydantic`.

## Where to next
- [Developer guide — MCP & APIs]({{ "/developer-guide-mcp/" | relative_url }})
- [Deployment guide]({{ "/deployment-guide/" | relative_url }})
- [End-to-end lab]({{ "/mcp-e2e-lab/" | relative_url }})
