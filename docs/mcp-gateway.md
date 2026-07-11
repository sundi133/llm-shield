---
title: MCP Gateway
layout: default
nav_order: 19
permalink: /mcp-gateway/
---

# MCP Gateway — protect any MCP server (no code changes)

Put Shield **in front of** an existing MCP server — third-party, vendor-built,
legacy, or your own — **without changing a line of it**. Your agents connect to
the gateway instead of the server; every `tools/call` and `resources/read` is
enforced (RBAC → input → forward → output DLP) before it reaches the real server.
One gateway deployment fronts many servers by config.

Use this when you **don't control** the server. If you do, the embedded pattern
([examples/mcp_server](../examples/mcp_server)) is simpler.

## How it works

Two separate connections — this is the thing to get right:

```
 your agent ───▶  Shield gateway  ───▶  your MCP server ("upstream")
                  api.guardrails…        e.g. mcp.internal:9000
   leg 1: public, direct         leg 2: the gateway must be able to reach it
   (agents point here)                  (and ONLY the gateway should)
```

- **Leg 1** (agent → gateway): the gateway is your public endpoint; agents point at
  `https://<shield>/gateway/<route>/mcp`.
- **Leg 2** (gateway → upstream): the gateway makes an **outbound** call to your
  server. Your server just has to be reachable *from the gateway* — and, for real
  protection, reachable **only** from the gateway (see [Non-bypassability](#4-lock-the-upstream-down-non-bypassable)).

Everything is served by the Shield **data plane** and authenticated with your
**tenant API key** (`X-API-Key`) — no admin key involved.

## Integrate in 4 steps

Prerequisites: a Shield tenant + API key (`X-API-Key`), and an MCP server that
speaks `http` (streamable) / `sse` / `stdio`.

```bash
export SHIELD=https://<your-shield-data-plane>     # e.g. https://api.guardrails.votal.ai
export KEY=<your-tenant-api-key>
export ROUTE=myserver
```

### 1. Register your agent + role→tool policy (so RBAC has something to enforce)

Enforcement keys off **tool names**, so tell Shield which role may call which tool.
Use your upstream's real tool names.

```bash
curl -s -X POST "$SHIELD/v1/agents/registry" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "my-agent",
    "tools": ["search", "get_record", "delete_record"],
    "role_permissions": {
      "reader": ["search", "get_record"],
      "admin":  ["search", "get_record", "delete_record"]
    }
  }'
```
(You can also manage this + per-tool **data policies** in the tenant portal.)

### 2. Configure the route → your upstream

```bash
curl -s -X PUT "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{
    "transport": "http",
    "url": "https://your-mcp-server/mcp",
    "enforcement_backend": "inprocess",
    "isolation_ack": true
  }'
```
- `transport`: `http` (streamable-HTTP) / `sse` / `stdio` (`command` + `args` + `env`).
- Upstream creds → `headers` / `env` (redacted on read).
- `url` must be reachable **from the gateway** (not `localhost` if the gateway is
  remote — see [Reachability](#reachability--deploying-the-upstream)).

### 3. Point your agents at the gateway

```
https://<shield>/gateway/myserver/mcp
```
Speaks MCP JSON-RPC. Identity comes from the **connection**, never from tool args:

| Header | Meaning |
|---|---|
| `X-API-Key` | your tenant key (which tenant's policy) |
| `X-Agent-Key` | the registered agent id (`my-agent`) |
| `X-User-Role` | the caller's role (`reader` / `admin` / …) |

```bash
GW="$SHIELD/gateway/$ROUTE/mcp"
H=(-H "X-API-Key: $KEY" -H "X-Agent-Key: my-agent" -H "X-User-Role: reader" -H 'Content-Type: application/json')

curl -s -X POST "$GW" "${H[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# reader may not delete -> blocked, never reaches the upstream:
curl -s -X POST "$GW" "${H[@]}" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_record","arguments":{"id":"1"}}}'
```

For MCP clients (Claude Desktop/Code, etc.), point a remote/streamable-HTTP
connector at that URL and set the identity headers.

### 4. Lock the upstream down (non-bypassable)

The gateway only enforces **what flows through it**. If agents can reach your
upstream directly, they can skip Shield. So make the upstream reachable **only**
from the gateway — private network / firewall / mTLS, or a gateway-only bearer
token in the route `headers` that the upstream checks — then keep
`isolation_ack: true` (your attestation of this). A route with
`isolation_ack: false` starts in a warned, not-truly-protected state.
See [mcp-runtime-enforcement.md](mcp-runtime-enforcement.md).

## Run agents in a sandbox (NVIDIA OpenShell)

Sandbox runtimes like [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) give
**kernel-level isolation** (filesystem, process, and **network egress** control) but
not semantic guardrails. Pair them: allowlist **only** the Shield gateway host in the
sandbox's egress policy, and the agent is *forced* through Shield with no way around
it — enforcement becomes non-bypassable, by the kernel, not by trusting the agent.

Full walkthrough (policy + verified tests): **[Agent Sandbox (OpenShell)](openshell-sandbox.md)**.

## Supported MCP methods

| Method | Gateway behavior |
|---|---|
| `initialize` | answered locally (handshake) |
| `tools/list` | forwarded, **RBAC-filtered** to what the role may use |
| `tools/call` | **enforced** (RBAC + data policy), forwarded, **output sanitized** |
| `resources/list`, `resources/templates/list` | forwarded (passthrough) |
| `resources/read` | forwarded, then **DLP-checked** — content treated like a tool result (redacted or blocked per role/policy) |
| `prompts/list`, `prompts/get` | forwarded (passthrough) |
| `notifications/*` | passed through (204) |
| `sampling/*`, `completion/*`, `resources/subscribe`, … | `-32601` not supported (yet) |

`resources/*` + `prompts/*` are on by default (`SHIELD_GATEWAY_RESOURCES=0` for
tools-only). Where no policy is configured for a method, the gateway **relays** it
rather than blocking.

## Enforcement backends

| `enforcement_backend` | Where enforcement runs | Use when |
|---|---|---|
| `inprocess` (default) | in the gateway process | gateway co-located with Shield; lowest latency |
| `http` | a central Shield data plane (`/v1/shield/tool/check` + `/tool/output`; set `shield_url` + `shield_tenant_key`) | thin-edge gateway, scaled separately; +1 round-trip/call |

Both run the **same** checks, so switching only changes *where* enforcement runs.

## Reachability & deploying the upstream

The gateway connects to the upstream **from the data-plane process**, so a **remote**
gateway (e.g. `api.guardrails.votal.ai`) cannot reach your `localhost`. Options:

| Setup | `url` in the route |
|---|---|
| **Local dev** (upstream on your laptop) | expose it: `ngrok http 9100` → use the public URL (+ header `"ngrok-skip-browser-warning":"1"`) |
| **Railway / Fly / Render** | the app's public URL (see [examples/mcp_gateway/RAILWAY.md](../examples/mcp_gateway/RAILWAY.md)) |
| **Same VPC / private network** | the internal address (best — naturally gateway-only) |

Runnable examples to copy from: [examples/mcp_gateway](../examples/mcp_gateway)
(`register_agent.py`, `bank_upstream.py`, `rp_upstream.py` for resources/prompts).

## Manage routes

```bash
curl "$SHIELD/v1/tenant/me/mcp-gateway/upstreams"          -H "X-API-Key: $KEY"   # list (secrets redacted)
curl "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE"   -H "X-API-Key: $KEY"   # get one
curl -X DELETE "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" -H "X-API-Key: $KEY"
```

## Troubleshooting

The gateway returns JSON-RPC errors; here's what each means.

| You see | Meaning / fix |
|---|---|
| `-32004 no upstream configured for route 'X'` | **The route isn't created** (or you deleted it). Run step 2's `PUT`. Most common gotcha — starting the upstream is **not** the same as configuring the route. |
| `-32001 unauthenticated: no tenant resolved` | `X-API-Key` missing or not a valid tenant key on **this** deployment (sandbox keys like `sk-test-*` may not exist in prod). |
| `-32601 method not supported` | The method isn't in the supported set, or `SHIELD_GATEWAY_RESOURCES=0`, or the deploy predates that feature. |
| `-32000 Blocked by Shield: Role '…' is not allowed to use tool '…'` | **RBAC decision** (working as intended). Register/adjust `role_permissions`. |
| `-32000 Resource content blocked by Shield data policy` | **DLP decision** — content withheld for that role. Expected; try a higher-clearance role. |
| `-32603 error handling …: <Exc>` | Upstream/transport error: upstream unreachable, or doesn't implement that method. Check the `url` is reachable from the gateway. |
| `tools/list` empty / upstream connect fails | Upstream not reachable from the gateway (`localhost` from a remote gateway) or an ngrok interstitial — add `"ngrok-skip-browser-warning":"1"` to the route `headers`. |
| Logs warn `isolation_ack=false` | The upstream isn't locked to the gateway — enforcement is bypassable until you fix leg 2 and set `isolation_ack: true`. |

## Reference

**Endpoints** (all tenant-key auth, on the data plane):

| Endpoint | Purpose |
|---|---|
| `POST /v1/agents/registry` | register agent + `role_permissions` |
| `PUT/GET/DELETE /v1/tenant/me/mcp-gateway/upstreams/{route}` | manage a route |
| `GET /v1/tenant/me/mcp-gateway/upstreams` | list routes |
| `POST /gateway/{route}/mcp` | the MCP endpoint agents call |

**Env flags** (gateway process): `SHIELD_GATEWAY_RESOURCES` (default on — resources/prompts),
`SHIELD_GATEWAY_FAIL_OPEN=1` (allow calls when enforcement is unreachable; default
fail-closed), `SHIELD_URL` / `RUNPOD_TOKEN` (for the `http` backend). The gateway
needs the `mcp` client SDK (already in `requirements.txt`).
