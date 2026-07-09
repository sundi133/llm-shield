---
title: MCP Gateway
layout: default
nav_order: 19
permalink: /mcp-gateway/
---

# MCP Gateway — protect an unmodified MCP server

Front a third-party / legacy / vendor MCP server with Shield **without changing a
line of it**. Point your agents at the gateway instead of the upstream; every tool
call is enforced (RBAC → input → forward → output) before it reaches the real
server. One deployment fronts many customers/servers by config.

This is the enforced counterpart to the embedded pattern
([examples/mcp_server](../examples/mcp_server)): use embedded when you control the
server, the gateway when you don't.

Built on the existing transparent proxy (`core/mcp/proxy_server.py::MCPProxy` +
`core/mcp/enforcement.py`) — same enforcement, relocated to a proxy.

## 1. Configure a route (per tenant, zero upstream change)

```bash
curl -X PUT https://<shield>/v1/tenant/me/mcp-gateway/upstreams/finance \
  -H "X-API-Key: $TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{
    "transport": "http",
    "url": "http://finance-mcp.internal:9000/mcp",
    "enforcement_backend": "inprocess",
    "isolation_ack": true
  }'
```

- `transport`: `http` (streamable) / `sse` / `stdio` (`command`+`args`+`env`).
- `enforcement_backend`: `inprocess` (co-located, fastest) or `http` (thin edge →
  central Shield; set `shield_url` + `shield_tenant_key`).
- Upstream creds go in `headers` / `env`; they're **redacted** on read.

## 2. Point agents at the gateway

```
https://<shield>/gateway/finance/mcp
```

Speaks MCP JSON-RPC: `initialize`, `tools/list` (RBAC-filtered), `tools/call`
(enforced). Identity is resolved from the **connection** (`X-API-Key` /
`X-Agent-Key` / `X-User-Role` / OAuth Bearer) — never from tool arguments.

```bash
# reader may not delete -> MCP error; the call never reaches the upstream
curl -s https://<shield>/gateway/finance/mcp \
  -H "X-API-Key: $TENANT_KEY" -H "X-User-Role: reader" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"wire_transfer","arguments":{"amt":9999}}}'
```

## 3. ⚠️ Make it non-bypassable

The gateway only enforces **what flows through it**. If agents can reach the
upstream directly, they can skip Shield. **Isolate the upstream** so it accepts
connections **only** from the gateway (firewall / private network / mTLS /
localhost-behind-the-gateway), then set `isolation_ack: true`.

Until you do, the config API and gateway logs emit a loud warning, and the route
is treated as **not truly protected**. This is a deployment property, not code —
see [mcp-runtime-enforcement.md](mcp-runtime-enforcement.md).

## Enforcement backends

| Backend | Where enforcement runs | Use when |
|---|---|---|
| `inprocess` (default) | in the gateway process (guard pipeline loaded) | gateway co-located with Shield; lowest latency |
| `http` | a central Shield data plane (`/v1/shield/tool/check` + `/tool/output`) | thin-edge gateway, scaled independently; +1 round-trip/call |

Both run the **same** checks (`core/mcp/http_enforcer.py` mirrors the in-process
surface), so switching changes only *where* enforcement runs.

## Manage routes

```bash
curl https://<shield>/v1/tenant/me/mcp-gateway/upstreams            -H "X-API-Key: $TENANT_KEY"  # list (secrets redacted)
curl https://<shield>/v1/tenant/me/mcp-gateway/upstreams/finance    -H "X-API-Key: $TENANT_KEY"  # get one
curl -X DELETE https://<shield>/v1/tenant/me/mcp-gateway/upstreams/finance -H "X-API-Key: $TENANT_KEY"
```

Deploy note: `connect_upstream` requires the `mcp` client SDK (declared in
`requirements.txt`). The gateway routes are served by the Shield data-plane app.
Set `SHIELD_GATEWAY_FAIL_OPEN=1` to allow calls when enforcement is unreachable
(default: fail closed).
