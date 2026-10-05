---
title: Hosting MCP servers behind Shield
layout: default
nav_order: 20
permalink: /mcp-hosting-upstreams/
description: "Where to run your MCP servers so the hosted Shield MCP gateway can govern them: vendor servers, your own public servers, and servers that must stay on a private network."
---

# Hosting MCP servers behind Shield
{: .no_toc }

The Shield MCP gateway at `https://api.guardrails.votal.ai` governs every tool
call your agents make: it checks the call before it runs and the result before
the model sees it. Because the gateway runs in the cloud, it can only reach MCP
servers it can connect to over the internet. This guide covers where to run
your MCP servers so Shield can govern them, and how to make sure agents cannot
go around it.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Pick your case

| Your MCP server is | Examples | What to do |
|---|---|---|
| **A vendor's hosted server** | Google Drive, Gmail, JumpCloud, Higgsfield | [Register its URL](#a-vendor-hosted-servers); Shield holds the credential |
| **Your own server, and it may be reachable from the internet** | A service you deploy on Cloud Run, AWS, Azure or Railway | [Host it on HTTPS and let only Shield in](#b-your-own-server-on-the-internet) |
| **Your own server, and it must stay on your private network** | Core banking, internal databases, on-premises systems | [Run the Shield gateway inside your network](#c-servers-on-a-private-network) |

In every case agents connect to Shield, never to the server:

```
https://api.guardrails.votal.ai/gateway/<route>/mcp
```

with these headers:

| Header | Value |
|---|---|
| `X-API-Key` | your Shield tenant key |
| `X-Agent-Key` | the agent's ID in Agent Registry |
| `X-User-Role` | the role the agent acts as |

## The rule that makes it work

**Shield governs only the traffic that goes through it.** If an agent can also
reach the MCP server directly, it can skip every policy. So for each server:

- Shield holds the credential the server needs, and agents never get it; or
- the server's network accepts connections only from Shield.

When that is true, confirm it when you register the server (**the upstream is
only reachable through Shield**). Until then the console marks the server
**bypassable**.

## A. Vendor-hosted servers

Vendors such as Google, JumpCloud and Higgsfield run MCP servers on the
internet. Shield can reach them directly.

1. In the Shield console, open **MCP Gateway**, then **Add Server**.
2. Enter a short route name (for example `gdrive`), transport `http`, and the
   vendor's MCP URL.
3. Give Shield the credential:
   - **API key or token**: add it under **Headers sent to the server** (see
     [Register with a secret header](#register-with-a-secret-header)). The
     console masks it.
   - **OAuth sign-in**: select **OAuth** on the server card and follow
     [Google Workspace MCP through Shield](/mcp-oauth-google/). The same panel
     works for other OAuth providers.
4. Do not give agents the vendor's credential or URL. With the credential held
   only by Shield, the vendor's server is reachable only through Shield, so you
   can confirm isolation.

## B. Your own server on the internet

Run your MCP server on a managed HTTPS platform, for example Google Cloud Run,
AWS App Runner or ECS behind a load balancer, Azure Container Apps, Railway or
Fly.io.

1. **Serve MCP over HTTPS** using the streamable HTTP transport, on a stable
   domain (for example `https://mcp-payments.example.com/mcp`).
2. **Let only Shield in.** Use at least one of:
   - **A secret header.** Your server rejects any request that does not carry
     a header such as `X-Upstream-Key` with a long random value. Shield sends
     it on every call; nobody else has it. This works on any platform.
   - **An IP allowlist** of the Shield gateway's outbound addresses, if your
     Shield deployment publishes fixed ones. Ask your Shield contact.
3. **Register it** with the secret header (below), then confirm isolation.

A secret-header check, for a Python MCP server built with the MCP SDK:

```python
import hmac, os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

KEY = os.environ["UPSTREAM_KEY"]          # the value only Shield holds

class OnlyShield(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not hmac.compare_digest(request.headers.get("x-upstream-key", ""), KEY):
            return JSONResponse({"error": "forbidden"}, status_code=401)
        return await call_next(request)

app = mcp.streamable_http_app()           # your FastMCP server
app.add_middleware(OnlyShield)
```

### Register with a secret header

In **Add Server**, select **+ Add header** under **Headers sent to the server**,
enter the header name (for example `X-Upstream-Key`) and its value, and register.
The value is stored by Shield and always shown masked; the server card shows
how many headers it sends. Saving the server again with the header rows left
empty keeps its current headers, as long as the URL is unchanged; changing the
URL drops them, so a secret never follows a route to a different host.

Or through the API with your tenant key:

```bash
curl -s -X POST https://shield.votal.ai/v1/tenant/me/mcp/servers -H "X-API-Key: $SHIELD_TENANT_KEY" -H "Content-Type: application/json" -d '{"route":"payments","transport":"http","url":"https://mcp-payments.example.com/mcp","headers":{"X-Upstream-Key":"'"$UPSTREAM_KEY"'"},"isolation_ack":true}'
```

Set `isolation_ack` to `true` only once the server really rejects requests
without the header. The response and the console show the header masked.

## C. Servers on a private network

The hosted gateway cannot reach a server inside your private network, and it
should not need to. Run the Shield MCP gateway **inside your network**, next to
your servers, and have it send every decision to the hosted Shield:

```yaml
# gateway.yaml
team: acme-bank
log: { format: json, path: "-" }
routes:
  - route: core-banking
    transport: http
    url: http://mcp-core-banking.internal:8080/mcp
    isolation_ack: true
    enforcement_backend: http
    shield_url: "https://api.guardrails.votal.ai"
    shield_tenant_key: "<tenant key>"
```

```bash
docker run -p 8080:8080 -v $PWD/gateway.yaml:/etc/mcp-gateway/gateway.yaml shield-mcp-gateway
```

What you get:

- Your MCP servers and their credentials never leave your network.
- Every tool call and result is checked by the hosted Shield, with your
  tenant's tool policies, flow control and audit.
- Agents inside your network use `http://<gateway host>:8080/gateway/core-banking/mcp`.

Trade-offs:

- Each call makes one extra round trip to the hosted Shield.
- These routes are defined in `gateway.yaml`, so they do not appear as server
  cards on the console's MCP Gateway page.
- Keep the MCP servers reachable only from the gateway (a private subnet or
  firewall rule), so agents cannot call them directly.

See [MCP gateway: small-team edition](/mcp-gateway-lite/) for the full
configuration reference.

### If you must use a tunnel instead

If you would rather expose one private server to the hosted gateway, use a
production tunnel that checks a credential at its edge:

- **Cloudflare Tunnel** with a Cloudflare Access service token. Put the
  `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers in the route's
  `headers`, so only Shield passes Access.
- **ngrok** on a reserved domain, with a traffic policy that rejects requests
  missing your secret header.

Free tunnel addresses (for example `*.ngrok-free.dev`) change whenever the tunnel
restarts. Use them for demos, not for customers.

## Transports on the hosted gateway

Use `http` (streamable HTTP) or `sse`. A `stdio` server runs as a process on the
machine running the gateway, so use it only with the gateway you run yourself
(case C).

## Before you give agents access

For every server:

| Console shows | Do this |
|---|---|
| **bypassable** | Make the server reachable only through Shield, then confirm isolation |
| **unscanned** | Select **Scan** to audit its tool descriptions for injected instructions |
| **Unbound** | Bind a policy profile to the server |
| Agents get "Unknown agent key" | Register the agent and its tools in **Agent Registry** |

Then set your tool policies (**Tool Registry**) and, if you move data between
apps, your flow policy (**Cross-App Flow**).

## Troubleshooting

| What you see | Likely cause | Fix |
|---|---|---|
| "no upstream configured for route" | The route name in the agent's URL does not match a registered server | Check the route name on the server card |
| Tool calls fail and the server logs 401 | The server did not get the secret header or the token | Check the header count on the server card, add the header again, or check its OAuth status |
| Tool calls fail with an HTTP 500 and no message | The server rejected or dropped the call | Check the server's logs and the route's credential |
| Calls work from Shield but also from elsewhere | The server does not enforce the secret header or network rule | Fix the server, then confirm isolation |
| The server is a free tunnel and stops working | The tunnel restarted with a new address | Use a stable domain or a reserved tunnel address |
