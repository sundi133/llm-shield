---
title: "JumpCloud AI Gateway: add Shield guardrails"
layout: default
nav_order: 52
permalink: /jumpcloud-mcp-setup/
description: "Put Shield in front of an MCP server registered in JumpCloud's AI Gateway. No code changes to the MCP server, no custom headers required. Deploy, register, mint an OAuth client, fill in Add Server."
---

# JumpCloud AI Gateway: add Shield guardrails
{: .no_toc }

JumpCloud's **Add Server** dialog takes a URL and an authentication method. That
is the whole integration surface, and it is enough: point it at Shield instead
of your MCP server, and Shield forwards to the server unchanged.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What you are building

```
JumpCloud AI Gateway
        |
        |  Authorization: Bearer <OAuth token>
        v
https://api.guardrails.votal.ai/gateway/{route}/mcp     <- Shield enforces here
        |
        v
https://<your-app>.up.railway.app/mcp                   <- your MCP server, unchanged
```

Your MCP server needs **no code changes**: no Shield SDK, no headers, no
awareness that it is proxied. Shield talks to it with the official MCP SDK as an
ordinary client. This is enforced by
`tests/test_mcp_upstream_needs_no_changes.py`, which drives a real MCP server
built with only the official SDK over real stdio.

JumpCloud's dialog has no custom-headers field, so identity has to travel over
OAuth. Step 3 covers that.

## Step 1: deploy an MCP server to Railway

If you already have one running publicly, skip to step 2.

This repo ships a ready-to-deploy sample at `examples/mcp_gateway/`
(`bank_upstream.py`, five tools, returns PII on purpose so output sanitization is
visible). It contains no Shield code.

1. **railway.com → New Project → Deploy from GitHub repo**, pick your fork.
2. **Settings → Source → Root Directory:** `examples/mcp_gateway`
   The `railway.json` there sets the build and `startCommand`, and
   `requirements.txt` pulls in `mcp`.
3. **Deploy**, then **Settings → Networking → Generate Domain**.
4. Nothing to configure: the server reads `$PORT` and binds `0.0.0.0`.

Verify it serves MCP at `/mcp`:

```bash
curl -s -X POST https://<your-app>.up.railway.app/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

A JSON-RPC result listing tools means it is live. Longer notes, including the
no-tunnel rationale, are in `examples/mcp_gateway/RAILWAY.md`.

## Step 2: put Shield in front of it

Register the Railway URL as an upstream behind a named route:

```bash
export SHIELD=https://api.guardrails.votal.ai
export KEY=<your tenant API key>
export ROUTE=bankco-prod

curl -s -X PUT "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"transport":"http",
       "url":"https://<your-app>.up.railway.app/mcp",
       "enforcement_backend":"inprocess",
       "isolation_ack":true}'
```

Shield now serves that server at
`https://api.guardrails.votal.ai/gateway/bankco-prod/mcp`.

Set `isolation_ack` truthfully. See [Isolation](#isolation-is-a-real-requirement).

## Step 3: create the Client ID and Client Secret

JumpCloud's dialog asks for these under **Advanced fields**. Shield is a full
OAuth 2.1 authorization server, so mint a confidential client bound to your
tenant:

```bash
curl -s -X POST "$SHIELD/oauth/register" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"client_name":"JumpCloud AI Gateway",
       "grant_types":["client_credentials"],
       "token_endpoint_auth_method":"client_secret_post",
       "scope":"shield"}'
```

The response carries `client_id` and `client_secret`. **The secret is shown
once.** Put it straight into JumpCloud rather than into a file or a chat window.

If your deployment sets `SHIELD_OAUTH_REGISTRATION_TOKEN`, add
`"initial_access_token":"<that value>"` to the body. Without it the endpoint
returns 401, which is the closed-by-default posture and is expected.

Confirm the pair works before leaving the terminal:

```bash
curl -s -X POST "$SHIELD/oauth/token" \
  -d 'grant_type=client_credentials' \
  -d "client_id=<client_id>" -d "client_secret=<client_secret>" \
  -d 'scope=shield'
```

You should get an `access_token` and `token_type: Bearer`. The token carries
your `tenant_id`, which is how Shield knows whose policies to apply. Tokens are
short-lived (600s); JumpCloud re-fetches with the same client credentials, so
there is nothing to rotate on a schedule.

Shield advertises its own metadata at
`GET /.well-known/oauth-authorization-server` if JumpCloud prefers discovery.

## Step 4: fill in Add Server

| Field | Value |
|---|---|
| **Name** | Anything, for example `Bank Core (guarded)` |
| **Prefix** | See [the prefix warning](#the-prefix-field-will-break-you) first |
| **URL** | `https://api.guardrails.votal.ai/gateway/bankco-prod/mcp` |
| **MCP authentication method** | **OAuth** |
| **Client ID** | from step 3 |
| **Client Secret** | from step 3 |
| **Scopes** | `shield` |

The only difference from registering the server directly is the URL. Everything
downstream of Shield is unchanged.

## Step 5: verify guardrails are actually running

A guardrail that has never refused anything is indistinguishable from one that
is not wired up, so confirm a **block**, not just a pass:

1. In the JumpCloud AI Gateway, ask the agent to use a low-risk tool. It should
   work exactly as before.
2. Ask it to use a tool the caller's role is not permitted to use. It should be
   refused by Shield, and the tool should not appear in the agent's tool list at
   all.
3. Check the refusal appears in Shield's audit under your tenant.

Point 2 is the demo worth showing: the same server exposes different tools to
different people, and the MCP server knows nothing about it.

---

## Three things that will bite you

### The prefix field will break you

JumpCloud prepends **Prefix** to MCP tool names. Shield's policies match on tool
name, so if the prefixed name is what reaches Shield, nothing matches and
**every call is denied**:

```
get_balance      -> allowed,  reaches upstream
BA_get_balance   -> BLOCKED:  "Role 'support' is not allowed to use tool 'BA_get_balance'"
```

That failure looks like Shield is broken rather than like a naming mismatch,
which is exactly how it will be reported to you.

Before rolling out, establish whether JumpCloud strips the prefix before
forwarding the call, or sends it through. Test with a real call and read Shield's
audit to see the tool name it actually received. If the prefix comes through,
either leave Prefix empty for guarded servers, or name your tool policies with
the prefix included.

### Per-user role needs more than client credentials

`client_credentials` is machine-to-machine. It identifies the JumpCloud gateway,
not the person behind the request, so the token carries no user role and
role-based filtering has nothing to act on.

Everything else still works: tool allowlisting per server, tool-poisoning scans,
injection detection on arguments, output sanitization, rate limits, audit. That
is a real deployment and a fine starting point.

For per-user decisions, JumpCloud needs to forward the end user's identity.
Since JumpCloud is itself the IdP, the role is already in a token they hold.
Shield verifies a signed role claim and reads it from a configurable path
(`core/identity_resolution.py` already handles Keycloak `realm_access.roles`,
Okta `groups`, Entra `roles`). This is the one thing worth asking JumpCloud
engineering for, and it is an upgrade rather than a blocker.

### Isolation is a real requirement

Shield only enforces if the upstream accepts connections **only** from the
gateway. If your Railway app stays publicly reachable, an agent that knows the
URL can call it directly and bypass every guardrail.

The registration API returns a warning when `isolation_ack` is false, and
setting it to true is an assertion you are making, not a switch that enforces
anything. Restrict the upstream by firewall, mTLS, or a shared secret the
gateway presents, and verify it before calling the deployment protected.

Raise this with your security reviewers yourself. It is the difference between a
guardrail and the appearance of one.
