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

## Step 3: register an agent and grant it the tools

**Do not skip this.** Without it the gateway denies every call and reads as a
broken integration. Shield resolves an agent identity for each connection and
checks the tools that agent is granted; an unregistered agent is denied by RBAC,
and an agent granted tool names that do not exist on this upstream is denied
just the same.

Grant exactly the tool names the upstream advertises:

```bash
curl -s -X POST "$SHIELD/v1/agents/registry" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"agent_id":"mcp-agent",
       "name":"JumpCloud AI Gateway connection",
       "tools":["customer_profile_get","transaction_history",
                "statement_generate","wire_transfer_execute","email_send"],
       "role_permissions":{
         "":["customer_profile_get","transaction_history","statement_generate"],
         "support":["customer_profile_get","transaction_history","statement_generate"],
         "admin":["customer_profile_get","transaction_history","statement_generate",
                  "wire_transfer_execute","email_send"]}}'
```

`mcp-agent` is the identity Shield falls back to when a connection supplies a
tenant key but no explicit agent key. The empty role `""` is what a connection
with no user role resolves to, so give it only the safe subset: the gateway then
works while `wire_transfer_execute` stays both invisible and unusable.

Use `PUT /v1/agents/registry/mcp-agent` with the same body to update an existing
agent.

## Step 4: fill in Add Server

| Field | Value |
|---|---|
| **Name** | Anything, for example `Bank Core (guarded)` |
| **Prefix** | Required by JumpCloud, but cosmetic. Grant Shield the UNPREFIXED names. See [Grant tools by their real names](#grant-tools-by-their-real-names-not-the-prefix) |
| **URL** | `https://api.guardrails.votal.ai/gateway/bankco-prod/mcp` |
| **MCP authentication method** | **API Token**, with your tenant key |
| Client ID / Secret / Scopes | leave empty |

The only difference from registering the server directly is the URL. Everything
downstream of Shield is unchanged.

### Why not OAuth

Shield is a full OAuth 2.1 authorization server and the token exchange itself
works, but the resulting identity cannot currently be governed. Shield derives
the agent key from the token subject, and every available path yields a subject
containing colons:

| flow | resulting agent key |
|---|---|
| `client_credentials` | `oauth:client:shield-<hex>` |
| `/oauth/authorize` with `SHIELD_OAUTH_AUTO_APPROVE` | `oauth:client:shield-<hex>` |
| `/oauth/authorize` with a tenant key | `oauth:tenant:<tenant>` |

The agent registry rejects colons (`agent_id must be 1-128 characters,
alphanumeric, hyphens, or underscores only`), and `/gateway/` is not in
`ShieldMiddleware._GUARDED_PREFIXES`, so gateway traffic never records a shadow
agent either. The id can therefore be neither registered nor adopted, and every
tool call is denied while the tools still appear in the list.

Two fixes are possible, and both touch guard-path identity so both need a spec
first. Binding an explicit `agent_key` to the OAuth client at registration is
the cleaner one: it removes the colon problem and gives each connection a
nameable identity to grant tools to. Recording shadow agents on the gateway path
is smaller, since the shadow validator already accepts colons, but it leaves a
two-pass setup whose first attempt fails.

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

### Grant tools by their real names, NOT the prefix

The Prefix field is cosmetic. JumpCloud handles it entirely on its own side:
it prepends the prefix to the tool names it **displays**, and strips it again
before **calling** Shield. Shield therefore only ever sees the upstream's real,
unprefixed names, at both `tools/list` and `tools/call` time.

So grant, and write policies against, the unprefixed names. Verified end to end
on a tenant whose route serves nine tools:

```
agent granted "customer_profile_get"        -> 6 tools visible, calls work
agent granted "DEMO_customer_profile_get"   -> 0 tools visible, empty connector
```

The prefixed grant is the trap, and its failure is silent: `tools/list` filters
the upstream's unprefixed names against a grant that only contains prefixed
ones, nothing matches, and JumpCloud shows an empty connector with no error.

Use `scripts/grant_agent_tools.py` **without** `--prefix` (the flag exists for
non-JumpCloud clients that genuinely rename tools; JumpCloud is not one). It
discovers the current tools from the upstream, so it cannot miss a tool you
added:

```bash
python scripts/grant_agent_tools.py --route <route> \
    --deny wire_transfer_execute --deny credential_reset
```

`--deny` withholds a tool from non-admin roles, so it stays filtered out of the
agent's list entirely rather than merely refused on call.

### A denial is usually configuration, and the message may misdirect you

Most refusals from a fresh setup are policy working correctly, not breakage.
Read the reason text rather than the fact of the block:

| message | actual cause |
|---|---|
| `Role 'x' is not allowed to use tool 'y'` | the agent's `role_permissions` do not grant `y` to `x` |
| `Payload policy blocked ...: role 'x' is not in the allowed list` | a **data policy** on that tool lists other roles. See `GET /v1/data-policies/tools/{tool}/policy` |
| `Payload policy blocked ...: role 'x' is explicitly blocked` | that data policy sets `action: block` for `x` |
| `Output blocked by Shield data policy` | the call ran; its **output** was refused |
| `Unknown agent key: <a registered agent>` | **misleading.** The agent exists but has no RBAC role assignment. `resolve_role` reads a role map separate from the agent registry |

That last one is a real defect rather than configuration. It only appears for
roles whose data policy sets `data_classification`, since that is what activates
`data_access_guard`, so it looks intermittent and role-specific while the agent
key is identical throughout.

### Per-user role

A connection carrying only a tenant key has no user role, so it resolves to the
empty role `""`. Role-based filtering still works (that is what step 3
configures), but every caller shares one role.

For genuine per-user decisions JumpCloud must forward the end user's identity.
Since JumpCloud is itself the IdP the role is already in a token they hold, and
Shield verifies a signed role claim from a configurable path
(`core/identity_resolution.py` handles Keycloak `realm_access.roles`, Okta
`groups`, Entra `roles`). This is the thing worth asking their engineering for.

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
