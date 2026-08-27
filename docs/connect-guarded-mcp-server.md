---
title: "Connect a guarded MCP server"
layout: default
nav_order: 63
permalink: /connect-guarded-mcp-server/
description: "Integration handout for a partner AI gateway team. Five fields in the Add Server dialog, one verification call, and what to expect when policy is working. No SDK, no OpenAPI spec, no code changes."
---

# Connect a guarded MCP server
{: .no_toc }

Your MCP server keeps working exactly as it does today. Point your AI gateway at a
Shield route instead of at the server directly, and every tool call is screened on
the way in and redacted on the way out.
{: .fs-6 .fw-300 }

**Five fields. No SDK, no OpenAPI spec, no code changes on either side.**

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What you are connecting to

```
Your AI gateway
      |
      v
https://api.guardrails.votal.ai/gateway/{route}/mcp    <- Shield enforces here
      |
      v
your MCP server                                        <- unchanged
```

Shield speaks MCP to your server as an ordinary client, using the official SDK.
Your server never knows it is proxied.

## Add Server: five fields

This is the entire integration surface. Only two rows carry real values.

| Field | Value |
|---|---|
| **Name** | Anything you like, for example `Bank Core (guarded)` |
| **Prefix** | Required by the dialog, but cosmetic. It does not change the tool names Shield sees. |
| **URL** | `https://api.guardrails.votal.ai/gateway/{route}/mcp` |
| **MCP authentication method** | **API Token**, set to the tenant key we provide |
| Client ID / Secret / Scopes | Leave empty. See [Use API Token, not OAuth](#use-api-token-not-oauth). |

## Confirm it works

Tool discovery happens at runtime over JSON-RPC. Ask the gateway what it offers and
you get the live, permission-filtered list back.

```bash
curl -s -X POST "https://api.guardrails.votal.ai/gateway/{route}/mcp" \
  -H "X-API-Key: <tenant key>" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

A JSON-RPC result listing tools means you are connected. That list is already
filtered by role, so a tool this connection may not use is not merely blocked, it is
never offered.

## What to expect

**Normal calls pass.** A well-formed request for one specific record goes straight
through. Latency is a single added hop.

**Sensitive fields come back masked.** A record may return with a card as
`**** **** **** 1111` and the CVV removed. That is policy working, not an error. Do
not retry.

**Unsafe calls are refused.** Bulk pulls, injection, and requests for unauthorized
fields return a JSON-RPC error beginning `Blocked by Shield:` followed by the
reason. The call never reaches the MCP server. Surface the reason to the user rather
than retrying, because a retry of the same argument will be refused again.

## If something looks wrong

| Symptom | Cause | Fix |
|---|---|---|
| Tool list is empty | The agent was granted prefixed tool names, or was not granted any | Grant the **unprefixed** names. The Prefix field is cosmetic. |
| Tools list, but every call is denied | Connected over OAuth, or the agent is not registered | Use **API Token** auth. Confirm the agent is registered on the Shield side. |
| `Session terminated` | Driving MCP with plain `curl` without a session | Expected. Use an MCP client, or the single `tools/list` call above. |

### Use API Token, not OAuth

Shield is a full OAuth 2.1 authorization server and the token exchange itself
succeeds, but the identity it derives cannot currently be governed: the subject
contains colons, which the agent registry rejects. The result is a connection where
tools appear in the list and every call is denied. API Token is the supported path
today.

## Common questions

**Do you need an OpenAPI spec?** No. MCP is JSON-RPC, not REST. Tools are discovered
at runtime through `tools/list`, so there is no spec to import, host, or keep in
sync.

**Do you change the MCP server?** No. No SDK, no headers, no awareness of the proxy.
Shield connects to it with the standard MCP client, exactly as any other consumer
would.

**What gets logged?** Every allow, redact, and block is recorded in the tenant
telemetry, with the tool name, the route, and the decision.

---

## Reference: Shield-side setup

Included so the whole picture is visible. These steps are run once by the Shield
operator before the connection is handed over. The gateway team does not run them.

```bash
export SHIELD=https://api.guardrails.votal.ai
export KEY=<tenant API key>
export ROUTE=<route name>
export UPSTREAM=https://<your-app>/mcp
```

**1. Register the MCP server behind a named route**

```bash
curl -s -X PUT "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d "{\"transport\":\"http\",\"url\":\"$UPSTREAM\",
       \"enforcement_backend\":\"inprocess\",\"isolation_ack\":true}"
```

**2. Register the agent and grant it tools, using unprefixed names**

```bash
curl -s -X POST "$SHIELD/v1/agents/registry" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"agent_id":"mcp-agent",
       "tools":["account_balance_get","customer_profile_get","card_details_get"],
       "role_permissions":{"":["account_balance_get","customer_profile_get"]}}'
```

The empty role `""` is what a connection with no user role resolves to. Give it only
the safe subset: anything left out is both invisible and unusable.

**3. Apply the data policy**

```bash
curl -s -X POST "$SHIELD/v1/data-policies/global/policy" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  --data @saas/examples/mcp_input_protection_policy.json
```

Input rules refuse the call. Output rules redact the result.

**4. Verify, then hand over the URL and key**

```bash
curl -s "$SHIELD/v1/tenant/me/telemetry?limit=10" -H "X-API-Key: $KEY"
```

Treat the tenant key as a credential: it authenticates the connection and scopes it
to one tenant.

## Related

- [JumpCloud AI Gateway: add Shield guardrails](/jumpcloud-mcp-setup/) for the full operator walkthrough
- [MCP input protection: a demo runbook](/mcp-input-protection-demo/) for what the policy stops
- [Tool Data Policies](/tool-data-policies/) for per-tool rules
