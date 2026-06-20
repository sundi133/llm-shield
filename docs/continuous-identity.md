---
title: Continuous Identity & Auto-Revoke
layout: default
nav_order: 18
permalink: /continuous-identity/
description: Closed-loop auto-revoke (detection to revoke) and CAEP/SSF signals so Shield interoperates with your IdP and EDR.
---

# Continuous identity, auto-revoke & CAEP/SSF
{: .no_toc }

Move agent identity from point-in-time `mint + verify` to a live, posture-aware
loop: when something is detected, Shield revokes the agent before more damage is
done, and it exchanges those decisions with your IdP/EDR over open standards.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Closed-loop auto-revoke

Normally a guardrail blocks a single request and the kill switch is a manual
action. **Auto-revoke** closes the loop: when a high-signal guardrail fires on a
request that carries a verified agent identity, Shield automatically **revokes
that agent instance** — which kills both its agent token and all of its
outstanding capability tokens — so the next action cannot execute.

### How it works

1. A trigger guardrail (default: `adversarial_detection`, `system_prompt_leak`)
   blocks a request that carries a verified agent identity (`X-Agent-Token`).
2. Shield calls `revoke_instance(agent_instance_id)`.
3. Because both `verify_agent_token` **and** `verify_cap` honour instance
   revocation, the agent's token and every cap it already minted stop verifying.
4. An `auto_revoke` telemetry event is recorded and a CAEP `session-revoked`
   signal is emitted (see section 2).

> **Burns the caps, not just the token.** A single revoke invalidates the
> instance's outstanding capability tokens — previously, revoking an instance
> stopped its token but not caps it had already minted.

### Safety

- **Off by default.** Enable with `SHIELD_ENABLE_AUTO_REVOKE=true`.
- Fires **only** when a verified agent identity is present, so plain
  tenant-key chat traffic is never affected.
- Fully defensive: a failure in the revoke path never breaks the request being
  served.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_ENABLE_AUTO_REVOKE` | _(off)_ | Master switch (`true`/`1`/`yes`). |
| `SHIELD_AUTO_REVOKE_GUARDRAILS` | `adversarial_detection,system_prompt_leak` | Comma list of guardrails that trigger a revoke. |
| `SHIELD_AUTO_REVOKE_TTL_SECONDS` | `3600` | Revocation TTL. |

After a revoke, the agent must obtain a fresh identity token to act again — a new
token is unaffected (only the revoked instance id is blocked for the TTL).

### Manual revoke — tenant self-service

A tenant can revoke its own misbehaving agent with **only its API key** — no
platform admin key:

```bash
curl -X POST "$SHIELD/v1/tenant/me/agent-auth/revoke" \
  -H "X-API-Key: <tenant-key>" -H "Content-Type: application/json" \
  -d '{"agent_instance_id": "<instance-id>", "reason": "investigating"}'
```

The instance is matched against the tenant that minted it, so a tenant can only
revoke instances it owns (revoking another tenant's instance returns 403/404).
The admin endpoint `POST /v1/shield/auth/revoke` remains for platform operators
(cross-tenant, by `agent_instance_id` / `user_sub` / `jti`).

---

## 2. CAEP / SSF — continuous signals

Auto-revoke is internal to Shield. Real environments also learn about risk from
the IdP (session killed), the EDR (device non-compliant), or the SIEM. Shield
speaks the OpenID **Shared Signals Framework (SSF)** and the **Continuous Access
Evaluation Protocol (CAEP)** so risk flows both ways.

![How Shield emits and consumes CAEP/SSF signals with your IdP, EDR and SIEM]({{ "/assets/images/caep-emit-consume.png" | relative_url }})

In plain terms: **emit** = Shield tells your other tools when it revokes an agent
(they drop it too); **consume** = your tools tell Shield when they see risk (a
compromised device, a killed user session) and Shield revokes the agent — even if
Shield itself saw nothing. Everyone reacts to the same alarm, in real time.

- **Emit** — on a revoke, Shield builds a signed CAEP `session-revoked`
  **Security Event Token (SET, RFC 8417)** and pushes it to a configured
  receiver, so the rest of your stack drops the agent too.
- **Consume** — Shield accepts pushed SETs and revokes the matching agent
  instance or user.

### Receive events (consume)

`POST /v1/shield/ssf/events` accepts a SET. A `session-revoked`,
`credential-change`, or non-compliant `device-compliance-change` event revokes
the subject (agent instance or user) in Shield. So an EDR marking a device
non-compliant, or an IdP killing a user session, instantly revokes the agent —
without Shield building any endpoint telemetry itself.

```bash
# Closed by default. Enable by setting a receiver token, then present it:
curl -s -X POST "$DP/v1/shield/ssf/events" \
  -H "Authorization: Bearer $SHIELD_SSF_RECEIVER_TOKEN" \
  -H "Content-Type: application/secevent+jwt" \
  -d '{"iss":"https://your-idp","jti":"1","iat":1,
       "events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":
                 {"subject":{"format":"opaque","agent_instance_id":"inst-123"}}}}'
# -> 202 {"status":"accepted","applied":[{"event":"session-revoked","type":"instance","id":"inst-123"}]}
```

> **Security: the receiver is closed by default.** It can revoke access, so it
> only acts when `SHIELD_SSF_RECEIVER_TOKEN` is set and presented as a bearer
> token (constant-time compared). If unset, the endpoint returns `503`. An
> optional `SHIELD_SSF_TRUSTED_ISSUERS` allowlist restricts which transmitters
> are honoured. (Production deployments should additionally verify the SET
> signature against the transmitter's JWKS.)

### Discovery

`GET /v1/shield/ssf/.well-known/ssf-configuration` returns the transmitter
metadata (issuer, supported events, delivery method) for receivers that
auto-discover.

### Configuration

| Variable | Used for | Meaning |
|---|---|---|
| `SHIELD_SSF_ISSUER` | emit | Transmitter `iss` (default `https://votal-shield`). |
| `SHIELD_SSF_AUDIENCE` | emit | SET `aud` (default `ssf-receivers`). |
| `SHIELD_SSF_PUSH_URL` | emit | Receiver endpoint to POST emitted SETs to. |
| `SHIELD_SSF_PUSH_TOKEN` | emit | Bearer token for the push (optional). |
| `SHIELD_SSF_PRIVATE_KEY` | emit | Hex Ed25519 key to sign SETs (else ephemeral). |
| `SHIELD_SSF_RECEIVER_TOKEN` | consume | Required to enable the receiver; the bearer callers must present. |
| `SHIELD_SSF_TRUSTED_ISSUERS` | consume | Optional comma list of allowed transmitter `iss`. |

Supported CAEP event types: `session-revoked`, `credential-change`,
`device-compliance-change`, `assurance-level-change`.

---

## 3. Auth telemetry

Auth decisions are counted per tenant and exposed at
`GET /v1/tenant/me/agent-auth/stats`. Relevant counters:

| Event | When |
|---|---|
| `token_issued` / `token_rejected` | agent token minted / failed verification |
| `cap_minted` / `cap_verified` | capability minted / verified |
| `cap_replay` / `cap_invalid` | replayed nonce / bad signature, expiry, or instance revoked |
| `revoke` | manual or SSF-driven revoke |
| `auto_revoke` | closed-loop auto-revoke fired |

---

## Where this fits

This is the runtime **response** layer of the Votal platform: detect (guardrails),
decide (RBAC + capabilities), and now **respond** (auto-revoke) and **interoperate**
(CAEP/SSF). It pairs with the [Developer Guide — MCP & APIs]({{ "/developer-guide-mcp/" | relative_url }})
(how agents get governed tool access) and the
[Security & Compliance evaluation]({{ "/security-evaluation/" | relative_url }}).
