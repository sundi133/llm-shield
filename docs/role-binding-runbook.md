---
title: "Runbook: role binding"
layout: default
nav_order: 42
permalink: /role-binding-runbook/
description: "Pick a role-binding mode, roll it out without breaking callers, and verify it is actually enforcing. Covers direct deployments and Shield behind an LLM gateway."
---

# Runbook: role binding
{: .no_toc }

How Shield decides which role an authorization decision uses, how to make that
role unforgeable, and how to verify it rather than assume it.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Pick a mode

`SHIELD_ROLE_BINDING` takes four values.

| mode | verified claim present | no verified claim | use when |
|---|---|---|---|
| `off` (default) | header wins | header wins | Shield is unreachable except from trusted callers |
| `prefer` | claim wins | header wins | migrating; you want the audit before you enforce |
| `strict` | claim wins | **no role** | every caller can present a verified credential |
| `strict_proxy` | claim wins | header accepted **only** from the trusted proxy | Shield is public, but internal callers legitimately send a role header |

The one thing to internalize: **`prefer` is not a control on a public
endpoint.** It upgrades callers that present a credential, and does nothing
about a caller that presents none. This still works under `prefer`:

```bash
curl -s "$SHIELD/guardrails/input" -H 'X-User-Role: sre_lead' -d '{"prompt":"restart checkout-api"}'
```

There is no verified claim, so there is nothing to prefer, so the header wins.

## Verify before you trust

Run these against the deployment, not a local instance. Thirty seconds, and
they are the whole claim.

**The negative test — must be refused under `strict` or `strict_proxy`:**

```bash
curl -s "$SHIELD/guardrails/input" -H 'X-User-Role: sre_lead' -H "X-API-Key: $TENANT_KEY" -d '{"prompt":"restart checkout-api"}'
```

**The positive test — must succeed under `strict_proxy`:**

```bash
curl -s "$SHIELD/guardrails/input" -H 'X-User-Role: sre_lead' -H "X-Shield-Proxy-Token: $PROXY_SECRET" -H "X-API-Key: $TENANT_KEY" -d '{"prompt":"restart checkout-api"}'
```

If the first one succeeds, role binding is not enforcing. The most common
causes, in order:

1. `SHIELD_ROLE_BINDING` is unset or `off` on the deployment you are testing.
2. Set to `strict_proxy` while `SHIELD_TRUSTED_PROXY_ONLY` is unset — the mode
   is inert by design, so it behaves as `strict`. Check the negative test is
   refused; if it is, this is not your problem.
3. The tenant has an overriding config. `SHIELD_ROLE_BINDING=off` is the
   operator kill switch and beats any tenant setting, but a tenant setting beats
   any other env value.

**Check what the decision actually recorded.** The audit carries
`role_source`, `role_verified` and `role_binding_mode` on every decision:

| `role_source` | meaning |
|---|---|
| `oidc` / `agent_token` / `mtls` | proven — a signature Shield checked |
| `proxy` | vouched — a trusted hop asserted it, nobody proved the user |
| `header` / `body` | claimed — the caller said so |
| `none` | refused or absent |

`role_verified` is true only for the first row. A `proxy` role is deliberately
not "verified", and any dashboard that treats it as such is wrong.

## Configure the IdP claim path (per tenant)

Which claim carries the role differs per IdP. Guessing fails silently: a wrong
path yields no roles, binding falls back, and the symptom looks like "binding is
broken" rather than "the path is wrong".

Ask for the known-good paths rather than guessing:

```bash
curl -s "$SHIELD_ADMIN/v1/tenant/me/identity/role-binding/presets" -H "X-API-Key: $TENANT_KEY"
```

| IdP | `role_claim` |
|---|---|
| Keycloak | `realm_access.roles` (the default) |
| Okta | `groups` |
| Entra ID | `roles` (app roles; directory groups appear as `groups`) |

Set the path, map IdP group names onto Shield role names, and list the roles
Shield should accept:

```bash
curl -X PUT "$SHIELD_ADMIN/v1/tenant/me/identity/role-binding" -H "X-API-Key: $TENANT_KEY" -H 'Content-Type: application/json' -d '{"role_claim":"groups","role_map":{"bank-payments-officers":"payments_officer"},"role_allowlist":["payments_officer","auditor"]}'
```

{: .warning }
> **Set `role_allowlist` if you are using Okta or Entra.** Their tokens carry
> *every* group the user belongs to — `all-employees`, `vpn-users`,
> `printer-access`. Without an allowlist, the first group in the token is taken
> as the role, purely because it was first. The allowlist names **Shield** role
> names and is applied after `role_map` renames them. An empty allowlist filters
> nothing, so this is opt-in.

### Namespaced claims (Auth0, custom Okta)

Auth0 and custom Okta claims are namespaced URLs, which contain dots the path
reader would otherwise treat as nesting. Bracket-quote the segment to take it
literally:

```json
{"role_claim": "[\"https://votal.ai/roles\"]"}
```

Bracket and dotted segments mix: `resource_access.["my.app"].roles`.

Read it back to see whether it is actually taking effect:

```bash
curl -s "$SHIELD_ADMIN/v1/tenant/me/identity/role-binding" -H "X-API-Key: $TENANT_KEY"
```

`effective_mode` and `env_kill_switch` are the fields to look at.
`SHIELD_ROLE_BINDING=off` overrides tenant config globally, so a tenant can have
`prefer` stored and see header roles still winning. That asymmetry is otherwise
invisible.

### One claim path, both features

`SHIELD_ROLE_CLAIM` is the deployment-wide fallback and now applies to **both**
role binding and delegation. It previously applied only to delegation, while
role binding hard-coded Keycloak's `realm_access.roles` — so pointing a
deployment at Okta fixed one path and silently not the other.

If your deployment already sets `SHIELD_ROLE_CLAIM` **and** has role binding
enabled, role binding will now honour it. That is the fix, but it is a change:
verify with the audit that `role_source` is `oidc` where you expect it, rather
than assuming.

Resolution order is tenant config, then `SHIELD_ROLE_CLAIM`, then
`realm_access.roles`.

Two behaviours to know:

- **Changes take up to 30 seconds fleet-wide.** Each replica caches the config
  for that long. The write drops the cache on the replica that served it; the
  others expire on their own.
- **A tenant may strengthen role binding, not weaken it.** If the deployment is
  `strict`, a tenant write of `off` or `prefer` is refused with `422`. Ordering
  is `off` < `prefer` < `strict_proxy` < `strict`. This applies to writes made
  through the API; configs already in Redis are read as-is.

## Configure the trusted-proxy boundary

Only needed for `strict_proxy`.

Generate a high-entropy secret:

```bash
openssl rand -base64 48
```

On Shield:

```
SHIELD_ROLE_BINDING=strict_proxy
SHIELD_TRUSTED_PROXY_ONLY=true
SHIELD_TRUSTED_PROXY_SECRET=<the secret>
SHIELD_TRUSTED_PROXY_IPS=10.0.0.0/8      # optional, further constrains
```

The proxy sends the secret as `X-Shield-Proxy-Token` on every request to
Shield.

**Why a secret and not an IP allowlist.** Under uvicorn's `proxy_headers`,
`request.client.host` is derived from the caller-controlled `X-Forwarded-For`
header and is therefore spoofable. The secret is authoritative when set; the IP
list, if also set, further constrains. With neither configured, trusted-proxy
mode trusts nobody — fail-closed.

**Blast radius.** Anything holding this secret can assert any role for any
tenant it can route to. That is the same authority the secret already carries
for mTLS-derived identity and for DPoP `htu` rewriting. Treat it as a
deployment-level trust root: injected by the proxy only, never reachable from a
client-settable header path, rotated on suspicion.

**Rotation.** Shield compares against a single secret, so rotation is a brief
two-step: set the new secret on Shield and the proxy in the same change window,
or accept a window where `strict_proxy` falls back to `strict` behaviour
(callers with verified claims keep working; header-only callers lose their
role).

## Rollout order

**Configure the proxy to inject `X-Shield-Proxy-Token` before switching
`SHIELD_ROLE_BINDING` to `strict_proxy`.**

Reversing the order fails closed, which is correct, but it drops every
header-derived role for the length of the window. Rollback is a single env
change: `SHIELD_ROLE_BINDING=off`. No data migration, no key cleanup.

## Shield behind an LLM gateway (LiteLLM)

When Shield sits behind LiteLLM, the guardrail hook is Shield's HTTP client,
not the agent. Only what the hook forwards survives, so role binding on that
path is exactly as strong as the hook's configuration.

Three tiers, and they compose without configuration — Shield already resolves
in this order.

### Tier 1 — verified. Preferred.

The agent sends its OIDC user token to LiteLLM as `X-On-Behalf-Of`. The hook
forwards it; Shield verifies the signature against the issuer's JWKS.

A bearer user token, unlike a DPoP proof, is not bound to the HTTP request, so
verification survives the gateway hop intact. **This is what makes `strict`
viable behind LiteLLM** — the role is proven, not vouched, and no proxy trust is
involved.

On Shield:

```
SHIELD_DELEGATION=optional
SHIELD_WORKLOAD_OIDC_ISSUERS=https://idp.example.com/realms/shield
SHIELD_WORKLOAD_OIDC_AUDIENCE=shield
SHIELD_ROLE_CLAIM=realm_access.roles
```

{: .warning }
> `SHIELD_WORKLOAD_OIDC_ISSUERS` must exactly match the `iss` your IdP puts in
> the token. An issuer mismatch means verification silently returns nothing and
> the role falls back — the failure looks like "role binding is broken" and is
> almost always this. Decode a real token and compare `iss` byte for byte before
> blaming anything else.

### Tier 2 — vouched. For callers with no human user token.

CI bots and service-to-service traffic that authenticate to LiteLLM by virtual
key alone.

On LiteLLM:

```
VOTAL_SHIELD_PROXY_TOKEN=<same value as SHIELD_TRUSTED_PROXY_SECRET>
```

{: .warning }
> **The role must be on the virtual key, not in a header.** The hook reads
> `metadata.shield_user_role` from the LiteLLM key the caller actually
> authenticated with. Provision it when you create the key:
>
> ```bash
> curl -X POST "$LITELLM/key/generate" -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
>   -d '{"metadata": {"shield_user_role": "ci_bot"}}'
> ```
>
> A key with no `shield_user_role` sends no role, and under `strict_proxy` that
> caller gets no grants. This is the step most likely to be missed in a
> rollout.

When `VOTAL_SHIELD_PROXY_TOKEN` is set, the hook stops forwarding **both** the
caller's `x-user-role` header and any `metadata.user_role` in the request body.
Both are caller-supplied — a client puts the second there with
`extra_body.metadata` — and asserting the hop is trusted while forwarding
either would launder the forgery through a hop Shield trusts.

That means under Tier 2 the role comes from the virtual key and nowhere else. A
caller that genuinely has a user identity should use Tier 1 instead: send the
OIDC token as `X-On-Behalf-Of` and the role is proven rather than vouched,
which outranks every source here.

Note the hook does **not** read LiteLLM's `UserAPIKeyAuth.user_role`. That field
is LiteLLM's admin model (`proxy_admin`, `internal_user`), not your RBAC role.

### Tier 3 — nothing. No role, per `strict`.

### What proof-of-possession does and does not cover here

Agent-token possession proofs (`docs/spec-agent-token-pop.md`) cannot work
through a gateway: DPoP binds a proof to the method and URI of the request, the
agent signs for `POST /v1/chat/completions` at LiteLLM, and Shield receives
`POST /guardrails/input`. The agent cannot sign for a request it does not make.

On that path the gateway authenticates itself with the shared secret and the
audit records that possession was vouched for rather than proven. The direct
paths — including `cap/mint` and `tools/call`, the endpoints that actually
authorize an action — are unaffected.

## Troubleshooting

| symptom | cause |
|---|---|
| Forged header still works | mode is `off` or `prefer`; `prefer` is not a control |
| Every request lost its role after enabling `strict_proxy` | proxy is not injecting `X-Shield-Proxy-Token`, or `SHIELD_TRUSTED_PROXY_ONLY` is unset |
| Roles work directly but not behind LiteLLM | hook is not forwarding `X-On-Behalf-Of`, or the virtual key has no `shield_user_role` |
| `role_source: header` when you expected `oidc` | issuer mismatch — decode the token and compare `iss` to `SHIELD_WORKLOAD_OIDC_ISSUERS` |
| One tenant behaves differently | tenant config at `shield:role_binding:{tenant_id}` overrides the env value unless the env is `off` |
| Role is used but `role_verified` is false | it came from the trusted proxy; that is correct and intended |

## Reference

- [Spec: proxy-trusted role header](spec-proxy-trusted-role-header.md) — design and rationale
- [Spec: IdP role-claim configuration](spec-idp-role-claim-config.md) — Okta, Entra, Google claim paths
- [FAQ: verified identity](faq-verified-identity.md) — what Shield proves and what it does not
