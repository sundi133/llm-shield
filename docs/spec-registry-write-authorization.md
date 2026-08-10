---
title: "Spec: registry write authorization"
layout: default
nav_order: 47
permalink: /spec-registry-write-authorization/
description: "Today the credential an agent uses to ask permission is the same credential that can grant it. Scoped keys and constrained self-registration close that, without a ticket queue between a developer and their first agent."
---

# Spec: registry write authorization
{: .no_toc }

An agent must hold a tenant API key to call `/guardrails/*`. That same key can
`POST /v1/agents/registry` and grant that agent every tool. The subject of an
authorization decision can rewrite the decision.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

### What is true today

An API key resolves to a tenant and nothing else. The stored mapping is a flat
string:

```
apikey:{sha256}  →  "acme"
```

There is no scope, no role, no principal. `get_tenant_from_api_key()` in
[`api/routes_agents_registry.py`](https://github.com/sundi133/llm-shield/blob/main/api/routes_agents_registry.py)
says so deliberately:

> kept consistent with the AuthMiddleware so the same credential works for both
> /tool/check and agent registration

And `agents_registry_router` is mounted on **both** planes, including
`core/app.py`, the process every agent reaches to be guarded.

So any holder of a tenant key can:

- `POST /v1/agents/registry` — register a new agent with any tool list
- `PUT /v1/agents/registry/{id}` — widen an existing agent's grants
- `DELETE /v1/agents/registry/{id}` — remove an agent from governance entirely

Every agent holds such a key by construction. A prompt injection that reaches
any HTTP-capable tool is one request away from full tool access, and the RBAC
layer, the role binding modes, and the capability tokens all sit downstream of
a registry the attacker just rewrote.

This is not a regression. It predates the governance work and is the assumption
underneath it: an access review of grants that anyone could have self-issued is
a different and much weaker exercise than a review of grants an administrator
made.

### The gate that already exists, and what walks around it

Shield already has the right shape for this. Shadow agents are discovered, then
`POST /v1/agents/unregistered/{id}/allow` promotes them, and its docstring is
explicit that promotion means registering the agent with its tools. That is an
administrative decision with an administrative endpoint.

`POST /registry` lets a caller skip the gate and arrive pre-approved.

The enforcement half exists too. `_registry_agent_status()` hard-blocks any
agent whose status is not `active`. An agent registered as `pending` is already
inert, today, with no new enforcement code. What is missing is a reason for
anything to ever be written as `pending`.

### Outcome

Two independent controls, each off by default, that together mean a runtime
credential cannot grant itself anything:

1. **Scoped keys.** A tenant may mint `runtime` keys (guard path, registry
   read-only) and `admin` keys (registry writes). Which key wrote is
   answerable.
2. **Constrained self-registration.** A runtime key may still declare an agent
   — no ticket queue, no lost developer — but what it declares arrives
   `pending` with zero grants, and an admin promotes it.

Observable success: with `SHIELD_REGISTRY_WRITE_SCOPE=enforce`, a request
carrying a runtime-scoped key receives `403` from every registry write route,
and the tenant's agents keep running with no change to guarded traffic.

### Non-goals

- **Per-user identity inside a tenant.** Scope is a property of a key, not a
  person. Answering "which human registered this" needs an IdP-backed portal
  session and is a separate spec.
- **A request/approve workflow** with approvers, queues and notifications.
  `pending` plus the existing promote action is the whole of it here.
- **Protecting against a stolen admin key.** Stated plainly in §5.
- **Scoping any route other than the four registry writes.** Extending the same
  mechanism to policies, vault or config is deliberately deferred so this stays
  reviewable.
- **Atomic registry writes.** `agents:{tenant}` is a read-modify-write blob
  today and stays one; see §7.

## 2. Plane & latency contract

**Both planes**, because the registry router is mounted on both. The new
enforcement runs on `POST`/`PUT`/`DELETE /v1/agents/registry*` and on
`POST /v1/tenants/{id}/api-keys`.

**Does it touch the guard path?** No. `/guardrails/*`, `cap/mint` and
`tools/call` gain **zero Redis reads**. This is the central design constraint
and it drives §3.

The obvious implementation — putting `scope` into the `apikey:{hash}` value —
would place a scope read inside `resolve_tenant_by_api_key()`, which every
guarded request calls. The sidecar key in §3 avoids that: the scope is read
only inside the write routes, which are not the guard path.

One cost does land on the guard path, and it is not I/O. `core/auth.py` must
stash the key hash on `request.state` so a write route can tell which key
authenticated, since today only `tenant_id` survives the middleware. That is
one SHA-256 over a ~40-character string per authenticated request:

| | |
|---|---|
| Added SHA-256 in middleware | ~0.2 µs |
| One Redis GET, for comparison | ~200 µs |

Three orders of magnitude below a single cache-miss lookup, and no syscall. The
alternative — stashing the raw key and hashing lazily in the write route — is
free but puts a live credential on `request.state` where an unlucky exception
handler could serialize it. The hash is worth 0.2 µs.

**Budget: no measurable change to guarded throughput.** Asserted by a test that
counts Redis reads on a guarded request, in the shape of the existing
environment-scoping guard.

## 3. Data model

### Scope lives beside the key, not inside it

```
apikeyscope:{sha256}  →  "runtime" | "admin"        no TTL
```

The existing `apikey:{sha256} → tenant_id` mapping is **not touched**. That
matters three times over:

- `resolve_tenant_by_api_key()` is byte-identical, so the guard path is
  untouched by construction rather than by review.
- There is no migration. No key needs re-minting for the deploy to be safe.
- **Absent means legacy means unscoped**, which is every key that exists today.

Scope is cached in the existing `_cache_get`/`_cache_set` layer under
`apikeyscope:{hash}`, and **invalidated on write and on key removal**. A
downgrade from `admin` to `runtime` that a stale cache ignores is a control
that silently does not apply, so `set_key_scope()` and `remove_api_key()` both
`_cache_delete`.

### Tenant scoping

The hash is of the key itself, which already resolves to exactly one tenant, so
a scope record is reachable only by a caller who holds that key. There is no
tenant-prefixed enumeration and therefore no cross-tenant read to argue about.
Scope is checked **after** the tenant resolves, never as a substitute for it.

### Agent status

No new field. `status` already exists and already defaults to `active` when
absent. This spec adds one new value, `pending`, which
`_registry_agent_status()` already blocks.

## 4. API / interface

### Minting a scoped key

`POST /v1/admin/tenants/{tenant_id}/api-keys` — platform admin plane,
`X-Admin-Key`, already audited via `log_admin_action`.

```json
{ "api_key": "...", "scope": "runtime" }
```

`scope` is **optional**. Omitted means unscoped, which is exactly today's
behaviour, so the endpoint is unchanged for every existing caller. Values other
than `runtime` or `admin` are a `400`. The `scope` is recorded in the admin
audit entry alongside the action, because "who was handed an admin key" is the
question this whole spec exists to make answerable.

### Reading your own scope

`GET /v1/tenant/me/key-scope` — the tenant self-service router, `X-API-Key`.

```json
{ "scope": "runtime", "registry_write": false, "enforcement": "warn" }
```

Three fields because three different people need this: the portal hides write
controls it cannot use, a developer debugging a `403` sees why, and an operator
mid-rollout sees whether the deployment is enforcing yet. `scope` is `null` for
an unscoped key.

### Enforcement on the write routes

No new routes. `POST`, `PUT` and `DELETE` on `/v1/agents/registry*` gain a
`require_registry_write(request)` call. Refusals are `403` with a body naming
the flag and the scope, because an operator reading a deploy log needs to tell
this apart from an expired key:

```json
{"detail": "This API key is scoped 'runtime' and cannot write the agent registry. Use an admin-scoped key. (SHIELD_REGISTRY_WRITE_SCOPE=enforce)"}
```

### The portal

`static/tenant.html` authenticates with a single tenant key from
`localStorage`. Under enforcement, a tenant admin pastes an **admin**-scoped
key into the portal and their agents run with **runtime** keys. That is the
separation working as intended: the human's credential and the workload's
credential stop being the same string.

## 5. Security & backward compatibility

### Defaults change nothing

Two flags, both defaulting to today's behaviour:

| Flag | Default | Other values |
|---|---|---|
| `SHIELD_REGISTRY_WRITE_SCOPE` | `off` | `warn`, `enforce` |
| `SHIELD_REGISTRY_SELF_REGISTER` | `on` | `pending`, `off` |

`SHIELD_REGISTRY_WRITE_SCOPE`:

- **`off`** — no scope check. Byte-identical to today.
- **`warn`** — every write is allowed, and a write by a runtime or unscoped key
  emits an admin audit record and an `X-Shield-Registry-Scope-Warning` response
  header. This is the preflight: it names the callers that `enforce` would
  break, before it breaks them.
- **`enforce`** — only `admin`-scoped keys may write. Runtime keys and
  **unscoped legacy keys** are refused.

Refusing unscoped keys under `enforce` is the deliberate choice, and it is why
`warn` exists. Allowing them would make enforcement decorative, since every key
in existence today is unscoped. The migration is the same declare-then-enforce
ladder as environment scoping: mint scoped keys, run `warn` until the audit is
quiet, then `enforce`.

`SHIELD_REGISTRY_SELF_REGISTER`:

- **`on`** — today's behaviour.
- **`pending`** — a runtime or unscoped key may `POST /registry`, but the entry
  is forced to `status="pending"` with `tools=[]`, `role_permissions={}` and
  `allowed_resources=[]`, **whatever the body asked for**. An admin-scoped key
  is unaffected. No new enforcement code: `_registry_agent_status()` already
  blocks a non-active agent.
- **`off`** — runtime and unscoped keys get `403` on `POST /registry`.

`pending` is the setting that makes strict posture survive an engineering org.
A developer still runs one command and sees their agent in the portal; what
they cannot do is grant it anything.

### The sandbox

`get_tenant_from_api_key()` auto-provisions a tenant for `sk-test-*` keys so
the zero-setup quickstart works. Those keys are treated as `admin` **within the
sandbox tenant**, under every flag value. The quickstart's whole purpose is
registering an agent in a throwaway tenant, and a sandbox that requires a
key-minting ceremony is a quickstart nobody finishes.

### What a malicious caller can and cannot do

**Closed:** an injected agent holding a runtime key cannot grant itself a tool,
widen an existing agent, delete an agent to escape governance, or register a
shadow agent pre-approved. Under `pending` it can create an inert record, which
is noise in an admin queue rather than an escalation.

**Not closed, and worth saying to a customer before they discover it:** this
does not stop an attacker who has stolen an **admin** key. It converts "any
injection on any agent escalates to full tool grants" into "you must exfiltrate
a credential that is never given to an agent." That is the same bar AWS draws
between an instance role and `iam:CreateRole`, and the same one Kubernetes
draws between using a ServiceAccount and creating one. It is the right bar. It
is not a perfect one, and the docs must not imply otherwise.

Two residual paths are in scope to document, not to fix here: a tenant that
puts its admin key in a deployed agent's environment has opted back into
today's model, and an admin key in the portal is only as safe as the browser
holding it.

## 6. Packaging & deploy

**No new dependency.** Nothing here needs a library.

**No new module, on purpose.** `key_scope()`, `set_key_scope()` and the cache
invalidation go into `storage/tenant_store.py`, which owns `apikey:*` and is
already in the `Dockerfile.admin` COPY allowlist. A new `storage/api_key_scope.py`
would be tidier and would require a `Dockerfile.admin` edit, which is the
allowlist invariant and a live crash-loop risk for a file this small. Cohesion
wins.

`require_registry_write()` lives in `api/routes_agents_registry.py`, already
copied.

**Images to rebuild:** both. The data plane carries the registry router; the
admin plane carries the portal and the minting endpoint.

**Rollout order**, and it is the order that matters:

1. Deploy with both flags at their defaults. Nothing changes.
2. Mint an admin-scoped key. Paste it into the portal.
3. Mint runtime-scoped keys and roll them out to agents.
4. Set `SHIELD_REGISTRY_WRITE_SCOPE=warn`. Watch the admin audit until it is
   quiet.
5. Set `enforce`. Optionally set `SHIELD_REGISTRY_SELF_REGISTER=pending`.

## 7. Failure modes & edge cases

**Redis down during a scope read — fail CLOSED.** Under `enforce`, a scope that
cannot be read is a `503` and the write does not happen. This inverts the guard
path's usual posture and is deliberate: a refused write is recoverable by
retrying, while a wrongly-allowed write is a permanent grant that nobody
revisits. Under `off` and `warn` the same failure is ignored, so a Redis blip
cannot break a deployment that has not opted in.

**Stale cache after a downgrade.** Covered in §3 by invalidating on write and
on removal. Tested, because a scope change that does not take effect is
indistinguishable from a control that was never applied.

**Bearer-token callers.** `core/auth.py` accepts `Authorization: Bearer` as
well as `X-API-Key`. The write route must not re-read the header itself; it
reads the hash the middleware stashed, which is populated on both paths. A
route that read `X-API-Key` directly would silently exempt every Bearer caller
from enforcement, which is the exact failure this spec is about.

**`SHIELD_AUTH_ENABLED` off.** `request.state.tenant_id` is unset and
`get_tenant_from_api_key()` falls back to the header. The write route falls
back the same way, and if there is no key at all the existing `401` still
fires first.

**Null and malformed scope values.** A stored value that is neither `runtime`
nor `admin` is treated as unscoped, not as admin. Garbage must not read as
privilege.

**`pending` interacting with an existing agent.** `PUT` on an agent that is
already `active` is a write and is governed by the write scope, not by
`SELF_REGISTER`. `SELF_REGISTER` constrains creation only. Without this split,
`pending` would silently demote live agents on an unrelated update.

**Concurrent writes.** `agents:{tenant}` is read-modify-write today and this
spec does not change it. Two simultaneous registrations can still lose one.
Called out because it is now more visible, not because it is introduced here.

**Empty, huge and hostile input** to the new `scope` field: non-string, wrong
value, and oversized are all `400` at the minting endpoint.

## 8. Test plan (Definition of Done)

### Scope storage
- Round trip `runtime` and `admin`; absent reads as `None`.
- Unknown stored value reads as unscoped, **not** admin.
- Cache invalidated on `set_key_scope` and on `remove_api_key`; a downgrade
  takes effect on the very next call.
- Minting rejects a non-string scope, an unknown value, and an oversized one.
- The admin audit entry records the scope.

### Enforcement ladder
- `off`: a runtime key writes successfully. Byte-identical to today.
- `warn`: a runtime key writes successfully **and** emits an audit record and
  the warning header. An admin key emits neither.
- `enforce`: runtime → `403`; **unscoped → `403`**; admin → `200`.
- All three flag values across all four write routes, parameterised, because
  an enforcement gap on `DELETE` is the same escalation as one on `POST`.
- A `403` body names the flag and the scope.

### Self-registration
- `on`: unchanged.
- `pending`: a runtime key's `POST` lands `status="pending"` with empty tools,
  empty `role_permissions` and empty `allowed_resources`, **even when the body
  asked for tools** — the load-bearing assertion.
- `pending`: an admin key's `POST` is unaffected.
- `pending`: a `PUT` on an existing active agent does **not** demote it.
- `off`: runtime `POST` → `403`.
- End to end: an agent created under `pending` is blocked by `RBACGuard`
  through the real guard, with no new enforcement code in the path. This is the
  test that proves the reuse claim rather than asserting it.

### Guard path
- Redis reads on a guarded request are **unchanged**, counted with a spy across
  50 calls under every combination of both flags. Same shape as the existing
  environment-scoping guard.
- `resolve_tenant_by_api_key()` is asserted not to reference `apikeyscope`.

### Regression guards
- Bearer-auth callers are enforced identically to `X-API-Key` callers.
- A source-level assertion that the write routes do not read the `X-API-Key`
  header directly, which would exempt Bearer callers.
- `sk-test-*` sandbox keys write successfully under `enforce`.

### Gate
Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Task breakdown

One PR each, in order. Each is independently revertible and none changes
behaviour until PR 2 ships a flag that is off.

| # | Scope | Rough size |
|---|---|---|
| 1 | Scope storage, minting, `GET /v1/tenant/me/key-scope`. No enforcement anywhere. | small |
| 2 | Stash the key hash in `core/auth.py`; `require_registry_write()`; the `off`/`warn`/`enforce` ladder on all four routes. | medium |
| 3 | `SHIELD_REGISTRY_SELF_REGISTER`, forced `pending` with zero grants. | small |
| 4 | Portal: pending-approval queue, promote action, key-scope badge, write controls hidden for a runtime key. | medium |
| 5 | Docs: the threat this closes, the rollout ladder, and the honest limit from §5. | small |

## 10. Open decisions

1. **`enforce` refuses unscoped legacy keys.** Specified that way, with `warn`
   as the migration. The alternative — grandfathering them — is non-breaking
   and makes the control meaningless. Confirm.
2. **`sk-test-*` sandbox keys are exempt.** Keeps the quickstart working.
   Confirm, since it is a permanently open door in one shared tenant.
3. **Fail-closed on Redis down under `enforce`.** A `503` on writes during a
   Redis outage, rather than an open registry. Confirm.
4. **Scope is per key, not per principal.** Anyone holding the admin key is the
   admin. Real per-human attribution needs the portal to carry an IdP session,
   which is a larger spec. Confirm this is the right stopping point for now.
