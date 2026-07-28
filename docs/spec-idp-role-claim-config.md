---
title: "Spec: IdP role-claim configuration (Okta, Entra, Google)"
layout: default
nav_order: 38
permalink: /spec-idp-role-claim-config/
description: "Role binding works only against Keycloak today. The per-tenant claim configuration is unreachable because no call site passes tenant_id, nothing writes it, and delegation reads a different knob. One admin endpoint, one source of truth, one cached read on the guard path."
---

# Spec: IdP role-claim configuration (Okta, Entra, Google)
{: .no_toc }

Role binding verifies a signed role claim and ignores the forgeable
`X-User-Role` header. It works against Keycloak and nothing else, because the
configuration that would make it work elsewhere cannot be read, cannot be
written, and disagrees with the delegation path that reads the same thing.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

`core/identity_resolution.py` supports a per-tenant `role_claim` (a dotted path
into the verified claims) and `role_map` (IdP group name to Shield role). Both
are read from `shield:role_binding:{tenant_id}` in Redis. Neither is reachable.

Three defects, each independently fatal:

**D1 — no caller passes `tenant_id`, so the config is never read.**
`role_binding_config(tenant_id)` returns the env-only default at
[identity_resolution.py:172](../core/identity_resolution.py) when `tenant_id` is
falsy. Every call site passes nothing:

| call site | call |
|---|---|
| [routes_tool.py:252](../api/routes_tool.py) | `resolve_identity(request, body_agent_key=…, body_user_role=…)` |
| [routes_tool.py:648](../api/routes_tool.py) | `resolve_identity(request, body_agent_key=body.agent_key)` |
| [routes_agent_chat.py:360](../api/routes_agent_chat.py) | `resolve_identity(request, body_agent_key=…, body_user_role=…)` |
| [routes_classify_output.py:443](../api/routes_classify_output.py) | `resolve_identity(request)` |
| [middleware.py:305](../core/middleware.py) | `resolve_identity(request)` |

So `role_claim` is hardcoded to its default `realm_access.roles` in production.
That path exists only in Keycloak. Okta puts roles at `groups`, Entra ID at
`roles`, and Google puts them nowhere.

**D2 — nothing writes the key.** `shield:role_binding:{tenant_id}` has two
readers and zero writers in the repo. There is no admin route, no storage
module, no CLI. Configuring a tenant today means hand-writing JSON with
`redis-cli`.

**D3 — two sources of truth for the same claim path.** Role binding reads
`role_claim` from tenant config. Delegation reads env `SHIELD_ROLE_CLAIM` at
[delegation.py:131](../core/delegation.py). Pointing a deployment at Okta means
setting both, in two different places, or the two paths silently disagree: role
binding looks for `realm_access.roles` while delegation looks at `groups`.

### Outcome

An operator configures a tenant for Okta through one admin endpoint, and both
the role-binding and delegation paths resolve roles from the same claim. Success
condition: with `SHIELD_ROLE_BINDING=prefer` and an Okta access token carrying
`groups: ["payments_officer"]`, `/v1/shield/tool/check` decides on
`payments_officer` with `role_source=oidc` and `role_verified=true`, while an
`X-User-Role: branch_manager` header on the same request is ignored.

### Non-goals

- Google Workspace group resolution. Google ID tokens carry no groups; fetching
  them needs the Cloud Identity API, which is a separate integration with its
  own credential and latency story. Google remains agent-identity-only.
- RFC 8693 token exchange. Already handled opportunistically via the `act`
  claim.
- A portal UI. API only; the console can follow.
- Changing any default. `SHIELD_ROLE_BINDING` stays `off`.

---

## 2. Plane & latency contract

**Both planes, asymmetrically.**

- **Admin plane (CPU)** — the read/write endpoint. Off hot path, no guarded-traffic impact.
- **Data plane (GPU)** — `resolve_identity` runs inside `/v1/shield/tool/check`
  and `/guardrails/*`. **This touches the guard path** and the spec must say so
  plainly, because fixing D1 is what puts a Redis read there.

### Latency budget

Today `resolve_identity` performs **zero** Redis reads when
`SHIELD_ROLE_BINDING=off` — `role_binding_mode` short-circuits at
[identity_resolution.py:140](../core/identity_resolution.py) before touching the
store. That must remain exactly true. Deployments with binding off pay nothing.

With binding on, the current code is already worse than it looks:
`role_binding_mode` memoizes the mode in `_CACHE` for 30s, but
`role_binding_config` then issues a **second, uncached** `GET` on the same key at
[identity_resolution.py:179](../core/identity_resolution.py) for `role_claim` and
`role_map`. That is one synchronous Redis round trip per guarded request. Fixing
D1 would make it live rather than dead code, so this spec must fix the caching
in the same change.

**Contract:** cache the *whole config object* under one 30s TTL entry, not just
the mode. One Redis `GET` per tenant per 30s, amortised to roughly zero per
request. Budget: **under 1 ms added p99** to `/v1/shield/tool/check` on a cache
hit, and unchanged (0 reads) when `SHIELD_ROLE_BINDING=off`.

Related: [spec-guard-path-scale](spec-guard-path-scale.md) covers the blocking
Redis call on the async guard path. This config read must follow whatever
non-blocking pattern that spec lands, and must not introduce a second blocking
call. If that spec has not shipped, the 30s cache keeps the blocking read rare
enough to be acceptable; the two should not be merged out of order.

---

## 3. Data model

**Key:** `shield:role_binding:{tenant_id}` — unchanged, so existing hand-written
values keep working.

**Value:** JSON object.

```json
{
  "mode": "prefer",
  "role_claim": "groups",
  "role_map": {"bank-payments-officers": "payments_officer"},
  "role_allowlist": ["customer_support", "payments_officer", "fraud_analyst"],
  "updated_at": "2026-07-28T10:14:22Z",
  "updated_by": "tenant:bankco"
}
```

| field | type | default | meaning |
|---|---|---|---|
| `mode` | `off` \| `prefer` \| `strict` | env value | Per-tenant override. Env `off` still wins globally. |
| `role_claim` | string | `realm_access.roles` | Dotted path into verified claims. |
| `role_map` | object | `{}` | IdP group name to Shield role. A rename, not a filter. |
| `role_allowlist` | array | `[]` | Roles that may come from a claim. Empty means no filtering (current behavior). |
| `updated_at` / `updated_by` | string | — | Audit provenance. |

**No TTL.** This is configuration, not cache. A TTL would silently revert a
tenant to header-trusting after expiry, which is the exact failure this feature
exists to prevent.

**Tenant scoping.** `tenant_id` is resolved on the data plane at
[routes_tool.py:226](../api/routes_tool.py) from `request.state.tenant_id` or the
API key, and on the admin plane by `get_tenant_from_request`. The key prefix is
the isolation boundary; a tenant's API key resolves only to its own
`tenant_id`, so tenant A cannot read or write tenant B's binding config. The
endpoint takes no `tenant_id` parameter — it is derived from the credential,
never from the request body.

### Why `role_allowlist` is in scope

`extract_roles` does not filter to known roles, and `resolve_identity` takes
`claimed[0]` — the first role as issued
([identity_resolution.py:421](../core/identity_resolution.py)). Verified against
the current code:

```
extract_roles({'groups': ['payments_officer', 'Everyone']}, 'groups')
  -> ('payments_officer', 'Everyone')
```

Okta emits `Everyone` for every user in the org. If it lands first, that becomes
the authorization role and every tool check denies — a self-inflicted outage on
rollout day. Telling operators to write a group filter regex in Okta is a
config-in-two-systems answer to a problem Shield can solve deterministically.
With an allowlist, non-Shield groups are dropped before ordering matters.

---

## 4. API / interface

Admin plane. New router `api/routes_identity_config.py`, mounted in
`admin_app.py` alongside the other `/v1/tenant/me/*` routers.

### `GET /v1/tenant/me/identity/role-binding`

Auth: `X-API-Key` (tenant key), via `core.auth.get_tenant_from_request`.

`200`:
```json
{
  "mode": "prefer",
  "effective_mode": "prefer",
  "role_claim": "groups",
  "role_map": {"bank-payments-officers": "payments_officer"},
  "role_allowlist": ["customer_support", "payments_officer"],
  "env_kill_switch": false,
  "updated_at": "2026-07-28T10:14:22Z",
  "updated_by": "tenant:bankco"
}
```

`effective_mode` and `env_kill_switch` exist so an operator can see *why* their
`prefer` is not taking effect. `SHIELD_ROLE_BINDING=off` globally overrides
tenant config ([identity_resolution.py:140](../core/identity_resolution.py)) and
that asymmetry is otherwise invisible and infuriating to debug.

### `PUT /v1/tenant/me/identity/role-binding`

Body: any subset of `mode`, `role_claim`, `role_map`, `role_allowlist`. Merged
over the stored value; omitted fields are untouched.

| status | when |
|---|---|
| `200` | written, returns the same shape as `GET` |
| `422` | `mode` not in the enum; `role_claim` empty or over 128 chars; `role_map` over 256 entries; a key or value over 128 chars; `role_allowlist` over 256 entries |
| `503` | Redis unreachable — the write is refused, not silently dropped |

Writes call `log_admin_action` for the admin audit, matching
`routes_agentic_control_plane.py`.

### Presets

`GET /v1/tenant/me/identity/role-binding/presets` returns known-good claim
paths, so operators do not guess:

```json
{"keycloak": {"role_claim": "realm_access.roles"},
 "okta":     {"role_claim": "groups"},
 "entra":    {"role_claim": "roles"},
 "auth0":    {"role_claim": "https://<namespace>/roles", "note": "namespaced claims need the dotted-path fix"}}
```

### Internal: one source of truth for the claim path

New module `storage/role_binding_config.py` with `get_role_binding_config(tenant_id)`
and `set_role_binding_config(tenant_id, cfg)`, owning the key, the schema, the
defaults, and the 30s cache. `core/identity_resolution.py` and
`core/delegation.py` both read through it.

`core/delegation.py:_roles_from` stops reading `SHIELD_ROLE_CLAIM` directly and
takes the claim path from the resolved config. This requires threading
`tenant_id` into `resolve_delegation(request)`, which `resolve_identity` already
has in scope once D1 is fixed.

---

## 5. Security & backward compatibility

**Default behavior is unchanged.** `SHIELD_ROLE_BINDING` stays `off`. A tenant
with no stored config gets `role_claim=realm_access.roles`, `role_map={}`,
`role_allowlist=[]` — byte-identical to today's hardcoded defaults. No existing
deployment changes behavior.

**The one behavior change is intended and gated.** Fixing D1 means a tenant that
*has* written a config starts having it honored. No such tenant exists today
(nothing can write the key except by hand). Anyone who hand-wrote one wanted it
applied.

**Escape hatch.** `SHIELD_ROLE_BINDING=off` remains the global kill switch and
overrides all tenant config. A second flag, `SHIELD_ROLE_BINDING_TENANT_CONFIG=0`,
disables *reading* tenant config while leaving binding on — the rollback path if
the Redis read misbehaves on the guard path, without giving up binding
entirely.

**Migration note.** For deployments already setting `SHIELD_ROLE_CLAIM` for
delegation: the env var stays honored as the fallback when a tenant has no
stored `role_claim`, so nothing breaks. It is documented as deprecated in favor
of the endpoint. Removing it is a later, separate change.

**Authz.** Callers authenticate with a tenant API key and can only touch their
own key. A malicious tenant admin can point `role_claim` at an arbitrary claim
or map any group to any Shield role — but only within their own tenant, and only
over claims from an issuer the *operator* allow-listed via
`SHIELD_WORKLOAD_OIDC_ISSUERS`. They cannot add an issuer, so they cannot
manufacture a claim; they can only decide how their own IdP's verified claims
map to their own roles. That is the intended authority.

The worst self-inflicted case is a tenant mapping every group to
`branch_manager`. This is no worse than today, where the same tenant simply
sends `X-User-Role: branch_manager`, and unlike today it is recorded in the
admin audit with an actor and timestamp.

---

## 6. Packaging & deploy

**`Dockerfile.admin` COPY additions** (the curated allowlist — omitting these
crash-loops the admin image at boot, enforced by
`tests/test_admin_dockerfile_imports.py`):

```
COPY api/routes_identity_config.py api/
COPY storage/role_binding_config.py storage/
```

`core/identity_resolution.py` and `core/delegation.py` are already copied
(lines 57 and 58).

**Dependencies: none.** Uses `storage.tenant_store._get_redis`, `core.auth`, and
`storage.admin_audit`, all already imported by the admin plane. No
`requirements*.txt` change.

**Env flags:** `SHIELD_ROLE_BINDING_TENANT_CONFIG` (default `1`). Existing
`SHIELD_ROLE_BINDING`, `SHIELD_ROLE_CLAIM`, and the `SHIELD_WORKLOAD_OIDC_*`
family are unchanged.

**Rebuild:** both images. Admin for the new router; data plane for the
`identity_resolution` and `delegation` changes.

**Rollout:**
1. Deploy both images with `SHIELD_ROLE_BINDING=off`. Endpoint is live, nothing
   is enforced.
2. `PUT` the tenant's `role_claim` and `role_allowlist`. Still nothing enforced.
3. Set `SHIELD_ROLE_BINDING=prefer` and watch `role_source` / `header_overridden`
   in the decision audit — these already land via `audit_fields()`.
4. Move to `strict` once no legitimate caller is being overridden.

---

## 7. Failure modes & edge cases

| condition | behavior | rationale |
|---|---|---|
| Redis down on **read** | serve the last cached config; if none, fall back to env defaults | **Fail-open**, matching the existing `except: mode = env` at [identity_resolution.py:158](../core/identity_resolution.py). "Cannot read config" must not become "deny every request for every tenant". Locking out an entire deployment on a Redis blip is a worse outcome than briefly trusting a header. |
| Redis down on **write** | `503`, nothing cached as written | **Fail-closed.** A write that reports success but is not durable is how config silently reverts. |
| Stored JSON is corrupt | log once, use defaults, serve requests | Same fail-open reasoning. |
| `role_claim` path missing from claims | `extract_roles` returns `()`, falls through to the header | Existing behavior. In `strict` mode a follow-up may deny instead; out of scope here. |
| Claim value is a bare string, not a list | accepted as a single role | Already handled at [identity_resolution.py:211](../core/identity_resolution.py). IdPs differ. |
| No role survives `role_allowlist` | falls through to the header, exactly as an empty claim does | Consistent with the line above. Recorded in audit as `claimed_roles` non-empty with `role_source=header` — the signal an allowlist is misconfigured. |
| `role_map` maps to an empty string | entry dropped by `extract_roles` | Already handled at [identity_resolution.py:216](../core/identity_resolution.py). |
| Huge `role_map` (10k entries) | `422` at write; the cap is 256 | Bounds the guard-path payload. |
| Namespaced claim (`https://votal.ai/roles`) | resolves to `()` today — `_dotted` splits on `.` | Verified. Fixed in Task 3, see below. |
| Concurrent `PUT`s | last write wins | Config is small and human-edited; CAS is not worth the complexity. Documented, with `updated_at`/`updated_by` making the winner visible. |
| `core.identity_resolution` missing from an image | middleware already catches `ImportError` and warns ([middleware.py:306](../core/middleware.py)) | Preserve that guard. |
| `SHIELD_ROLE_BINDING=off` | zero Redis reads, no config module import on the request path | The hot-path contract from §2. |

---

## 8. Test plan (Definition of Done)

**Unit — `tests/test_role_binding_config.py`**
- Defaults when the key is absent match today's hardcoded values exactly.
- Round trip: `set` then `get` preserves `role_claim`, `role_map`, `role_allowlist`.
- Partial `PUT` merges rather than replacing.
- Redis down on read serves the cache; with a cold cache, serves env defaults.
- Redis down on write returns `503`.
- Corrupt JSON falls back to defaults without raising.
- Validation: bad `mode`, empty `role_claim`, oversized `role_map`, oversized `role_allowlist` all `422`.
- Cache: two `get` calls inside the TTL issue one Redis `GET`.

**Unit — `tests/test_identity_resolution.py` (extend)**
- Okta shape: `groups: ["payments_officer"]` with `role_claim=groups` resolves `payments_officer`, `role_source=oidc`, `role_verified=True`.
- Entra shape: `roles: ["payments_officer"]` with `role_claim=roles`.
- `role_allowlist` drops `Everyone` when it is issued **first**, and the surviving role is used. This is the regression that would have been the rollout outage.
- Empty `role_allowlist` preserves today's unfiltered behavior.
- `SHIELD_ROLE_BINDING=off` performs zero Redis reads (assert on a mock store).
- Tenant `mode` cannot escalate past an env kill switch of `off`.

**Unit — `tests/test_delegation.py` (extend)**
- Delegation resolves roles using the tenant's `role_claim`, not `SHIELD_ROLE_CLAIM`.
- With no stored config, `SHIELD_ROLE_CLAIM` is still honored (migration path).

**Integration — `tests/test_routes_identity_config.py`**
- `GET`/`PUT` happy path with a tenant key.
- Tenant A's key cannot read or write tenant B's config.
- `effective_mode` reports `off` and `env_kill_switch: true` when the env kill switch is set while stored `mode` is `prefer`.
- `PUT` writes an admin audit record.

**Regression guards for drift-prone couplings**
- `tests/test_admin_dockerfile_imports.py` covers the two new COPY lines automatically — confirm it fails without them before adding them.
- **New:** `tests/test_resolve_identity_call_sites.py` — AST-walk every
  `resolve_identity(` call in `api/` and `core/` and assert each passes
  `tenant_id`. D1 was silent for the life of the feature precisely because
  nothing checked. Without this guard the next call site reintroduces it.

**Gate**
- `python -m pytest tests -q` green in a clean venv
  (`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`).
- CI `pytest` gate passes.

---

## 9. Task breakdown (one PR each, in order)

**Task 1 — `storage/role_binding_config.py` + wire `tenant_id` through.**
The load-bearing change. New storage module owning the key, schema, defaults and
a 30s whole-config cache; `role_binding_config` reads through it; all five
`resolve_identity` call sites pass `tenant_id`; the second uncached Redis `GET`
is removed. Ships with the call-site AST guard and the zero-reads-when-off test.
No new endpoint, no behavior change for any tenant without stored config.

**Task 2 — `api/routes_identity_config.py` + `Dockerfile.admin`.**
`GET`/`PUT`/`presets`, mounted in `admin_app.py`, admin audit on write, both
COPY lines in the same PR. Self-contained: the image must boot from this diff
alone.

**Task 3 — one claim path for delegation, and namespaced claims.**
`core/delegation.py` reads `role_claim` from the tenant config with
`SHIELD_ROLE_CLAIM` as fallback; `role_allowlist` enforced in `extract_roles`;
`_dotted` learns bracket escaping (`["https://votal.ai/roles"]`) so Auth0 and
custom Okta claims resolve. Separable — Tasks 1 and 2 deliver working Okta and
Entra support without it.

Suggested branch: `feat/idp-role-claim-config`, off `main`, all three tasks on
the one branch as separate reviewable commits.

---

## 10. Open decisions

1. **`role_allowlist` in Task 3 or Task 1?** It is a correctness fix for the
   most likely rollout failure, which argues for landing it early. It is also
   the only piece that changes what `extract_roles` returns, which argues for
   isolating it. Proposed: Task 3, with the Okta group-filter workaround
   documented for anyone rolling out before it lands.
2. **Should `strict` deny when a claim yields no role?** Today it falls through
   to the header, which makes `strict` barely stricter than `prefer`. Arguably a
   defect, but a behavior change with its own blast radius. Proposed: out of
   scope, own spec.
3. **Portal UI.** Assumed not now.
