---
title: "Spec: Tenant self-service enforce mode"
layout: default
nav_exclude: true
permalink: /specs/tenant-enforce-mode/
description: Let a tenant's SecOps see and switch their guardrail policy between monitor and enforce from the tenant portal, instead of only through the platform admin API.
---

# Spec: Tenant self-service enforce mode

> Status: **APPROVED** 2026-10-04. Task 1 (API) implemented.
> Found by the red-team harness (docs/specs/redteam-tenant-harness.md, task 3
> notes): an `unenforced (monitor mode)` result had no fix a tenant could make.

## 1. Problem & outcome

**Problem.** A tenant's guardrail policy runs in `monitor` (would-be blocks are
recorded, not enforced) or `enforce`. The mode is the `policy_mode` field of the
tenant config, read on the guard path by `core/policy_mode.resolve_mode`.
Today only the platform admin API changes it:

- `POST /v1/admin/tenants/{tenant_id}/apply-template` **lands a tenant in monitor
  mode by design** (`api/routes_policy_templates.py`), and
- `PUT /v1/admin/tenants/{tenant_id}/policy-mode` is the only way to `enforce`.

The tenant portal (`static/tenant.html`) neither shows the mode nor changes it.
So a tenant onboarded from a template is unprotected until Votal staff flip it,
SecOps cannot see that they are in monitor mode, and when the red-team harness
reports `unenforced (monitor mode)` they cannot act on it.

**Outcome.** SecOps sees the current mode in the portal's Policies tab and
switches it themselves, with the change audited (who, when, why) and taking
effect on the guard path within the tenant cache TTL.

**Observable success condition.** A tenant in monitor mode opens Policies, sees
"Monitor: would-be blocks are recorded, not enforced", clicks Enforce, and
within the propagation bound (about 2 minutes by default, §2) a red-team run that reported
`unenforced (monitor mode)` reports `caught`. The admin audit shows
`tenant_self_set_policy_mode` with before, after, actor and reason.

**Non-goals.**
- **No change to what monitor mode does.** Note the existing gap:
  `/guardrails/output` does not apply `policy_mode` (input, file, tool, MCP,
  gateway, OpenAI-compat, agent chat and LiteLLM paths do), so output blocks still enforce
  in monitor mode. The portal states this; fixing it is a separate spec.
- No auto-revert ("monitor until a date"), no per-guard mode, no per-tenant lock
  that stops a tenant leaving enforce. Possible follow-ups.
- The admin endpoints and `apply-template` are unchanged.
- No change to `PUT /v1/tenant/me/policies` (which, notably, does not call the
  key-scope guard; out of scope here).

## 2. Plane & latency contract

- **Plane: admin (CPU portal) for the UI; the route also mounts on the data
  plane** because `api/routes_tenant_self.py` is included by both `admin_app.py`
  and `core/app.py`. No new router, no new mount.
- **Guard path: not touched.** The new handler writes one field of the tenant
  config. The guard path already reads `policy_mode` from the cached tenant
  config on every request; nothing is added to `/guardrails/*`, `cap/mint` or
  `tools/call`. **Off hot path, no guarded-traffic latency impact.**
- Propagation: two caches stand between the store and the guard path: the
  middleware's per-key tenant cache (`core/middleware._CACHE_TTL_SECONDS`, 60 s)
  and, behind it, `storage/tenant_store`'s cache (`TENANT_CACHE_TTL`, default
  60 s). Worst case is their sum, 120 s by default. The API returns that bound
  (`takes_effect_within_seconds`) so the UI can say "within about 2 minutes".
  (Corrected during task 1; the draft counted only the second cache.)

## 3. Data model

- **No new Redis keys.** Reuses `tenant:{tenant_id}` (JSON tenant config), field
  `policy_mode`: `"monitor"` or `"enforce"`; absent means `enforce`
  (`resolve_mode`'s default). No TTL (persistent, as today).
- Tenant scoping: tenant id comes only from `_require_tenant(request)` (portal
  session first, then API key); the route has no tenant path parameter, so a
  caller can only change its own tenant.
- **Concurrency.** `update_tenant` is a read-modify-write of the whole blob, so
  a concurrent write (for example a policy save) can overwrite the mode change,
  or the reverse. The admin endpoint has the same exposure today. Mitigation:
  after writing, re-read the tenant bypassing the in-process cache; if
  `policy_mode` is not the requested value, return `409` ("changed by another
  write, retry"). This detects a lost mode change; it does not make the blob
  write atomic (out of scope).

## 4. API / interface

Both on `api/routes_tenant_self.py` (prefix `/v1/tenant`), auth as every
`/v1/tenant/me/*` route: portal session or `X-API-Key`.

**`GET /v1/tenant/me/policy-mode`** → `200`
```json
{"policy_mode": "monitor",
 "self_service": true,
 "takes_effect_within_seconds": 120,
 "applies_to": ["/guardrails/input", "/guardrails/file", "tool and MCP calls", "gateway", "OpenAI-compatible proxy", "agent chat", "LiteLLM"],
 "not_applied_to": ["/guardrails/output"]}
```
`404` tenant not found.

**`PUT /v1/tenant/me/policy-mode`** body `{"mode": "enforce" | "monitor", "reason": "..."}`
- `200` `{"status": "updated", "policy_mode": "...", "previous": "...", "takes_effect_within_seconds": 120}`;
  setting the current mode again is `200` with `"status": "unchanged"` and no audit row.
- `400` mode not `monitor`/`enforce`; or switching **to monitor** without a
  non-empty `reason` (max 500 chars). A reason is optional for `enforce`.
- `403` key not admin-scoped, via `core.auth.require_registry_write(request,
  tenant_id, "change the enforcement mode")` (enforced only when
  `SHIELD_REGISTRY_WRITE_SCOPE=enforce`, as for minting keys and runtime
  profiles); or self-service disabled (§5).
- `404` tenant not found. `409` lost to a concurrent write (§3).
- `503` tenant store degraded (§7); nothing written.

Audit: `log_admin_action(action="tenant_self_set_policy_mode", actor=_actor(request, tenant_id), tenant_id, source_ip, before={"policy_mode"}, after={"policy_mode"}, metadata={"reason"})`, which also feeds the tamper-evident audit chain when that is on.

**Portal (`static/tenant.html`, Policies tab):** an "Enforcement mode" panel
above the guardrail list: the current mode as a badge, one line on what monitor
means and that output guardrails still block, the propagation note, and a
button to switch. Switching to monitor asks for a reason and a confirmation;
switching to enforce asks for a confirmation. The panel is read-only (button
hidden) when `self_service` is false.

## 5. Security & backward compatibility

- **Default: additive.** Existing tenants keep their current mode; nothing flips.
  The admin API keeps working and both write the same field.
- **New tenant capability.** A tenant can now downgrade itself to monitor. It
  can already disable guards one by one in Policies, so this is not new power
  over its own tenant, but it is a one-click downgrade, hence: a required reason,
  an audit row, the same key-scope guard as other privileged tenant writes, and
  an escape hatch.
- **Escape hatch:** `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE` (`on` by default;
  `off` makes `PUT` return `403 "enforcement mode is managed by your Shield
  administrator"` and the portal panel read-only). Read from the process
  environment, never the request. Migration note: none needed; set `off` to
  keep today's admin-only behaviour.
- **What a malicious caller can do:** with a stolen tenant key under the default
  `SHIELD_REGISTRY_WRITE_SCOPE=off`, switch that tenant to monitor, which is the
  same exposure as `PUT /me/policies` today. Under `enforce`, only an
  admin-scoped key or a portal administrator can. Every change is audited with
  actor and reason.

## 6. Packaging & deploy

- **No new modules imported by `admin_app.py`.** The handler lives in
  `api/routes_tenant_self.py` and uses `core/policy_mode.py`, `core/auth.py`,
  `storage/tenant_store.py`, `storage/admin_audit.py`, all already in the
  `Dockerfile.admin` allowlist (`tests/test_admin_dockerfile_imports.py` stays
  green).
- **No new dependencies.**
- New env flag `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE` (default on). Rebuild
  both images (admin for the portal and route; data plane mounts the same router).

## 7. Failure modes & edge cases

- **Redis down / degraded:** `update_tenant` would fall back to the in-process
  memory store, so the change would live in one process and vanish on restart
  while the portal shows success. **Refuse with `503`** when the store is
  degraded (`core.auth._store_is_degraded()`); nothing written. Fail closed for
  the write; the guard path is unaffected.
- **Tenant has no `policy_mode`:** reads as `enforce`.
- **Unknown stored value** (hand-edited): `resolve_mode` already treats anything
  but `"monitor"` as `enforce`; `GET` reports the resolved mode.
- **Same mode again:** `200 unchanged`, no write, no audit row.
- **Concurrent writes:** detected lost update returns `409` (§3).
- **Reason:** trimmed; empty or whitespace for monitor is `400`; over 500 chars
  is `400`; stored only in the audit row.
- **Propagation:** guard-path processes see the change within
  the sum of both cache TTLs (§2); the response and portal say so rather than claiming
  "immediately".
- **Sandbox tenant (`sk-test-`):** behaves like any tenant (it has a config).

## 8. Test plan (Definition of Done)

`tests/test_tenant_policy_mode.py`, against the FastAPI app with the in-memory
store:
- `GET` default `enforce`; after `PUT monitor`, `GET` reports `monitor`.
- `PUT enforce` / `PUT monitor` persist `policy_mode`; `resolve_mode` on the
  stored config agrees.
- Monitor without reason → `400`; invalid mode → `400`; reason over 500 chars → `400`.
- Same mode → `200 unchanged`, no audit row.
- Audit row: action, actor, before, after, reason.
- `SHIELD_REGISTRY_WRITE_SCOPE=enforce` + runtime-scoped key → `403`; admin key → `200`.
- `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE=off` → `PUT 403`, `GET` `self_service: false`.
- Store degraded → `503`, config unchanged.
- Lost update (stored value differs after write) → `409`.
- **End to end:** `PUT monitor`, then a `/guardrails/input` call that a guard
  blocks returns `action: "monitor"` with `would_block`; `PUT enforce`, the same
  call returns `block`.
- **Regression guard:** `applies_to` / `not_applied_to` must match the routes
  that call `resolve_mode`, so the portal never misstates coverage (the test
  greps the call sites).
- Portal: `static/tenant.html` has the panel and calls both routes (string check,
  like the existing portal wiring tests).
- `tests/test_admin_dockerfile_imports.py` green; full suite green in a clean venv.

## Tasks (one small PR each, in order)

1. **API.** `GET`/`PUT /v1/tenant/me/policy-mode` with the scope guard,
   escape-hatch flag, degraded-store `503`, lost-update `409`, audit, and
   `tests/test_tenant_policy_mode.py`.
2. **Portal.** The Enforcement mode panel in the Policies tab (badge, coverage
   note, propagation note, reason and confirm), plus its wiring test.
3. **Harness pointer.** In `scripts/redteam_tenant.py`, change the
   `unenforced (monitor mode)` fix from "Not in the portal" to "Policies:
   Enforcement mode", and the coverage matrix's "ask Votal" line to match. After
   tasks 1 and 2 merge.
