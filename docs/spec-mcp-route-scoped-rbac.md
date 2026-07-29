# Spec: Route-scoped RBAC for the MCP gateway

Status: **SUPERSEDED by `docs/spec-mcp-fleet-control-plane.md`.** That spec absorbs
this one as the `rbac` section of a policy profile. Kept for the enforcement-seam
analysis and the collision test case it works through; implement the fleet spec,
not this one.

## 1. Problem & outcome

Ops can already register many upstream MCP servers per tenant — portal MCP Gateway
tab (`static/tenant.html:4777`), `POST /v1/tenant/me/mcp/servers`
(`api/routes_mcp_admin.py:229`), `PUT /v1/tenant/me/mcp-gateway/upstreams/{route}`
(`api/routes_mcp_gateway.py:90`). One gateway process fronts them all, pooled per
`(tenant_id, route)` (`core/mcp/gateway.py:129`).

But **`route` never reaches the authorization decision.** It selects the upstream
and is then dropped. Every RBAC check keys on `(agent_key, user_role, tool_name)`
against a single tenant-global tool namespace:

- `core/mcp/enforcement.py:440` `filter_tools_for_role` — filters `tools/list`
- `guardrails/agentic/rbac_guard.py:280` — the call-time `check_tool_access`
- `storage/tool_killswitch.py:92` `is_tool_disabled(tenant_id, tool_name)`

Three consequences, each worsening as ops adds servers:

1. **Cross-server privilege leak.** Two routes exposing a tool of the same name
   are indistinguishable. Granting `reader` the tool `search` for the internal
   wiki also grants `search` on every other registered server. This is a silent
   authorization bug, not a UX wart.
2. **Policy hangs off the wrong object.** `role_permissions` lives on the agent
   registry entry (`agents:{tenant_id}`), so ops registering a new server cannot
   write policy for it — they must edit every agent entry.
3. **The kill switch is fleet-wide.** Disabling `delete_record` during an incident
   disables it on all servers, when the intent was to isolate one.

`core/mcp/proxy_server.py:146` already carries a note anticipating a per-route
filter, so this is a known seam.

**Outcome.** Ops registers a server and writes its role→tool policy *on the route*.
`route:tool` is the qualified tool identity. `tools/list`, `tools/call`, and the
kill switch all resolve per route. Success condition: with routes `alpha` and
`beta` both exposing `search`, a role granted `search` on `alpha` is allowed there
and **blocked** on `beta`, and `tools/list` on `beta` omits it.

**Non-goals**
- No change to how roles are *sourced* (still `X-User-Role` / verified claim).
- No hierarchical roles, inheritance, wildcards, or per-argument policy. Exact
  tool names only, as today.
- No new console surface beyond extending the existing MCP Gateway tab.
- Not touching `resources/*` or `prompts/*` scoping — separate spec.
- No dynamic OAuth/token brokering for upstreams.

## 2. Plane & latency contract

**Both planes.** Data plane owns enforcement and the route config API; admin plane
(CPU portal) owns the ops editing surface (`admin_app.py:70,1086` already mounts
`routes_mcp_admin`).

**This touches the guard path** (`tools/call`) — the invariant applies, so the
design is built around it rather than excused.

**Latency budget: no additional network round-trip; target added p99 < 0.5 ms.**

The mechanism is the point of the design: `core/mcp/gateway.py:115` `_load_cfg`
**already** does one Redis GET of the route document on every gateway call. Policy
is stored **inside that same document**, so route-scoped RBAC resolves from a dict
already in memory. Zero new I/O.

The kill switch is the only other read. It is one `SISMEMBER` today; the route-aware
version issues one `SMISMEMBER` for both the bare and qualified member. Same single
round trip.

Net cost on `tools/call`: two dict lookups and a string concat.

Everything else here (policy editing, inventory, the permission matrix) is admin
plane, off the hot path, no guarded-traffic impact.

## 3. Data model

**No new Redis key and no new storage module.** Extending the existing document is
what buys the latency guarantee.

### Extended: `mcp_gateway:upstream:{tenant_id}:{route}` (JSON, no TTL)

Two optional fields added to the existing config:

```jsonc
{
  "transport": "http",
  "url": "https://mcp.higgsfield.ai/mcp",
  "headers": {"Authorization": "Bearer ..."},   // existing, redacted on read
  "isolation_ack": true,                        // existing

  "role_permissions": {                         // NEW — ops-owned, unqualified names
    "viewer":  ["list_jobs"],
    "creator": ["list_jobs", "generate_image"],
    "admin":   ["list_jobs", "generate_image", "generate_video"]
  },
  "policy_updated_at": 1785288596               // NEW — optimistic-concurrency token
}
```

Tool names inside `role_permissions` are stored **unqualified**. Qualification is
derived at decision time from the trusted route id. Never parse a qualified name
out of an upstream-supplied tool name — see §7.

Tri-state, and it is the backward-compatibility hinge:

| `role_permissions` | Meaning |
|---|---|
| **absent / `null`** | Route not migrated. Today's flat behavior, byte-for-byte. |
| **present, role listed** | Allow exactly those tools on this route. |
| **present, role absent** | Deny all on this route (fail-closed within the route). |
| **`{}` (explicit empty)** | Deny all roles on this route. Distinct from absent. |

### Extended: `killswitch:tools:{tenant_id}` (Redis SET, existing)

Gains qualified members alongside bare ones. `storage/tool_killswitch.py:20`
already writes bare names; those keep fleet-wide meaning forever.

| Member | Scope |
|---|---|
| `delete_record` | fleet-wide (existing, unchanged) |
| `higgsfield:generate_video` | that route only (new) |

Metadata key becomes `killswitch:meta:{tenant_id}:{member}` — unchanged shape,
the member is just sometimes qualified.

### Route-name constraint (new, required for unambiguous qualification)

`route` has no format validation today (`api/routes_mcp_admin.py:201` is a bare
`Field(...)`). `route:tool` is only unambiguous if `:` cannot appear in a route.

- **On write:** enforce `^[a-z0-9][a-z0-9_-]{0,63}$`. Reject with 422 otherwise.
- **On read:** no validation. Any pre-existing route is served exactly as today.
- A grandfathered route whose name fails the pattern has route-scoped features
  **disabled** (policy ignored, kill switch stays fleet-wide) and is flagged in
  the inventory response. It never silently half-enforces.

Route ids appear in gateway URLs, so real-world violations should be ~zero; this
is a guard, not a migration.

### Tenant scoping

Unchanged and unweakened. `tenant_id` comes from the verified `X-API-Key` via
`get_tenant_from_request` / `_require_tenant`; it is never accepted from a body or
header. Every key above is already tenant-prefixed, so route policy inherits the
existing cross-tenant isolation with no new surface: a tenant cannot name another
tenant's route because lookup is `mcp_gateway:upstream:{their_tenant}:{route}`.

## 4. API / interface

### Data plane (tenant key `X-API-Key`) — `api/routes_mcp_gateway.py`

`PUT /v1/tenant/me/mcp-gateway/upstreams/{route}` — accepts optional
`role_permissions`. Unchanged otherwise.

**New:** a focused policy sub-resource, because today's `PUT` replaces the whole
document — editing policy would force ops to re-send the upstream bearer token in
plaintext, which is how credentials get pasted into shell history.

```
GET    /v1/tenant/me/mcp-gateway/upstreams/{route}/policy
PUT    /v1/tenant/me/mcp-gateway/upstreams/{route}/policy
DELETE /v1/tenant/me/mcp-gateway/upstreams/{route}/policy   → revert to flat behavior
```

`PUT` request:
```jsonc
{
  "role_permissions": {"viewer": ["list_jobs"]},
  "if_policy_updated_at": 1785288596   // optional; 409 on mismatch
}
```

Response `200`: `{route, role_permissions, policy_updated_at}` — never echoes
`headers`/`env`.

Status codes: `200` ok · `404` unknown route · `409` concurrent-write conflict ·
`422` bad role/tool shape or invalid route name.

Writes call the existing `gateway_router.invalidate(tenant_id, route)`
(`api/routes_mcp_gateway.py:100`) and are audited via `log_admin_action`.

### Admin plane (portal) — `api/routes_mcp_admin.py`

- `GET /v1/tenant/me/mcp/inventory` — each server gains `role_permissions`,
  `policy_enabled: bool`, and `route_name_valid: bool`.
- **New** `PUT /v1/tenant/me/mcp/servers/{route}/policy` — portal-session
  equivalent of the above.
- **New** `POST /v1/tenant/me/mcp/tools/{tool_name}/disable` gains optional body
  field `route`. Omitted → fleet-wide (today's behavior). Present → qualified
  member only. Same for `/enable`.

### Enforcement seam (internal)

`route` becomes an **optional keyword** on the two decision entry points. Default
`None` reproduces current behavior exactly, so every existing caller (REST tool
routes, embedded server, lite gateway) is unaffected and needs no edit.

```python
# core/mcp/enforcement.py
async def enforce_tool_call(..., route: Optional[str] = None, ...)
def filter_tools_for_role(..., route: Optional[str] = None, route_policy: Optional[dict] = None)
```

Threading: `core/mcp/gateway.py:186` already holds `route` → pass to
`core/mcp/proxy_server.py:89` `call_tool` → `enforce_tool_call` at
`proxy_server.py:109`. The route policy dict is read off the already-loaded `cfg`.

**Resolution order** (first match wins):

1. `SHIELD_MCP_ROUTE_RBAC=0` → skip entirely, use flat path.
2. Route name invalid (grandfathered) → flat path, warn.
3. `role_permissions` present on the route → decide from it, deny-by-default.
4. Otherwise → existing registry / `core.rbac` fallback, unchanged.

Step 4 is verbatim today's code path, which is what makes this non-breaking.

## 5. Security & backward compatibility

**Opt-in, per route.** A route without `role_permissions` behaves exactly as it
does today. There is no tenant-wide flag day and no default change. Enabling is a
deliberate per-route `PUT`.

**Escape hatch:** `SHIELD_MCP_ROUTE_RBAC=0` (default `1`) disables route-scoped
resolution process-wide and falls back to flat RBAC, for rollback without a
config rewrite. Documented in `docs/mcp-gateway.md` env-flags table.

**Migration note.** Adopting route policy is *tightening*: a role that could reach
a tool by global name may lose it on routes where it isn't listed. That is the
entire point, but it is a behavior change for that route, so the portal must warn
before the first save and the docs must say it plainly. Suggested path: use the
inventory's effective-permission matrix to copy current effective grants into the
route policy, verify, then narrow.

**Authz.** Policy writes require the tenant key (data plane) or an authenticated
portal session (admin plane); `tenant_id` is always the verified one. A malicious
caller with a valid tenant key can edit **only their own** routes — the same
authority they already have to repoint the upstream URL entirely, so this grants
no new power. A caller without a tenant key can do nothing (`-32001`).

**What this does not fix.** Route-scoped RBAC is still only as good as leg-2
isolation. A route with `isolation_ack: false` is bypassable regardless of how
precise its policy is. The portal must not present a policy editor as protection
on a non-isolated route — show the existing isolation warning alongside it.

## 6. Packaging & deploy

**No new pip dependency.** No `requirements.txt` / `requirements-test.txt` /
`requirements-admin.txt` change.

**No `Dockerfile.admin` change**, by design — the spec deliberately adds no new
storage module. Every file touched is already in the COPY allowlist:
`api/routes_mcp_admin.py:92`, `storage/mcp_gateway_store.py:122`,
`storage/tool_killswitch.py:106`. `tests/test_admin_dockerfile_imports.py` remains
the guard; if review pushes a new module, it lands in the **same PR** as its COPY
line.

**Redis:** `SMISMEMBER` requires Redis ≥ 6.2. Upstash and Redis 7 both support it.
Task 3 must include a capability probe falling back to two `SISMEMBER` calls, so
an older self-hosted Redis degrades in latency, never in correctness.

**Rebuild:** data-plane image (enforcement + gateway routes) and admin image
(portal UI + admin routes). No ordering constraint between them — an old admin
image simply cannot edit policy; an old data plane ignores a policy field it does
not know. Both directions are safe, so the two images can roll independently.

**Env flags:** `SHIELD_MCP_ROUTE_RBAC` (default `1`).

## 7. Failure modes & edge cases

| Condition | Behavior | Rationale |
|---|---|---|
| Redis down on `_load_cfg` | Existing failure (`-32004`/`-32603`) | Unchanged; policy inherits it |
| Redis down on kill-switch read | Fail-**open**, unchanged | `_killswitch_blocks` (`core/mcp/enforcement.py:493`) already swallows and returns `False`. Preserve exactly — do not "fix" it here |
| Route policy present, role absent | **Deny all** on that route | Fail-closed *within* an explicitly configured route |
| `role_permissions: {}` | Deny all roles | Explicit empty ≠ absent. Distinct branch, distinct test |
| `role_permissions: null` | Flat path | Same as absent |
| Role listed with `[]` | Deny all for that role | Consistent with above |
| Upstream advertises tool named `foo:bar` | Matched **literally** against policy; never split on `:` | A poisoned upstream must not forge a qualified identity. Qualification is composed gateway-side from the trusted route id only |
| Grandfathered route name with `:` | Flat path + `route_name_valid: false` in inventory | Never half-enforce |
| Route policy names a tool the upstream doesn't expose | Silently unused | Upstreams change; a stale entry must not error |
| Upstream returns 0 tools | Empty list, no crash | Existing behavior |
| Huge policy (1000 roles × 1000 tools) | Cap at 200 roles / 2000 tools per route, `422` past that | Bounds the hot-path document size |
| Concurrent policy + credential writes | `409` when `if_policy_updated_at` is sent and stale | Read-modify-write on a shared document; opt-in guard |
| Concurrent policy writes, no token | Last-write-wins, audited | Matches existing `set_upstream` semantics |
| Pooled connection after policy change | `invalidate(tenant_id, route)` on write | Reuses the existing invalidation |
| `SMISMEMBER` unsupported | Fall back to two `SISMEMBER` | Correctness over latency |

**Fail-open vs fail-closed, stated:** authorization is **fail-closed** once a route
has a policy (unknown role → deny). Infrastructure failures keep their **existing**
posture — the kill switch stays fail-open on a Redis error because that is today's
behavior and changing it is a separate, riskier decision that does not belong in
this spec.

## 8. Test plan (Definition of Done)

New `tests/test_mcp_route_scoped_rbac.py`, plus additions to
`tests/test_mcp_enforcement.py`, `tests/test_mcp_gateway.py`,
`tests/test_mcp_admin_console.py`.

**The headline test — the bug this spec exists to fix:**
routes `alpha` and `beta` both expose `search`; `alpha` grants it to `reader`,
`beta` does not. Assert `tools/call search` on `alpha` allows, on `beta` blocks,
and `tools/list` on `beta` omits `search`.

**Backward compatibility (non-negotiable):**
- Route with no `role_permissions` produces decisions **identical** to `main` for
  allow, block, and `tools/list` filtering.
- `enforce_tool_call` / `filter_tools_for_role` called without `route` behave as
  before — covers REST tool routes, embedded server, lite gateway.
- `SHIELD_MCP_ROUTE_RBAC=0` fully restores flat behavior on a policied route.

**Per §7:** one test each for absent / `{}` / `null` / role-absent / role-`[]`,
literal `foo:bar` tool name, grandfathered route with `:`, policy naming an absent
tool, Redis-down fail-open on the kill switch, oversized policy `422`, `409` on
stale `if_policy_updated_at`.

**Kill switch:** bare member stays fleet-wide; qualified member affects one route;
both present; `SMISMEMBER`-unsupported fallback path.

**API:** `PUT`/`GET`/`DELETE` policy round-trip; `404` unknown route; `422` invalid
route name and bad shape; secrets never echoed in a policy response; cross-tenant
read/write of another tenant's route returns `404`.

**Regression guards:**
- `tests/test_admin_dockerfile_imports.py` must stay green (proves no undeclared
  admin import crept in).
- Assert `enforce_tool_call`'s new parameter is keyword-only with default `None`,
  so a future positional arg can't silently reorder call sites.
- Assert the route-name pattern is applied on write and **not** on read.

**Latency:** a test asserting the number of Redis calls per `tools/call` is
unchanged versus the no-policy path — this is the §2 contract, so it gets an
executable guard rather than a promise.

**Green bar:** `python -m pytest tests -q` fully green in a **clean venv**
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`), and
the `pytest` CI gate passes.

## 9. Task breakdown (one PR each, in order)

| # | Task | Touches | Ships |
|---|---|---|---|
| 1 | Route-name validation + `role_permissions` on the route doc + policy sub-resource | `storage/mcp_gateway_store.py`, `api/routes_mcp_gateway.py` | Storage + API only. **No enforcement change** — policy is inert. Independently mergeable and safe |
| 2 | Thread `route` into the decision; resolution order; `SHIELD_MCP_ROUTE_RBAC` | `core/mcp/gateway.py`, `core/mcp/proxy_server.py`, `core/mcp/enforcement.py` | The actual fix, incl. the headline collision test |
| 3 | Route-scoped kill switch | `storage/tool_killswitch.py`, `api/routes_mcp_admin.py` | Qualified members, `SMISMEMBER` + fallback |
| 4 | Portal: per-route policy editor + effective-permission matrix | `static/tenant.html`, `api/routes_mcp_admin.py` | The ops surface; carries the tightening warning and the `isolation_ack` warning |
| 5 | Docs | `docs/mcp-gateway.md`, `docs/developer-guide-mcp.md` | Route-scoped RBAC section, env flag, migration note |

Task 2 is where the risk is — it is the only one on the guard path. Tasks 1 and 3
are additive; 4 and 5 are admin/docs. Recommend landing 1 and 2, verifying against
a real two-route setup, then 3–5.
