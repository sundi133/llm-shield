# Spec: MCP fleet control plane v1 — SecOps catalog + server-scoped policy

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

Supersedes `docs/spec-mcp-route-scoped-rbac.md`. NHI/agent identity is **v2** (§10).

## 1. Problem & outcome

SecOps needs one place to onboard **any** MCP server — `https://mcp.higgsfield.ai/mcp`,
a vendor SaaS MCP, an internal one — and govern the fleet centrally: what each
server may expose, what screening its inputs get, what its outputs may return,
and whether its results are scanned.

The pieces exist; all are bound at the wrong scope.

| Capability | Exists at | Scoped to |
|---|---|---|
| Server catalog | `api/routes_mcp_admin.py:229` | ✅ per route |
| Input guard chain | `core/mcp/enforcement.py:325` | ❌ tenant-wide |
| Output DLP / redaction | `guardrails/agentic/tool/tool_output_sanitization.py` | ❌ tenant-wide |
| Tool-result scanning | `guardrails/agentic/tool/indirect_injection_detection.py:36` | ❌ **process-wide env var** |
| Kill switch | `storage/tool_killswitch.py:92` | ❌ fleet-wide |
| Secret vault | `storage/vault_store.py:165` | ✅ but unused by the gateway |
| Metadata scanner | `packages/shield-mcp` | ✅ but never runs on register |

So an untrusted third-party SaaS MCP and a trusted internal one get **identical**
posture, tool-result scanning is a single process-wide on/off switch, and
Higgsfield's bearer token sits in plaintext in Redis while a vault built for
exactly that goes unused.

### 1.1 The v1 scoping decision: floors, not grants

`api/routes_mcp_server.py` `_resolve_identity` resolves the caller's role as
`user_role or h.get("x-user-role")`. Middleware state wins when present, but
nothing *requires* it, so on the documented `X-API-Key` + `X-User-Role`
connection **the caller chooses its own role**. Additionally
`guardrails/agentic/rbac_guard.py:108` hardcodes `allowed_data_scopes=[]` on the
registry path (ABAC is inert), and `/v1/shield/cap/mint`
(`api/routes_agent_auth.py:219`) is never consulted by the gateway.

Therefore v1 ships only controls that are **independent of the claimed identity**:

- A **floor** is a server-scoped control enforced on every call no matter who the
  caller says it is — a tool allowlist, a redaction baseline, a result scan.
  Its security does not depend on trusting the caller. **This is v1.**
- A **grant** is "role R may call tool T". It is worth exactly as much as the
  identity behind it. **This is v2**, after identity binding.

This is not a compromise; it is the correct order. A floor built now keeps
working unchanged when grants land on top of it.

**Outcome.** SecOps authors a policy profile once, binds it to many servers, and
each bound server enforces it per-route. Observable success condition: bind
`saas-untrusted` to `higgsfield` and `vendor-x`, `internal-trusted` to `wiki`.
Then, **with an attacker-chosen `X-User-Role: admin` on every request**:
`higgsfield` exposes only its allowlisted tools in `tools/list` and blocks the
rest on `tools/call`; its outputs are redacted at the profile's baseline; its
tool results are scanned for indirect injection while `wiki`'s are not; disabling
`generate_video` on `higgsfield` leaves `vendor-x` untouched; and its bearer
token is never at rest in plaintext.

**Non-goals (v1)**
- No RBAC/ABAC grants, capability tokens, or per-user policy — §10.
- No human-approval workflow — broken on this path today (§10), unchanged here.
- No stdio sandboxing — separate spec (§10); v1 adds only the disable flag.
- No OAuth brokering; Shield stores and presents a credential, it does not run
  the authorization-code flow or refresh tokens.
- No protocol-level hardening (payload caps, batch, version pinning) — §10.
- `prompts/*` keeps today's passthrough. `resources/read` **is** covered (§3.3).
- Nothing cross-tenant. Every object is tenant-scoped.

## 2. Plane & latency contract

**Admin plane (CPU portal)** owns everything SecOps touches: profile CRUD,
binding, catalog, scans, console, effective-policy computation. `admin_app.py:70,1086`
already mounts `routes_mcp_admin`. **Data plane** owns enforcement and the
tenant-key route API.

**This touches the guard path** (`tools/call`), so the invariant governs the design.

**Budget: zero additional Redis round-trips on `tools/call`; added p99 < 0.5 ms
excluding guardrails the profile newly switches on.**

The load-bearing decision: a profile lookup at call time would add a second Redis
GET per guarded call. Instead, **effective policy is computed on write and
denormalized into the route document**, which `core/mcp/gateway.py:115` `_load_cfg`
already GETs on every call.

| Read per `tools/call` | Today | After |
|---|---|---|
| Route config | 1 GET | 1 GET (now carries `effective_policy`) |
| Profile | — | **0** (denormalized) |
| Kill switch | 1 `SISMEMBER` | 1 `SMISMEMBER` (bare + qualified) |

**Stated honestly:** turning a guardrail *on* for a server costs what that
guardrail costs. `ToolOutputSanitizationGuardrail` is `tier = "slow"` — it makes
an `async_llm_call`. A profile that enables output DLP where it was off adds an
LLM round-trip to that server's calls. That is the operator's deliberate choice,
surfaced in the console as a per-profile latency estimate. The §2 contract covers
the *plumbing*, which must be free; it does not pretend enabling a guard is free.

## 3. Data model

### 3.1 Catalog entry — extend `mcp_gateway:upstream:{tenant_id}:{route}` (JSON, no TTL)

```jsonc
{
  "transport": "http",
  "url": "https://mcp.higgsfield.ai/mcp",
  "headers": {"Authorization": "Bearer {{vault:higgsfield-token}}"},  // §3.4
  "isolation_ack": true,

  "profile_id": "saas-untrusted",     // NEW — binding
  "overrides": { ... },               // NEW — partial profile shape
  "effective_policy": { ... },        // NEW — denormalized, computed on write
  "effective_rev": 1785288596,        // NEW — profile updated_at it was built from
  "active": true,                     // NEW — false blocks traffic (§3.5)
  "scan": {"score": 82, "verdict": "pass", "critical": 0, "scanned_at": 1785288000}
}
```

`effective_policy` is the **only** field the guard path reads.

### 3.2 Policy profile — `mcp_profile:{tenant_id}:{profile_id}` (JSON, no TTL)

Every sub-shape reuses an existing vocabulary. No new policy language.

```jsonc
{
  "profile_id": "saas-untrusted",
  "description": "Third-party SaaS MCP servers",

  "tools": {                             // FLOOR — server-scoped, identity-independent
    "allow": ["list_jobs", "generate_image"],   // null = allow all
    "deny":  ["delete_account"]                 // deny wins over allow
  },

  "input_guardrails":  {"prompt_injection": {"enabled": true, "action": "block", "settings": {}}},
  "output_guardrails": {"pii_detection":    {"enabled": true, "action": "block", "settings": {}}},
  // ^ dict[str, GuardrailPolicy] — exactly storage/tenant_models.py:8

  "dlp": {
    "role_ceiling": "public",            // FLOOR — §3.3, the identity-independence trick
    "data_policies_text": null,          // null = inherit tenant policies
    "max_output_length": 20000
  },

  "result_scanning": {                   // per-server override of a process-wide env flag
    "enabled": true,
    "action": "block"                    // block | monitor
  },

  "scan_policy": {"on_register": "block_on_critical", "rescan_interval_hours": 24},
  "updated_at": 1785288596
}
```

Indexes: `mcp_profiles:{tenant_id}` (SET of ids),
`mcp_profile:routes:{tenant_id}:{profile_id}` (SET of bound routes, drives fan-out).

### 3.3 How each floor stays identity-independent

| Floor | Mechanism | Why identity can't weaken it |
|---|---|---|
| Tool allowlist / denylist | Filter `tools/list`; block `tools/call` before the guard chain | Compared against `route` + tool name only. Role is never read |
| Kill switch | Qualified `route:tool` member (§3.6) | Same |
| Input guardrails | Populate the existing `_request_configs` ContextVar (`core/mcp/enforcement.py:307`) from `effective_policy` instead of only from `tenant_config` | Config comes from the route document, not the request |
| Output DLP / redaction | **`role_ceiling` clamp** | See below |
| Tool-result scanning | Per-route override of `IndirectInjectionGuardrail` | Currently `scan_enabled()` reads env only; the override is route-derived |
| Resource-read DLP | Same sanitizer path as tool results | Same clamp applies |

**The `role_ceiling` clamp.** `ToolOutputSanitizationGuardrail` puts
`user_role` into its LLM prompt
(`guardrails/agentic/tool/tool_output_sanitization.py:50,77`), so a claimed role
influences redaction. v1 does not try to verify the role — it **clamps** it:

```
effective_role_for_dlp = min(claimed_role, profile.dlp.role_ceiling)
```

by the tenant's role ordering, applied in the gateway before the sanitizer is
called. With `role_ceiling: "public"` on `higgsfield`, a caller sending
`X-User-Role: admin` is sanitized as `public`. The claimed role can only ever
*lower* clearance, never raise it past the ceiling. A `null` ceiling means "no
clamp" — today's behavior, for routes that haven't opted in.

This is the single change that makes v1 DLP real without identity, and it is
forward-compatible: when v2 lands verified identity, the ceiling remains a
legitimate per-server maximum.

### 3.4 Credentials as vault refs

`headers` may contain `{{vault:<ref>}}`, resolved at upstream-connect time via
`storage/vault_store.py:165` `resolve_binding`, with the entry's `bindings`
checked against the upstream URL host (`mcp.higgsfield.ai`).

This fits the vault's existing contract exactly: `create_vault_entry` already
**refuses** a binding to a Shield host (`storage/vault_store.py:105`) because a
secret materializes on the leg *out* of Shield to the real upstream — precisely
gateway leg 2.

Cost note: `core/mcp/gateway.py:100` states network transports connect **per
request**, so resolution is per call and must use `decrypt_entry_cached` (already
used by `resolve_binding`). Covered by the §8 latency test. A literal header
string keeps working unchanged.

### 3.5 Onboarding scan and `active`

On register and on the rescan timer, the admin plane runs `packages/shield-mcp`
against the upstream and stores the result (§3.1). `scan_policy.on_register`:

| Value | Behavior |
|---|---|
| `off` | No scan |
| `warn` | Scan, record, always activate (default) |
| `block_on_critical` | A CRITICAL finding leaves `active: false` until SecOps overrides |

`active: false` returns the existing `-32004`, so no new failure mode reaches agents.

### 3.6 Kill switch — extend `killswitch:tools:{tenant_id}` (Redis SET, existing)

| Member | Scope |
|---|---|
| `delete_record` | fleet-wide (existing, unchanged) |
| `higgsfield:generate_video` | that route only (new) |

### 3.7 Route-name constraint

`route` has no format validation today (`api/routes_mcp_admin.py:201`), and
`route:tool` is unambiguous only if `:` cannot appear in a route.

- **On write:** `^[a-z0-9][a-z0-9_-]{0,63}$`, else `422`.
- **On read:** no validation — every pre-existing route serves exactly as today.
- A grandfathered route failing the pattern has route-scoped features **disabled**
  and is flagged in inventory. It never half-enforces.

### 3.8 Effective-policy resolution and drift

```
tenant config  ←  profile  ←  route overrides   =  effective_policy (denormalized)
```

Per-key `_deep_merge`, reusing `storage/agentic_control_plane.py:107`. Computed on
the admin plane on: profile write, route write, binding change, tenant-config write.
Fan-out walks `mcp_profile:routes:{tenant}:{profile_id}`, rewrites each bound
route's `effective_policy` + `effective_rev`, and calls the existing
`gateway_router.invalidate(tenant_id, route)` (`api/routes_mcp_gateway.py:100`).

**Drift** is the cost of denormalization, handled explicitly. On partial fan-out
failure a route carries `effective_rev` < the profile's `updated_at`. Default:
**serve the stale policy, flag drift loudly** — failing a fleet's traffic on a
fan-out hiccup is worse than briefly enforcing the previous, already-approved
policy. `SHIELD_MCP_POLICY_STRICT_REV=1` fails closed instead. A reconciler
repairs drift on a timer and on console load.

### 3.9 Tenant scoping

`tenant_id` always comes from the verified `X-API-Key` (`get_tenant_from_request`)
or portal session (`_require_tenant`), never from a body or header. Every key is
tenant-prefixed, so a tenant cannot name another tenant's profile or route.
Cross-tenant reads return `404`, not `403` (no existence oracle).

## 4. API / interface

### Admin plane (portal session) — `api/routes_mcp_admin.py`

```
GET    /v1/tenant/me/mcp/profiles                  list
POST   /v1/tenant/me/mcp/profiles                  create
GET    /v1/tenant/me/mcp/profiles/{profile_id}
PUT    /v1/tenant/me/mcp/profiles/{profile_id}     → fan-out
DELETE /v1/tenant/me/mcp/profiles/{profile_id}     409 if bound

PUT    /v1/tenant/me/mcp/servers/{route}/binding   {profile_id, overrides}
POST   /v1/tenant/me/mcp/servers/{route}/scan      scan now
POST   /v1/tenant/me/mcp/servers/{route}/activate  override block_on_critical
GET    /v1/tenant/me/mcp/fleet                     console payload (§4.3)
```

`POST /v1/tenant/me/mcp/tools/{tool_name}/disable` gains optional body field
`route`. Omitted → fleet-wide (today's behavior); present → qualified member.
Same for `/enable`.

### Data plane (tenant key `X-API-Key`) — `api/routes_mcp_gateway.py`

`PUT /v1/tenant/me/mcp-gateway/upstreams/{route}` accepts `profile_id` /
`overrides`. **New** sub-resource, so editing policy never requires re-sending
upstream credentials in a full-document `PUT` — that is how bearer tokens reach
shell history:

```
GET/PUT/DELETE /v1/tenant/me/mcp-gateway/upstreams/{route}/binding
```

`PUT` accepts optional `if_effective_rev` → `409` on conflict. Responses **never**
echo `headers` / `env` / resolved secrets.

Codes: `200` · `404` unknown route/profile · `409` conflict or bound-profile
delete · `422` invalid shape, route name, or unknown guardrail key.

### 4.3 Fleet console payload

Per server: `route`, `transport`, `url` host, `profile_id`, `active`,
`isolation_ack`, `scan` summary, `effective_rev` + `drift`, `route_name_valid`,
the **resolved effective policy** (so SecOps sees the outcome, not three layers to
merge mentally), and a **latency estimate** for the guards the profile enables.

### 4.4 Enforcement seam (internal)

`route` and `policy` become **keyword-only with `None` defaults**, so every
existing caller — REST tool routes, embedded server, `core/mcp/lite.py` — is
untouched.

```python
# core/mcp/enforcement.py
async def enforce_tool_call(..., route: Optional[str] = None, policy: Optional[dict] = None)
def filter_tools_for_role(..., route: Optional[str] = None, policy: Optional[dict] = None)
async def sanitize_tool_result(..., route: Optional[str] = None, policy: Optional[dict] = None)
```

`core/mcp/gateway.py:186` already holds both `route` and `cfg` → pass to
`core/mcp/proxy_server.py:89` `call_tool` → the enforcer at `proxy_server.py:109`
and the sanitizer at `proxy_server.py:130`.

**Resolution order** (first match wins):
1. `SHIELD_MCP_FLEET_POLICY=0` → skip, flat behavior.
2. Route name invalid (grandfathered) → flat, warn.
3. `effective_policy` present → enforce it.
4. Otherwise → today's tenant-wide path, verbatim.

Step 4 being unchanged code is what makes this non-breaking.

## 5. Security & backward compatibility

**Opt-in, per route.** No `profile_id` and no `effective_policy` → behaves exactly
as today. No flag day, no default change.

**Escape hatches:** `SHIELD_MCP_FLEET_POLICY=0` (default `1`);
`SHIELD_MCP_POLICY_STRICT_REV=1` (default `0`); `SHIELD_MCP_STDIO_ENABLED=0`
(default `1`; §10) to disable stdio upstreams on shared deployments.

**Migration.** Binding is a **tightening**: an allowlist removes tools that used
to be reachable, and a `role_ceiling` starts redacting output that previously
passed. That is the point, but it is a real per-route behavior change. Path: bind
with `tools.allow: null` and `role_ceiling: null` first (guardrails only), read
the console's resolved policy, then narrow. The console warns before the first
save that sets either.

**Authz.** Profile/binding writes need a tenant key or portal session; `tenant_id`
is always the verified one. A tenant-key holder can already repoint a route's
upstream URL entirely, so editing that route's policy grants **no new authority**.
What *is* new: a profile is multi-route, so one write can loosen many servers —
hence every profile write is audited via `log_admin_action` with a before/after
diff, and delete is blocked while routes are bound.

**Secrets.** Vault refs are strictly better than today (encrypted at rest, bound
to the upstream host, refused if bound to a Shield host). Resolved values are
never logged, never returned by any read endpoint, never in `effective_policy`.

**What v1 does not claim.** It does **not** authenticate the caller. Anyone with
the tenant key can still claim any role; v1's floors are chosen precisely so that
does not matter, and the console must state this next to the (v2) grants UI so no
operator mistakes a floor for a grant. Likewise, policy precision does not make a
directly-reachable upstream non-bypassable — a route with `isolation_ack: false`
shows the existing warning beside the policy editor.

## 6. Packaging & deploy

**New module `storage/mcp_policy_store.py` MUST be added to the `Dockerfile.admin`
COPY allowlist** — `admin_app.py` imports it via `routes_mcp_admin`, and omitting
it crash-loops the admin image at boot. The COPY line lands in the **same PR** as
the module; `tests/test_admin_dockerfile_imports.py` is the guard. Already
allowlisted and unchanged: `api/routes_mcp_admin.py:92`,
`storage/mcp_gateway_store.py:122`, `storage/tool_killswitch.py:106`,
`storage/vault_store.py:115`.

**New dependency `shield-mcp`** (scanner, §3.5), admin plane only → add to
`requirements-admin.txt` **and** `requirements-test.txt`. Not `requirements.txt`
— the data plane must not import it. The import must be **optional and guarded**:
if absent, scan verdict is `"unavailable"` and registration proceeds under `warn`.
A missing scanner must never crash the console or block onboarding.

**Redis:** `SMISMEMBER` needs ≥ 6.2 (Upstash and Redis 7 fine). Include a
capability probe falling back to two `SISMEMBER` calls — degrade in latency, never
in correctness.

**Rebuild:** admin image and data-plane image. **Roll admin first** so policy
exists before anything enforces it. Both orderings are safe (an old data plane
ignores a field it doesn't know; an old admin image can't edit profiles).

## 7. Failure modes & edge cases

| Condition | Behavior | Rationale |
|---|---|---|
| Redis down on `_load_cfg` | Existing `-32004`/`-32603` | Unchanged |
| Redis down on kill-switch read | Fail-**open**, unchanged | `_killswitch_blocks` (`core/mcp/enforcement.py:493`) already swallows → `False`. Preserve exactly; changing it is a separate decision |
| Fan-out partially fails | Serve stale + `drift: true`; strict mode fails closed | §3.8 |
| Profile deleted while bound | `409` | No orphaned `effective_policy` |
| Profile missing at recompute | Keep last `effective_policy`, flag drift | Never silently drop to no policy |
| `tools.allow: null` | Allow all (inherit) | Distinct from `[]` |
| `tools.allow: []` | Deny all on that route | Explicit empty ≠ absent |
| `tools.deny` overlaps `allow` | **Deny wins** | Least surprise for SecOps |
| Unknown guardrail key in a profile | `422` on write | Reject at the edge, never at call time |
| `role_ceiling` names an unknown role | `422` on write | Would otherwise clamp to nothing |
| `role_ceiling: null` | No clamp (today's behavior) | Opt-in |
| Output DLP enabled but LLM unreachable | Existing sanitizer error path, unchanged | Do not add a new posture here |
| Vault ref unresolvable / binding mismatch | **Fail closed** — `-32603`, audited | A silently unauthenticated upstream call is worse than an outage |
| Vault disabled + `{{vault:…}}` present | `422` on write; existing routes fail closed | Never send the literal placeholder upstream |
| Literal header (no placeholder) | Unchanged | Backward compatible |
| Scanner module absent | `verdict: "unavailable"`, registration proceeds | Optional dep must not gate onboarding |
| Scan times out / upstream `401` | `verdict: "unreachable"`, no block under `warn` | `mcp.higgsfield.ai` returns `401` without a token — the common case |
| `block_on_critical` + CRITICAL | `active: false` → `-32004` | Reuses an existing error path |
| Upstream tool literally named `foo:bar` | Matched **literally**, never split on `:` | A poisoned upstream must not forge a qualified identity |
| Grandfathered route name with `:` | Flat path + `route_name_valid: false` | Never half-enforce |
| Allowlist names a tool the upstream dropped | Silently unused | Upstreams change; stale entries must not error |
| Huge profile / fleet | Cap 2000 tools per list, 500 routes per profile; `422` past that | Bounds hot-path document size and fan-out cost |
| Concurrent binding + credential writes | `409` when `if_effective_rev` sent and stale | Read-modify-write on a shared document |
| `SMISMEMBER` unsupported | Two `SISMEMBER` | Correctness over latency |

**Fail-open vs fail-closed, stated:** the tool allowlist and credential resolution
are **fail-closed**. Infrastructure failures keep their **existing** posture — the
kill switch stays fail-open on a Redis error because that is today's behavior, and
changing it does not belong in this spec.

## 8. Test plan (Definition of Done)

New `tests/test_mcp_fleet_policy.py`, `tests/test_mcp_policy_store.py`,
`tests/test_mcp_upstream_vault_refs.py`; additions to `tests/test_mcp_enforcement.py`,
`tests/test_mcp_gateway.py`, `tests/test_mcp_admin_console.py`.

**Headline test — v1's whole thesis.** Every assertion below runs with an
attacker-chosen `X-User-Role: admin` on the request, proving the floors hold
without identity:
- `tools/list` on a route with `tools.allow` returns only allowlisted tools.
- `tools/call` on a non-allowlisted tool is blocked before the guard chain.
- `tools.deny` beats `tools.allow` for the same tool.
- With `role_ceiling: "public"`, the sanitizer receives `public`, not `admin`.
- `result_scanning.enabled` on route A scans and blocks; route B is untouched.
- Two routes exposing the same tool name are governed independently.

**Backward compatibility (non-negotiable).**
- A route with no binding produces decisions **identical to `main`** for allow,
  block, `tools/list` filtering, and output sanitization.
- `enforce_tool_call` / `filter_tools_for_role` / `sanitize_tool_result` called
  without `route`/`policy` behave as before — covers REST tool routes, embedded
  server, `core/mcp/lite.py`.
- `SHIELD_MCP_FLEET_POLICY=0` fully restores flat behavior on a bound route.
- A literal `Authorization` header still works with the vault disabled.
- `SHIELD_INDIRECT_INJECTION_SCAN` env behavior is unchanged for unbound routes.

**Resolution & drift.** Three-layer merge incl. `enabled: false` at each layer;
fan-out updates all bound routes; partial-failure drift serves stale + flags;
`SHIELD_MCP_POLICY_STRICT_REV=1` fails closed; bound-profile delete `409`s.

**Per §7:** one test each for `allow: null` vs `[]`, deny-beats-allow, unknown
guardrail key `422`, unknown `role_ceiling` `422`, vault ref unresolvable → fail
closed, vault disabled + placeholder, scanner absent, scan `401`/timeout,
`block_on_critical` → `-32004`, literal `foo:bar`, grandfathered `:` route,
oversized profile `422`, `409` on stale `if_effective_rev`, Redis-down kill-switch
fail-open.

**Kill switch:** bare member stays fleet-wide; qualified affects one route; both
present; `SMISMEMBER`-unsupported fallback.

**Security:** cross-tenant profile/route read/write → `404`; no endpoint echoes
`headers`/`env`/resolved secrets; resolved secrets absent from `effective_policy`
and logs; every profile write emits `log_admin_action` with a before/after diff.

**Regression guards.**
- `tests/test_admin_dockerfile_imports.py` green — proves the COPY line landed
  with `storage/mcp_policy_store.py`.
- Assert the new enforcement params are **keyword-only with `None` defaults**, so
  a future positional arg cannot silently reorder call sites.
- Assert the route-name pattern applies on write and **not** on read.
- **Latency contract:** assert the Redis call count per `tools/call` is unchanged
  versus the no-policy path, with and without a vault-ref header. Executable
  guard, not a promise.

**Green bar:** `python -m pytest tests -q` fully green in a **clean venv**
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`), and
the `pytest` CI gate passes.

## 9. Implementation order

Sequential reviewable commits on one branch `feat/mcp-fleet-control-plane`, one PR
(per the single-branch preference). Each phase is independently green.

| Phase | Task | Guard path? | SecOps can… |
|---|---|---|---|
| **1** | `storage/mcp_policy_store.py` + profile CRUD + **`Dockerfile.admin` COPY** + route-name validation | No | …author profiles. Inert — nothing enforces |
| **2** | Binding fields + binding sub-resource + effective-policy compute, fan-out, drift, reconciler | No | …bind profiles and see resolved policy. Still inert |
| **3** | Thread `route`+`policy` into the decision; **tool allowlist/denylist floor**; `SHIELD_MCP_FLEET_POLICY` | **Yes** | **…control which tools each server exposes.** First real enforcement |
| **4** | Per-server kill switch (`SMISMEMBER` + fallback) | Marginal | …isolate one server's tool in an incident |
| **5** | Per-server **input guardrails** via the existing `_request_configs` ContextVar | **Yes** | …screen untrusted servers' inputs strictly, internal ones loosely |
| **6** | Per-server **DLP + redaction**: route data policies + **`role_ceiling` clamp**; same for `resources/read` | **Yes** | …set a redaction floor per server |
| **7** | Per-server **tool-result scanning**: route override of the env-only injection guard | **Yes** | …scan untrusted servers' results for indirect injection |
| **8** | Vault-ref upstream credentials | Marginal | …stop storing bearer tokens in plaintext |
| **9** | Onboarding scan + rescan + `requirements-admin.txt` dep | No | …gate registration on a metadata scan |
| **10** | Fleet console: profile editor, resolved policy, drift, scan, latency estimate | No | …do all of the above without curl |

**Phases 3, 5, 6, 7 are the guard-path work and carry all the risk.** Phases 1–2
are pure setup and safe to land immediately.

Recommended checkpoints: **stop after 3** and verify against `higgsfield` plus a
second SaaS MCP — that alone is a working access-control system. **Stop after 7**
— that is the complete enterprise ask (I/O guardrails, DLP, redaction,
tool-result scanning), all identity-independent. 8–10 are hardening and UX.

## 10. v2 and separate specs

**v2 — NHI / agent identity** (the prerequisite for grants, in order):
1. **Identity binding** — a per-route `require_verified_identity` flag rejecting
   calls whose role came from a bare header rather than a verified claim. Without
   this, everything below is theater.
2. **RBAC grants** — role→tool per route, layered on v1's floors.
3. **ABAC** — revive data scopes; `guardrails/agentic/rbac_guard.py:108` currently
   hardcodes `allowed_data_scopes=[]`, so ABAC is inert on the registry path.
4. **Capability tokens** — wire `/v1/shield/cap/mint`
   (`api/routes_agent_auth.py:219`) into `/gateway/{route}/mcp`.
5. **Human approval** — `core/mcp/enforcement.py:142` currently *hard-denies* any
   tool matching an approval rule ("the MCP path cannot supply" approval). The
   confirmation-token channel already exists (`confirm:{session_id}:{token}`,
   `api/routes_mcp_gateway_server.py:51`); control-plane approval rules need
   routing through it.

**Separate specs:**
- **stdio sandboxing.** `core/mcp/upstream.py:171` passes tenant-supplied
  `command`/`args`/`env` straight to `stdio_client`, spawning them as a subprocess
  of the gateway. No allowlist, container, or seccomp exists. On a shared
  data plane, "register an MCP server" is a remote-code-execution primitive. v1
  adds only `SHIELD_MCP_STDIO_ENABLED=0` as a mitigation; real jailing needs its
  own spec.
- **Protocol hardening** — payload caps, JSON-RPC batch handling, protocol-version
  pinning, upstream response validation.
- **OAuth brokering** — `mcp.higgsfield.ai` advertises `offline_access`, so a
  refresh flow is possible, but Shield running the authorization-code dance
  per-tenant is its own spec. Until then a long-lived credential is required, and
  a short-lived one must be re-`PUT` on expiry.
