# Spec: verified identity for the MCP gateway (fleet control plane v2, step 1)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

Prerequisite for everything in `docs/spec-mcp-fleet-control-plane.md` §10 (RBAC
grants, ABAC, capability tokens, HITL). Those are all *grants*, and a grant is
worth exactly as much as the identity behind it.

## 1. Problem & outcome

v1 shipped **floors** — server-scoped controls that never read the caller's role,
precisely because the role is self-asserted. To ship **grants**, the role has to
mean something.

Investigation changed what this spec is. The machinery to do this **already
exists and is already used** — by the REST tool path, not by the MCP gateway.

`core/identity_resolution.py::resolve_identity` returns a `ResolvedIdentity`
carrying not just `agent_key` / `user_role` but **where each came from**:

| Field | Meaning |
|---|---|
| `agent_source`, `role_source` | `agent_token` · `mtls` · `oidc` · `body` · `header` · `none` |
| `identity_method`, `trust_level` | how the caller authenticated, and how much that is worth |
| `claimed_roles` | roles from the **verified** credential only |
| `binding`, `binding_failed`, `binding_error` | proof-of-possession (DPoP) |
| `acting_for`, `delegation_verified` | verified delegated user |
| `mode` | per-tenant role-binding mode: `off` · `prefer` · `strict` |
| `audit_fields()` | the provenance bundle for the decision log |

`api/routes_tool.py:252` and `api/routes_agent_chat.py:360` call it.
**`api/routes_mcp_gateway_server.py:121` does not** — it calls a separate,
weaker `_resolve_identity` (`api/routes_mcp_server.py:170`) that walks
`request.state` → headers → API key → OAuth claims, reports no provenance, and
honors no mode.

So there are two identity paths in one codebase with different security
properties, and the MCP gateway is on the weaker one.

### 1.1 A second finding: `strict` does not reject

Inside the resolver, `MODE_STRICT` and `MODE_PREFER` are treated **identically**
(`core/identity_resolution.py:411,418`). When a verified claim exists it wins in
both. When one does **not** exist, both fall through to `X-User-Role`.

Rejection is left to the caller, and the only caller that enforces anything
(`api/routes_tool.py:259`) enforces *token binding*, not role provenance. So
today, on every path, **a tenant in `strict` mode still accepts a header-asserted
role** when no verified claim is present.

That is not a bug in the resolver — reporting provenance and acting on it are
properly separate — but `strict` is a name that promises enforcement nobody
performs. An operator who set it believes something that is not true.

**Outcome.** One identity seam for the whole product, provenance in every MCP
decision, and a per-route switch that actually refuses unverified callers.
Observable success condition: with `require_verified_identity` on the
`higgsfield` route, a request carrying only `X-API-Key` + `X-User-Role: admin` is
refused with a distinct JSON-RPC error; the same request carrying a valid
`X-Agent-Token` whose claims include `admin` succeeds; and the audit record for
both shows `role_source`.

**Non-goals**
- No new credential type. Agent tokens, mTLS, OIDC and delegation already exist.
- No RBAC/ABAC grants, capability tokens, or HITL — those come after this.
- No change to how tenants authenticate (`X-API-Key` stays).
- Not deleting `_resolve_identity`; it keeps working for unmigrated callers.
- No per-user credential issuance workflow (§9 — the open `X-Agent-Key` question).

## 2. Plane & latency contract

**Data plane.** Enforcement is in the gateway's JSON-RPC entry point.

**This touches the guard path** (`tools/call`), so the invariant applies.

**Budget: no new Redis round-trip; target added p99 < 0.5 ms** for the resolution
itself.

`resolve_identity` reads request state and headers, and `role_binding_config`
caches per tenant (`_CACHE`, `core/identity_resolution.py:120`). The verified
identity is produced by `AgentIdentityMiddleware`, which already runs on every
request — the gateway is currently *discarding* what it computed, not saving work
by ignoring it.

Honest exception: `verify_token_binding` runs when `SHIELD_TOKEN_BINDING` is not
`off` (default `off`), and delegation resolution when `SHIELD_DELEGATION` is on.
Both are opt-in and already priced on the REST path; this spec does not change
their cost, it stops the MCP path from being the one place they silently do not
apply.

## 3. Data model

**No new Redis key.** One new field on the existing route document
(`mcp_gateway:upstream:{tenant_id}:{route}`), which the guard path already reads:

```jsonc
{
  "require_verified_identity": false   // NEW; absent = false = today's behavior
}
```

Deliberately a **route** field rather than a profile field. A tenant onboarding
verified identity does it server by server — the vendor MCP their pilot team uses
first, then the rest — and putting it in a shared profile would force the whole
fleet across at once. It can move into a profile later once tenants are past
migration; the reverse is painful.

Tenant-level `role_binding_config` (mode, claim path, rename map) is unchanged and
already stored.

## 4. API / interface

### 4.1 Gateway entry point — `api/routes_mcp_gateway_server.py`

Replace the `_resolve_identity` call with `core.identity_resolution.resolve_identity`,
keeping the same `(tenant_id, agent_key, user_role)` unpacking so nothing
downstream changes shape. Tenant still resolves from `X-API-Key` exactly as now —
the resolver covers agent and role, not tenancy.

**New rejection**, only when the route opts in:

| Condition | JSON-RPC error |
|---|---|
| `require_verified_identity` and `role_source` in (`header`, `body`, `none`) | `-32002 unverified identity: this server requires a verified agent credential` |
| `binding_failed` and `token_binding_mode() == required` | `-32002 proof-of-possession failed` |

`-32002` is distinct from `-32001 unauthenticated` on purpose: the caller *is*
authenticated as a tenant, and what is missing is a verified **agent** identity.
Conflating them sends an operator to rotate the wrong credential.

### 4.2 Route config — both planes

`require_verified_identity: bool = False` on `UpstreamConfigRequest`
(`api/routes_mcp_gateway.py`) and `RegisterServerRequest`
(`api/routes_mcp_admin.py`), and added to `_PRESERVED_ON_REWRITE` so a config
rewrite cannot silently turn it off.

### 4.3 Inventory / console

Each server reports `require_verified_identity`. The fleet console shows an
`unverified` pill on routes that do **not** require it, mirroring how
`bypassable` already reports `isolation_ack: false` — the same class of "policy
here is weaker than it looks".

### 4.4 Audit

Every MCP decision record gains `ResolvedIdentity.audit_fields()`. This is the
part worth having even before anyone enables enforcement: it answers "how many of
last month's calls carried a verified role?" — which is the number that tells a
tenant whether they can turn this on.

## 5. Security & backward compatibility

**Opt-in per route.** `require_verified_identity` absent → false → today's
behavior exactly. No tenant is broken by deploying this.

**Escape hatch:** `SHIELD_MCP_REQUIRE_VERIFIED=0` disables the rejection
fleet-wide, for rollback without editing routes.

**Migration, and why the audit ships first.** Enabling this on a route rejects
every client that has not been issued an agent token — that is the point, and it
is also an outage if done blind. Path: deploy (audit only, nothing rejects) →
read `role_source` in the decision log → issue tokens to the clients that show
`header` → enable per route once that count is zero.

**The `strict` naming problem.** This spec does **not** silently change what
`MODE_STRICT` does — tenants have it set, and turning a reporting mode into a
rejecting one under them is exactly the kind of behavior change `CLAUDE.md`
forbids. Instead:
1. `require_verified_identity` is the explicit, opt-in rejection switch.
2. `resolve_identity` gains no new behavior.
3. The docs stop describing `strict` as though it rejects, and a follow-up spec
   decides whether `strict` should gain teeth under a new name.

**What this does and does not buy.** A verified role makes grants meaningful. It
does **not** make a route non-bypassable — `isolation_ack` still governs that —
and it does not authenticate the *tenant* differently. The console must not let
`require_verified_identity: true` read as "this route is fully locked down".

## 6. Packaging & deploy

**No new module, no new dependency, no `Dockerfile.admin` change.**
`core/identity_resolution.py` is already in the admin image
(`Dockerfile.admin:63`) and already imported by the data plane.

**Env flags:** `SHIELD_MCP_REQUIRE_VERIFIED` (default `1`, meaning the per-route
flag is honored). Existing `SHIELD_ROLE_BINDING`, `SHIELD_TOKEN_BINDING`,
`SHIELD_DELEGATION` are unchanged.

**Rebuild:** data-plane image (enforcement), admin image (route field + console).
Either order is safe: an old data plane ignores a field it does not know, an old
admin image cannot set it.

## 7. Failure modes & edge cases

| Condition | Behavior | Rationale |
|---|---|---|
| Route flag absent | Today's path, unchanged | The compatibility guarantee |
| `SHIELD_MCP_REQUIRE_VERIFIED=0` | Never rejects | Rollback without config edits |
| Verified token, no `roles` claim | `role_source` is not `header` only if a claim exists; otherwise rejected when required | A token that asserts no role does not assert a role. Honest, and the fix is to mint one |
| mTLS identity, no roles | Same as above | `trust_level: high` is not a role |
| Verified delegated user | Accepted; `role_source: oidc`, `acting_for` recorded | Delegation already resolves before the header |
| `X-Agent-Token` present but invalid | Existing middleware rejects at 401 before the gateway | Unchanged; a present-but-invalid token is a stronger signal than none |
| Role binding mode `off` + route requires verified | Rejected, because `claimed_roles` is never consulted in `off` | Surfaced in the error: the tenant must set a mode for the route flag to be satisfiable |
| `binding_failed`, binding mode `optional` | Allowed, recorded | Matches the REST path; only `required` rejects |
| Resolver raises | **Fail closed** when the route requires verified; fall back to `_resolve_identity` when it does not | A route that asked for verification must not degrade to headers on an error |
| `tools/list` from an unverified caller on a required route | Rejected like any other method | Otherwise the surface is enumerable without identity |

**Fail-open vs fail-closed, stated:** on a route with
`require_verified_identity: true`, identity resolution is **fail-closed**. On
every other route nothing changes, including on error.

## 8. Test plan (Definition of Done)

New `tests/test_mcp_verified_identity.py`; additions to
`tests/test_mcp_identity_resolution.py`, `tests/test_mcp_gateway.py`.

**Headline test.** On a route with `require_verified_identity: true`:
`X-API-Key` + `X-User-Role: admin` → `-32002`, and the upstream is never
contacted; the same call with a valid `X-Agent-Token` carrying `roles: ["admin"]`
→ allowed, `role_source == "agent_token"`.

**Backward compatibility (non-negotiable).**
- A route without the flag produces decisions **identical to `main`**, including
  when the resolver raises.
- `_resolve_identity` keeps its current behavior for its other callers.
- `SHIELD_MCP_REQUIRE_VERIFIED=0` fully restores pre-spec behavior on a flagged route.
- A config rewrite does not clear the flag (`_PRESERVED_ON_REWRITE`).

**Per §7:** one test each for no-roles token, mTLS without roles, delegation,
mode `off` + flag on, `binding_failed` under `optional` vs `required`, resolver
raising on flagged vs unflagged routes, and `tools/list` rejection.

**Parity guard.** Assert the MCP gateway and `api/routes_tool.py` resolve the
same request to the same `(agent_key, user_role, role_source)`. The whole point
is one seam; a test is the only thing that keeps two call sites from drifting
again.

**Audit.** Assert `role_source` and `identity_method` reach the decision record
on both allowed and blocked calls — the migration depends on that number.

**Green bar:** `python -m pytest tests -q` green in a clean venv; CI `pytest` gate passes.

## 9. Task breakdown

One branch, sequential commits, per the single-branch preference.

| # | Task | Guard path? |
|---|---|---|
| 1 | Route field + preservation + inventory/console reporting | No |
| 2 | **Audit only**: gateway calls `resolve_identity`, records provenance, rejects nothing | **Yes** — behavior-neutral by design |
| 3 | `require_verified_identity` enforcement + `-32002` + env flag | **Yes** |
| 4 | Parity guard between the MCP and REST seams | No |
| 5 | Docs: stop describing `strict` as rejecting; migration runbook | No |

**Land 1–2 and leave them running.** Task 2 changes no decision, and the
`role_source` distribution it produces is what tells a tenant whether task 3 can
be enabled without an outage. Enabling enforcement before that data exists is
guessing.

## 10. Follow-ups this spec deliberately does not answer

- **How agent keys map to individual people.** Flagged during the employee-guide
  work and still open: today `X-Agent-Key` is a registry lookup, and an
  unrecognized value reads as an unregistered agent rather than a new user.
  Verified identity changes the shape of that question — an agent token carries a
  subject — so it should be answered after this, not before.
- **Whether `strict` should reject.** Renaming or re-scoping an existing mode
  under tenants who already set it needs its own migration note.
- **`docs/spec-agent-role-binding.md` is referenced by `api/routes_tool.py:251`
  and does not exist.** Either restore it or fix the two comments pointing at it.
