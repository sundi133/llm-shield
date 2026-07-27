---
title: "Spec: Verified role binding for agent RBAC"
layout: default
nav_order: 34
permalink: /spec-agent-role-binding/
description: Bind the RBAC role to a verified token claim instead of a client-supplied header, so a compromised agent cannot promote itself. Opt-in per tenant, off by default.
---

# Spec: Verified role binding for agent RBAC
{: .no_toc }

Status: DRAFT — awaiting approval. No code written.
{: .fs-6 .fw-300 }

---

## 1. Problem & outcome

Tool RBAC decides what an agent may do from `user_role`, and `user_role` is read
straight off the request. Nothing verifies it:

| site | source |
| --- | --- |
| [api/routes_tool.py:245-248](https://github.com/sundi133/llm-shield/blob/main/api/routes_tool.py#L245) | `body.user_role` or `X-User-Role` header |
| [api/routes_agent_chat.py:357](https://github.com/sundi133/llm-shield/blob/main/api/routes_agent_chat.py#L357) | `body.user_role` or `X-User-Role` |
| [api/routes_classify_output.py:439](https://github.com/sundi133/llm-shield/blob/main/api/routes_classify_output.py#L439) | `X-User-Role` or `context.user_role` |
| [core/middleware.py:294](https://github.com/sundi133/llm-shield/blob/main/core/middleware.py#L294) | `X-User-Role` (shadow-agent attribution) |

`verify_agent_token()` checks signature, issuer, audience, and build hash, but
carries no role. `IdentityTuple` ([core/identity.py:22](https://github.com/sundi133/llm-shield/blob/main/core/identity.py#L22))
has no roles field. So the caller asserts its own role, and the subject Shield is
constraining is the same party that supplies the constraint input.

This matters because the threat model Shield sells against is a **compromised or
prompt-injected agent** — precisely the party able to rewrite its own headers. A
support-desk agent that is talked into emitting `X-User-Role: payments_officer`
is authorized for `wire_transfer_execute`, and the audit records a legitimate
payments-officer action. Classic confused deputy.

**Outcome.** A tenant can require that the role come from a **verified** claim —
an agent token minted by Shield, or an OIDC token from a trusted issuer — and
that a client-supplied `X-User-Role` be ignored or rejected. Observable success:
with binding in `strict`, replaying the exact escalation request with a forged
header is denied, and the audit shows the rejected claim and its source.

### Non-goals
- Not an authentication system. Shield verifies tokens minted elsewhere; it does
  not become an IdP, issue user sessions, or manage login.
- No change to how roles map to tools. `role_permissions` in the agent registry
  stays the source of authorization; this spec only changes *how the role is
  established*.
- No end-user SSO for the tenant portal. Unrelated surface.
- Not a fix for the data-policy layer overriding registry permissions. Separate
  known issue.

---

## 2. Plane & latency contract

**Data plane** (`core/app.py`). This is squarely **on the guard path**:
`/v1/shield/tool/check`, `/guardrails/*`, and `cap/mint` all resolve a role.

Latency budget: **no network I/O on the hot path.**

- Agent tokens verify locally against an in-process signer — the cost is one
  signature verification.
- OIDC verifies against JWKS from [core/oauth/jwks_cache.py](https://github.com/sundi133/llm-shield/blob/main/core/oauth/jwks_cache.py),
  which is already cached. A cache miss must **not** block a guard call: on miss
  the request resolves under the configured fallback (§5) and the fetch happens
  out of band.
- Tenant binding config is read from Redis, so it is cached in-process with a
  short TTL rather than fetched per request.

Target: **p99 added latency < 2 ms** with warm caches. This must be measured, not
assumed, and the measurement belongs in the PR that turns enforcement on.

Admin plane (`admin_app.py`) hosts only the configuration endpoint (§4).

---

## 3. Data model

### 3.1 Per-tenant binding config (new)

Redis key `shield:role_binding:{tenant_id}`, JSON, no TTL (config, not cache):

```json
{
  "mode": "off",
  "role_claim": "roles",
  "role_map": {"bank-payments": "payments_officer"},
  "allowed_issuers": ["https://keycloak.example.com/realms/bank"],
  "updated_at": 1785000000
}
```

| field | meaning |
| --- | --- |
| `mode` | `off` \| `prefer` \| `strict` — see §5 |
| `role_claim` | claim to read the role from; supports a dotted path (`realm_access.roles`) |
| `role_map` | optional IdP-role → Shield-role rename; unmapped values pass through |
| `allowed_issuers` | issuers accepted for this tenant; empty means fall back to the existing per-tenant OIDC provider registry |

Tenant scoping is by key, consistent with `shield:oidc:providers:{tenant_id}`
([core/oauth/oidc_client.py:244](https://github.com/sundi133/llm-shield/blob/main/core/oauth/oidc_client.py#L244)).

In-process cache: `{tenant_id: (config, fetched_at)}`, TTL 30 s.

### 3.2 Reused, not rebuilt

- `shield:oidc:providers:{tenant_id}` — issuer, JWKS URI, audience. Already exists.
- `map_claims()` ([oidc_client.py:156](https://github.com/sundi133/llm-shield/blob/main/core/oauth/oidc_client.py#L156)) — already maps IdP claims to Shield claims.
- `OIDCServiceAccountProvider` ([workload_identity/providers.py:124](https://github.com/sundi133/llm-shield/blob/main/core/workload_identity/providers.py#L124)) — already verifies a Bearer JWT against trusted issuers with mandatory audience.

### 3.3 `IdentityTuple` extension

Add two optional fields, defaulted so every existing construction site keeps working:

```python
roles: tuple[str, ...] = ()
role_source: str = "unbound"   # unbound | header | agent_token | oidc
```

### 3.4 Audit

Every decision already writes audit metadata. Add `role_source` and, when a
supplied header was overridden or rejected, `role_header_rejected: true` plus the
claimed value. This is what makes a rejected escalation visible after the fact —
without it, `strict` denies silently and the operator cannot tell an attack from
a misconfiguration.

---

## 4. API / interface

### 4.1 Guard path — no new endpoints

`/v1/shield/tool/check` and friends keep their contract. A new internal resolver:

```python
def resolve_role(request, body_role: str | None, tenant_id: str) -> RoleDecision
# RoleDecision(role: str|None, source: str, rejected_header: str|None)
```

Precedence, per mode (§5). Call sites in §1 switch from reading the header
directly to calling this.

**Response change.** When `strict` rejects, `/v1/shield/tool/check` returns its
normal shape with `allowed: false` and a `rbac_guard`-style entry naming the
cause. It does **not** invent a new HTTP status: existing clients treat non-200
as an outage, and an authorization denial is a decision, not an outage.

### 4.2 Admin plane — configuration

Mounted in `admin_app.py`:

- `GET /v1/tenant/me/role-binding` → current config
- `PUT /v1/tenant/me/role-binding` → set `mode`, `role_claim`, `role_map`, `allowed_issuers`

Auth: existing tenant API-key dependency, same as neighbouring `/v1/tenant/me/*`.

Off the hot path: the guard path reads Redis (cached), never this endpoint.

---

## 5. Security & backward compatibility

### 5.1 Modes

| mode | verified claim present | no verified claim |
| --- | --- | --- |
| `off` (default) | header wins — today's behavior exactly | header |
| `prefer` | claim wins; header ignored; mismatch audited | header, audited as unbound |
| `strict` | claim wins; header rejected | **deny** |

`off` is the default and is byte-for-byte today's behavior. Nothing changes for
any existing deployment until a tenant opts in.

### 5.2 Escape hatch

`SHIELD_ROLE_BINDING=off|prefer|strict` sets the floor for tenants with no
config. Default `off`. A tenant setting is capped by the env value only in the
sense that `SHIELD_ROLE_BINDING=off` **disables the feature globally** — the
operator kill switch if binding misfires in production.

This satisfies the repo's secure-by-default-but-non-breaking rule: the secure
behavior is available and documented, the default is non-breaking, and there is
one flag to turn it off.

### 5.3 Threats this closes, and does not

Closes: a compromised agent asserting a higher role via `X-User-Role`, when it
cannot mint a token for that role.

Does **not** close:
- An IdP that will issue `payments_officer` to anyone who asks. Binding moves
  trust to the issuer; it does not audit the issuer.
- A caller holding a genuinely-issued privileged token (stolen credentials).
- Any bypass of Shield entirely. The checkpoint model still requires that tools
  be reachable only through Shield.

State these in the docs. A control that is oversold is worse than one that is
absent, because it stops people looking further.

### 5.4 Migration

Rolling out `strict` before callers send tokens will deny every tool call. The
documented path is `off` → `prefer` (observe `role_source` in the audit until
`header` disappears) → `strict`. The config endpoint should refuse to jump
straight to `strict` unless the caller passes `acknowledge_denial_risk: true`.

---

## 6. Packaging & deploy

- **Deps:** none new. `PyJWT[crypto]>=2.8` is already in `requirements.txt:18`
  and `requirements-admin.txt:12`.
- **`Dockerfile.admin`:** `core/identity.py` (line 44) and `core/oauth/` (line 54)
  are already copied. **If the config endpoint lands in a new module, that module
  MUST be added to the COPY allowlist** or the admin image crash-loops at boot —
  enforced by `tests/test_admin_dockerfile_imports.py`. Flagged as the single
  highest-risk packaging item in this spec.
- **Images:** data plane (guard path) and admin plane (config endpoint) both
  rebuild.
- **Env:** `SHIELD_ROLE_BINDING` (default `off`).

---

## 7. Failure modes & edge cases

| case | behavior |
| --- | --- |
| No token, `off`/`prefer` | header used; `role_source=header` |
| No token, `strict` | deny, `role_source=unbound` |
| Token valid, no role claim | `prefer`: fall back to header, audited. `strict`: deny — an unroled token must not silently inherit a header |
| Token expired / bad signature / wrong audience | treated as no token |
| Issuer not in `allowed_issuers` | treated as no token, audited with the issuer seen |
| JWKS unreachable, claim uncached | `prefer`: header + audit. `strict`: **deny** (fail closed) |
| Redis down, config never loaded | env default (`off`) — fails to today's behavior rather than locking out every tenant |
| Redis down, config previously loaded | last-known config, served past TTL rather than downgrading silently |
| Role claim is a list | first entry after `role_map`; deterministic ordering, not set iteration |
| Role claim is huge / deeply nested | cap length and depth; reject rather than truncate into a different role |
| Header and claim agree | claim wins, no rejection audited |
| Header present, claim present, disagree | claim wins; `role_header_rejected: true` with the claimed value |
| Multiple identity sources (mTLS + agent token + OIDC) | fixed precedence: agent token, then OIDC, then mTLS; documented and tested |

Fail-open vs fail-closed: **`strict` fails closed, `prefer` fails to the header.**
That asymmetry is deliberate and must be documented — `prefer` is an observation
mode, not a control.

---

## 8. Test plan (Definition of Done)

Unit, one per row in §7. Specifically:

1. `off` mode is byte-identical to current behavior — regression guard.
2. `prefer` with a valid agent token carrying `roles` overrides a conflicting header.
3. `strict` with a forged header and no token denies.
4. `strict` with a valid token and a conflicting header uses the claim and sets `role_header_rejected`.
5. Expired / wrong-audience / untrusted-issuer tokens are treated as absent.
6. JWKS unreachable: `prefer` falls back, `strict` denies.
7. Redis down with no cached config resolves to the env default.
8. List-valued and mapped claims resolve deterministically.
9. Precedence when several identity sources are present.
10. Audit contains `role_source` on every path.

Regression guards for drift-prone couplings:
- A test asserting **every** call site in §1 goes through `resolve_role()`, so a
  new route cannot quietly reintroduce header trust. This is the coupling most
  likely to rot.
- `tests/test_admin_dockerfile_imports.py` already covers the admin COPY risk.

Performance: assert added p99 < 2 ms with warm caches on the guard path.

Full suite green in a **clean venv**; `pytest` CI gate passes.

---

## 9. Task breakdown (one PR each)

| # | PR | Risk |
| --- | --- | --- |
| 1 | `IdentityTuple.roles` + `role_source`, `resolve_role()` resolver, audit field. Mode hardwired `off`. No behavior change. | low |
| 2 | Route call sites switch to `resolve_role()`, plus the regression test that all of them do. Still `off`. | low — the diff is wide but inert |
| 3 | Role claim extraction from agent tokens and OIDC; `prefer` mode; per-tenant config read with cache. | medium |
| 4 | `strict` mode, header rejection, deny semantics, migration guard on the config endpoint. | **high — first behavior change**; ship with the perf measurement |
| 5 | Admin config endpoint + portal UI. Check `Dockerfile.admin` COPY. | medium |
| 6 | Keycloak demo bundle under `examples/identity/keycloak/` — compose file, realm export with the three banking roles, runbook. Docs only. | low |

PRs 1–2 are safe to land immediately and make the rest small. PR 4 is the one
that deserves the careful review.

---

## 10. Open questions

1. **Should `prefer` be the eventual default for new tenants?** Secure-by-default
   argues yes; it changes nothing for callers that send no token, and starts
   populating `role_source` for anyone who does.
2. **Do we need a role claim in Shield-minted agent tokens**, or is OIDC enough?
   Minting roles ourselves means Shield decides who is a payments officer, which
   is authority we may not want.
3. **Does the MCP gateway path need the same treatment?**
   [core/mcp/enforcement.py:166,252](https://github.com/sundi133/llm-shield/blob/main/core/mcp/enforcement.py#L166)
   forwards `X-User-Role` onward. If binding stops at the tool-check route, the
   gateway becomes the bypass.
