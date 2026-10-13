# Spec: Enterprise MCP Gateway (hardening to the v0.1 product spec)

> Status: DRAFT — awaiting approval. Spec-first per `CLAUDE.md`; no code until approved.
> Target reference: `docs/specs/mcp-gateway-target-v0.1.md` (external draft v0.1).

## 0. Framing — why this sells, and what we already have

The target spec describes a **default-deny, multi-tenant MCP gateway** that an
enterprise can put in front of Codex / Claude Code / custom apps and trust with
tool authorization, downstream credentials, approvals and audit. We are **not
building this from zero** — the gap analysis (below) shows the hard, trust-
establishing parts already exist. This spec closes the remaining gaps and packages
the result as an enterprise-sellable control.

**Keep (our existing strengths — the spec is built around these):**
- Federated identity: principal + external-identity entities keyed on
  (issuer, subject), issuer→role mapping where **unknown claims grant nothing**
  (`core/identity_resolution.py:305-337`), header-role escalation refused
  (`core/mcp/principal.py:155`), **cryptographic agent-for-user delegation**
  (`core/delegation.py`).
- **Revocation freshness, fail-closed**: 15s cache + per-call jti revocation
  (`core/mcp/principal.py:50`, `api/routes_mcp_server.py:178`) — already beats the
  30s target.
- **Tamper-evident, hash-chained + signed audit** (`storage/audit_chain.py`),
  never logs tokens/arguments.
- **Connector/secret management**: vault materialization bound to the upstream
  host, per-user downstream OAuth, refuses to reuse the gateway bearer upstream
  (`core/mcp/gateway.py:89`).
- **REST↔MCP enforcement parity** via one shared evaluator
  (`core/mcp/enforcement.py`); server description scanning gates activation
  (`core/mcp_scan.py`).

**Gap summary (what this spec delivers), worst-first for an enterprise buyer:**

| # | Gap | Today | Target |
|---|---|---|---|
| G1 | **Declarative policy language** | `role_permissions` maps + per-tool allow/deny (`storage/mcp_policy_store.py`) | YAML grants: subjects/actions/resource/conditions/obligations, compiled + versioned |
| G2 | **SSRF on server registration** | URL unvalidated at register (`routes_mcp_admin.py:398`); `validate_outbound_url` only on OAuth discovery | Validate DNS/address on register + connect; block loopback/link-local/metadata |
| G3 | **Decision binding** | no arg-hash/policy-version/schema-version on the decision/audit | bind every decision to principal/tenant/cred/action/arg-hash/policy-ver/schema-ver |
| G4 | **Default-deny** | empty allow = allow-all (`core/rbac.py:50-62`) | default-deny per tenant (flagged, migrated) |
| G5 | **REST data plane** | `/v1/shield/tool/check` + chat-completions only | `/api/v1/{me,tools,tool-calls}` + idempotency, REST==MCP |
| G6 | **HITL on MCP** | grant machinery is REST-only (`core/approvals.py`); MCP can only deny | `approval_required` over MCP via gateway-side approval state |
| G7 | **Transport hardening** | no pagination, no `server__tool` catalog, no Origin/CORS/size/timeout, no OTel, audit fails open | add all; **durable audit outbox, fail-closed** |
| G8 | **Credential model** | principal API keys: no expiry/rotation/audience/ceiling (`storage/principal_store.py:243`) | add expiry, rotation, scope ceiling that can only narrow |

## 1. Problem & outcome

**Problem.** Enterprises want to let coding agents and apps use internal MCP
tools without handing them broad access or credentials. Our gateway governs tool
calls today, but the authorization model (role→tool maps), the lack of a policy
language, decision provenance, SSRF-safe registration, a REST surface, MCP-path
approvals, and fail-closed audit keep it below the bar a security review sets.

**Outcome.** A gateway where: a principal starts with **no tool access**; access
comes only from an **explicit, versioned, declarative grant**; every call is
**independently authorized and bound** to (principal, tenant, credential, tool,
schema version, argument hash, policy version); sensitive calls route to
**human approval**; registration is **SSRF-safe**; and every decision is in a
**tamper-evident, fail-closed audit**. Native MCP and a REST API are enforcement-
equivalent.

**Observable success:** the 13 acceptance tests in §8 pass; p95 authz < 20 ms,
gateway-added p95 < 50 ms (§ SLOs); a pinned Codex + Claude Code release connect,
list and invoke under policy.

**Non-goals (v1):** resources/prompts/sampling/elicitation/roots over MCP (tools-
only); a stdio bridge (Next); SCIM lifecycle sync (Next); DLP/prompt-injection
inspection *new* work (we already have guardrail hooks — reused, not rebuilt);
replacing the authorization server with a third-party broker (we remain our own
AS and may *additionally* act as a resource server for a broker later).

## 2. Plane & latency contract

- **Planes:** Data plane (the `/mcp` + `/api/v1/tool-calls` dispatch path) and
  admin/control plane (policy authoring, registration, approvals UI). The target
  spec's "control plane issues signed, versioned snapshots the data plane cannot
  edit" maps onto our existing `rev`-versioned profile fan-out
  (`storage/mcp_policy_store.py:87,244`) — extended to compiled policy snapshots.
- **Guard path / latency:** `tools/call` **is** on the guard path
  (`CLAUDE.md`). The declarative policy engine (G1) must **compile** policies to
  an in-memory decision structure loaded from a versioned snapshot — never
  interpret YAML per call. **Budget: p95 authorization < 20 ms** with warm caches
  (matches the target SLO), evaluated against `tests/` timing. SSRF checks (G2)
  run at **registration/connect**, not per call. The audit outbox (G7) write is
  on the path and must be bounded (append to a durable local queue, flush async).

## 3. Data model

New/extended, all tenant-scoped (Redis unless noted; Postgres is the target
system of record per the doc — v1 stays on the existing Redis+fallback store and
notes the Postgres migration as Next):

- **Principal** (extend `storage/principal_store.py`): add `kind: agent` as a
  first-class kind; add an `attributes: {}` map; keep `principals:{tenant}:{id}`.
- **Credential** (extend `create_principal_key`): add `expires_at`, `audience`,
  `scope_ceiling: [tool_id|action]` (can only *narrow* the principal's effective
  permissions), `rotated_from`. Key `pkey:{tenant}:{key_id}` → `{hash, principal_id,
  scope_ceiling, audience, expires_at, revoked}`.
- **Delegation** (persist `core/delegation.Delegation`): `delegations:{tenant}:{id}`
  → `{subject_principal, acting_principal, allowed_actions, resource_restrictions,
  expires_at, issuance_context}`. Permissions = intersection(subject, actor,
  delegation).
- **Policy** (new `storage/mcp_authz_policy.py`): source YAML + a **compiled,
  versioned snapshot**. `authzpolicy:{tenant}:{id}` (source) and
  `authzsnapshot:{tenant}:{version}` (compiled). `version` is a content hash.
- **Catalog** (new): immutable public tool name `server__tool` →
  `{server_id, upstream_tool_name, input_schema_hash, description_hash,
  risk_class, status: approved|pending|disabled, catalog_version}`. Key
  `catalog:{tenant}:{public_name}`.
- **Approval** (extend `core/approvals.py`): `approval:{tenant}:{ref}` →
  `{subject, actor, tool_id, schema_version, params_hash, expires_at, used,
  approver, min_approvals}`.
- **Idempotency** (new): `idem:{tenant}:{principal}:{tool}:{key}` →
  `{args_hash, call_id, status}` TTL 24h.
- **Audit outbox** (new, durable): `auditoutbox:{tenant}` list; records drain to
  the tamper-evident chain (`storage/audit_chain.py`).

Cross-tenant isolation: every key is tenant-prefixed and the caller's tenant is
resolved from the credential (never the body — §5), as today
(`core/mcp/principal.py`).

## 4. API / interface

### 4.1 Native MCP (extend `api/routes_mcp_gateway_server.py`)
- Keep `POST /gateway/{route}/mcp` and `/gateway/t/{tenant}/{route}/mcp`.
- Add `ping`; implement real `tools/list` **pagination** with cursors bound to
  (tenant, principal, catalog+policy version); add `server__tool` **namespacing**
  via the immutable catalog.
- Enforce **Origin validation, CORS allowlist, request/response size caps
  (1 MiB / 10 MiB), 60 s tool timeout, bounded stream duration**.
- **Tools-only:** default `SHIELD_GATEWAY_RESOURCES=0` (flip today's default) so
  resources/prompts/sampling/elicitation/roots are rejected unless explicitly
  enabled (reconciles the §5-target divergence).
- Policy denial → documented gateway error `GATEWAY_POLICY_DENIED` in `error.data`
  (already partly present at `:47`), never claimed as a standard MCP error.

### 4.2 REST data plane (new `api/routes_gateway_rest.py`, prefix `/api/v1`)
- `GET /api/v1/me` → principal, tenant, effective context.
- `GET /api/v1/tools` → authorized catalog (public name, input schema, tool
  version, pagination cursor).
- `POST /api/v1/tool-calls` → same evaluator as MCP `tools/call`; `Idempotency-Key`
  header; identity **only** from the validated credential (body tenant/principal/
  role/credential rejected); `200` completed or `202` + status URL.
- `GET /api/v1/tool-calls/{id}` (own call / auditor per policy),
  `POST /api/v1/tool-calls/{id}/cancel` (best-effort).
- Error contract: 400/401/403/404/409(idempotency)/429/502/504, stable `code` +
  safe message + request id; never leak tokens/hidden names.

### 4.3 Admin / control plane (extend `api/routes_mcp_admin.py` + new)
- `/admin/v1/principals` (create/inspect/disable/bind-roles/provenance) — **new**.
- `/admin/v1/identity-providers` — exists (`routes_oidc_admin.py`), add mapping
  preview on sanitized claims.
- `/admin/v1/credentials` — extend issue/rotate/revoke with scope ceiling + expiry.
- `/admin/v1/servers` + `tools` — exists; add schema/description **hashing**,
  new-tool **approve-before-publish**, catalog version pinning, and SSRF
  validation at register (G2).
- `/admin/v1/policies` — **new**: draft / validate / **simulate** / publish
  (atomic, versioned snapshot) / compare / **rollback**.
- `/admin/v1/audit-events` — exists via telemetry; add the full field set (G3).
- **Separate admin roles**: tenant-admin / policy-admin / connector-admin /
  auditor / caller; control-plane rights never grant tool execution.

## 5. Security & backward compatibility

- **Default-deny (G4) is a behavior-changing default → shipped non-breaking.**
  New per-tenant `authz_mode ∈ {legacy, declarative}`. Existing tenants default
  **legacy** (today's `role_permissions` allow-all-on-empty) until migrated; new
  tenants default **declarative** (default-deny). Env escape hatch
  `SHIELD_GATEWAY_AUTHZ_MODE` as a fleet override; a migration tool emits an
  equivalent declarative policy from a tenant's current `role_permissions`.
- **Identity never from the body** (REST + MCP): resolve from the validated
  credential; reject body-supplied tenant/principal/role/`on_behalf_of` as
  identity (tighten `api/routes_tool.py` fallback). OBO only via the signed
  delegation token (`core/delegation.py`).
- **SSRF (G2):** `validate_outbound_url` (today only on OAuth discovery,
  `core/mcp_oauth.py:167`) applied to upstream URL at **register and connect**;
  block loopback/link-local/metadata (169.254.169.254, etc.), restrict redirects;
  private enterprise destinations explicitly allowlisted.
- **Token validation:** add `nbf`, a JWKS-refresh rate limit, and opaque-token
  introspection (today JWT-only, `core/jwt_utils.py`). Keep issuer allowlist, aud,
  alg, sig, ≤15 min lifetime, per-call jti revocation.
- **Decision binding (G3):** every decision carries principal/tenant/credential/
  action/resource/normalized-arg-hash/policy-version/schema-version; evaluation
  errors and unavailable mandatory inspection **fail closed**.
- **Audit fail-closed (G7):** the durable outbox replaces today's fire-and-forget
  (`core/mcp/gateway.py:320`); if the outbox cannot accept a record, **deny new
  execution**. If an upstream action completed but audit/inspection delivery
  failed, record execution separately and report delivery failure — never imply
  the side effect was prevented.

## 6. Packaging & deploy

- **`Dockerfile.admin` COPY:** new admin modules (`routes_gateway_rest.py`,
  `routes_mcp_principals.py`, `storage/mcp_authz_policy.py`, the policy compiler)
  imported by `admin_app.py` MUST be added to the COPY allowlist
  (`tests/test_admin_dockerfile_imports.py` guards it).
- **Deps:** a YAML policy compiler uses existing `pyyaml`; no new runtime dep
  expected. Any new dep → `requirements.txt` + `requirements-test.txt`
  (+ `requirements-admin.txt`), validated in a clean venv.
- **Env flags:** `SHIELD_GATEWAY_AUTHZ_MODE`, `SHIELD_GATEWAY_RESOURCES` (default
  0), `SHIELD_GATEWAY_MAX_REQUEST_BYTES`/`_RESPONSE_BYTES`/`_TOOL_TIMEOUT_S`,
  `SHIELD_GATEWAY_AUDIT_FAIL_CLOSED`. Rebuild: data-plane + admin images.

## 7. Failure modes & edge cases

- **Policy snapshot missing/corrupt** → fail closed (deny), serve last-good only
  if signature-valid; never fall back to allow-all.
- **Redis down** → principal/revocation path already fails closed
  (`core/mcp/principal.py:269`); policy snapshot cached in-process with a bounded
  TTL; audit outbox buffers locally and denies new execution if it cannot persist.
- **Freshness unestablished** (token/introspection/principal status/policy) within
  the bound → deny new execution; in-flight upstream work reported accurately
  (`outcome_unknown`).
- **Idempotency** key reuse with a different arg-hash → 409; timeout after
  dispatch → `outcome_unknown`, never auto-retry writes.
- **Catalog drift**: schema/description hash change → tool disabled pending review.

## 8. Test plan (Definition of Done) — the enterprise acceptance tests

Mirror the target's 13 acceptance tests, each a test:
local-identity (no access until granted; key can't exceed grant); federated-roles
(mappings grant, forged roles don't); token-misuse (ID token / wrong aud / wrong
iss / expired / bad sig / cross-tenant rejected); tool-enforcement (hidden tool
not invocable by name-guess; write/out-of-scope args denied before dispatch);
API-parity (REST==MCP for same identity+tool+args); session-isolation (cross-user
session/cursor/stream/call ids disclose nothing); policy-change (revoked key /
disabled principal loses access within the bound, incl. open MCP session);
client-interop (pinned Codex + Claude Code login/list/invoke; one OSS HTTP client
token-auths); upstream-safety (incoming tokens never reach upstream; pools
isolated; SSRF/redirect blocked); reliability (no silent write-retry; uncertain
execution visible); audit-and-secrets (every exec has correlated decision+outcome;
secret scan finds nothing); catalog-and-failure (unapproved tools denied; schema
change triggers review; mandatory inspection failure blocks dispatch).
Plus: regression guard that `Dockerfile.admin` covers new imports; full suite
green in a **clean venv**; CI `pytest` gate passes.

## 9. Milestones (delivery sequence, one+ PR each)

- **M1 — Model & registration safety.** Credential ceiling/expiry/rotation (G8),
  persisted delegation (G3-pre), **SSRF-safe server registration** (G2),
  schema/description hashing + approve-before-publish, `/admin/v1/principals`.
- **M2 — Policy engine & decision binding.** Declarative YAML policy language +
  compiler + versioned snapshots + `/admin/v1/policies` (validate/simulate/
  publish/rollback) (G1); **default-deny** per-tenant mode + migration (G4);
  decision binding + full audit field set + **durable fail-closed outbox** (G3,
  G7-audit).
- **M3 — Surfaces & interop.** REST data plane `/api/v1/*` + idempotency (G5);
  transport hardening — pagination, `server__tool` catalog, Origin/CORS/size/
  timeout, tools-only default, `ping` (G7); Codex + Claude Code certification.
- **M4 — Approvals, reliability, hardening.** `approval_required` over MCP via
  gateway-side approval state (G6); OTel spans; concurrency limits; opaque-token
  introspection + `nbf` + JWKS rate limit; adversarial test pass.
- **Next (post-v1):** stdio bridge, SCIM lifecycle sync, Postgres system-of-record,
  third-party-broker resource-server mode.

## 10. Decisions (resolved 2026-10-12)

1. **Authz default — DECIDED:** existing tenants stay `legacy` (allow-all-on-empty)
   until migrated; **new tenants default-deny** (`declarative`). Secure-by-default
   without breaking a year of running agents.
2. **System of record — DECIDED: Redis + fallback for v1.** Postgres is Next.
3. **Authorization server — DECIDED:** remain our **own AS** for v1 (we already
   issue + validate Shield JWTs). Resource-server-for-a-broker mode is Next.
4. **First IdPs — DECIDED: Okta and Entra.** Plus the **"custom app sends its own
   headers"** path: a scoped gateway-issued token or **API key** presented in a
   header, validated by the gateway (the header/client name confers nothing; the
   gateway never forwards it upstream). First two **upstream servers** still TBD
   (proposed default: GitHub + one internal/Jira) — drives the M3 interop matrix.
5. **API keys at launch — DECIDED: yes**, as **scoped machine/service/agent
   credentials** (never a human login — humans use Okta/Entra SSO). Enterprise-
   acceptable **because** M1/G8 gives them: shown-once secret + hashed storage,
   **expiry, rotation, immediate revocation, a scope ceiling that only narrows**,
   and tenant+principal+audience binding; issuance gated by strong admin auth and
   audited. We **also** offer short-lived OAuth client-credentials and recommend
   them where the client supports it. Private-network destinations: allowed via an
   explicit per-tenant allowlist (not open by default).

**Still open (not blocking M1):** the first two upstream MCP servers to certify.
