# Spec: AIBOM — AI Bill of Materials for integrated apps (v1)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.
Target spec: **AIBOM Specification v1.0** (Votal AI). This document scopes what
Shield ships in v1 to implement it for tenant apps.

## 1. Problem & outcome

**Problem.** Teams running AI applications have no machine-readable inventory of
what their app is actually made of — which models, prompts, agents, tools, MCP
servers, guardrails, and policies are in play — and no way to detect when the
running system drifts from what was approved. Compliance (EU AI Act, ISO 42001,
NIST AI RMF) increasingly demands exactly this artifact.

**Insight.** An app that integrates with Shield already gives Shield most of the
inventory: the agent registry (`agents:{tenant}`), shadow agents observed in
traffic (`unregistered:{tenant}`), tool definitions and policies, MCP gateway
routes, enabled guardrails, RBAC roles, and a runtime activity buffer
(`agent_auth_stats`). **Shield can generate the app's AIBOM for it.** What
Shield cannot observe (the app's LLM models, prompts, knowledge sources, memory
backends, package supply chain), the app **declares** through a small API — so
integrated apps effectively create their own BOM with Shield filling in
everything it already knows.

**Outcome.** Per tenant:
1. `GET /v1/tenant/me/aibom` returns a complete AIBOM JSON document (schema in
   §4) assembled live from existing Shield state + declared components.
2. The tenant can **snapshot** an AIBOM as the approved design-time baseline.
3. `GET /v1/tenant/me/aibom/drift` diffs the current runtime AIBOM against the
   approved snapshot (AIBOM v1.0 §18 "Runtime Drift Detection") — new/removed
   agents, tools, MCP servers, permission changes, guardrail changes — and can
   emit an `aibom_drift_detected` webhook event.

**Success condition.** A tenant with registered agents, tools, an MCP gateway
route, and enabled guardrails calls one endpoint and gets a valid AIBOM v1.0
JSON document; after approving a snapshot, registering a new tool grant makes
`/drift` report exactly that change.

**Non-goals (v1)** — these are AIBOM v1.0 §20 "Future Extensions", explicitly
out of scope now:
- CycloneDX / SPDX / SBOM interoperability or export formats.
- Cryptographic signing of the BOM.
- CVE / vulnerability-feed enrichment of supply-chain entries.
- Automatic scanning of the customer's codebase for packages (supply chain is
  declared-only in v1; a scanner can feed the declare API later).
- Agent-to-agent trust graphs, prompt/tool lineage, decision provenance.
- Continuous/streaming drift evaluation (v1 drift is computed on demand; a
  scheduled check can call the same endpoint later).
- Portal UI tab (JSON API first; UI is a follow-up).
- HTML/PDF rendering (the evidence-pack HTML pattern can be added later).

## 2. Plane & latency contract

- **Plane: admin (CPU portal) only.** New router mounted by `admin_app.py`,
  following the evidence-pack precedent (`api/routes_evidence.py`,
  `/v1/tenant/me/compliance/*`).
- **Off the hot path — no guarded-traffic impact.** Every endpoint is a
  read-only aggregation (plus small KV writes for declares/snapshots) over data
  **already written** by the guard/auth/registry paths: registry KV,
  `agent_auth_stats` recent buffer, guardrail metrics, gateway route KV. Nothing
  in this feature runs in-line with `/guardrails/*`, `cap/mint`, or
  `tools/call`, and no new writes are added to those paths. Same contract as
  `api/routes_governance.py` (see its LATENCY note).

## 3. Data model

Tenant scoping everywhere: `tenant_id` resolves from the API key exactly as the
neighboring routers do (§4); every key below embeds `{tenant_id}`; no endpoint
accepts a tenant id from the request body, so cross-tenant reads are impossible
by construction.

**New Redis keys** (via `storage/tenant_store.kv_get/kv_set`, which already
handles Upstash/TCP/in-memory fallback):

| Key | Value shape | TTL |
|---|---|---|
| `aibom:declared:{tenant_id}` | `{"models": {id: {...}}, "prompts": {id: {...}}, "knowledge_sources": {id: {...}}, "memory": {id: {...}}, "supply_chain": {id: {...}}, "metadata": {...}, "updated_at": ts}` | none |
| `aibom:snapshot:{tenant_id}:{snapshot_id}` | full generated AIBOM doc + `{"snapshot_id", "created_at", "approved_by", "note"}` | none |
| `aibom:snapshots:{tenant_id}` | index: `{"snapshots": [{snapshot_id, created_at, approved_by, note, sections_hash}]}` | none |

`snapshot_id` = `bom-{unix_ts}-{token_hex(3)}` (same pattern as governance
campaign ids). The index caps at the **20 most recent** snapshots; creating the
21st evicts the oldest (documented truncation, logged in the response).

**Existing keys read (no shape changes):**

- `tenant:{tenant_id}` — tenant config: `input_guardrails`, `output_guardrails`,
  `rbac.roles`, `plan` (as used by `storage/evidence_pack.py`).
- `agents:{tenant_id}` — registered agents: name, status, `tools`,
  `role_permissions`, `allowed_resources`, timestamps.
- `unregistered:{tenant_id}` — shadow agents/tools observed in traffic.
- `tool_definitions:{tenant_id}` — tenant-defined tools.
- `policies:{tenant_id}`, `tool_policies:{tenant_id}`,
  `policy:{tenant_id}:{policy_id}` — tool/custom policies
  (`storage/policy_store.py`).
- `mcp_gateway:routes:{tenant_id}`, `mcp_gateway:upstream:{tenant_id}:{route}` —
  MCP servers behind the gateway (`storage/mcp_gateway_store.py`).
- `agent_trust:{tenant_id}:{agent_key}` — cert/trust registry entries.
- `agent_auth_stats` last-seen/recent buffers (`storage/agent_auth_stats.py`,
  bounded to `RECENT_BUFFER_MAX=50` recent events — the same bounded-window
  caveat `routes_governance.py` documents).
- `storage/guardrail_metrics.get_all_guardrails_summary` — guardrail
  effectiveness for the observability section.

**Secrets rule (hard).** Declared components may contain *references* only
(`secrets_used: ["OPENAI_API_KEY"]` — names, never values). The declare
endpoint rejects any value matching obvious credential shapes (e.g. `sk-`,
`AKIA`, PEM headers) with a 422; the generator never reads the vault
(`storage/vault_store.py`) into a BOM.

## 4. API / interface

Router: `api/routes_aibom.py`, prefix `/v1/tenant/me/aibom`, mounted by
`admin_app.py` next to `evidence_router`. Auth: tenant API key — same
`_require_tenant`-style resolution as `api/routes_evidence.py`
(`request.state.tenant_id` populated by the existing auth middleware from
`X-API-Key`); 401 without it. Admin-key access to other tenants' BOMs is *not*
in v1.

| Method & path | Purpose | Response (200) |
|---|---|---|
| `GET /v1/tenant/me/aibom` | Generate current AIBOM. Query: `view=full\|observed\|declared` (default `full`) | AIBOM doc (below) |
| `GET /v1/tenant/me/aibom/components` | Read declared components | `{"declared": {...}, "updated_at"}` |
| `PUT /v1/tenant/me/aibom/components/{section}` | Upsert declared entries for one section (`models`, `prompts`, `knowledge_sources`, `memory`, `supply_chain`, `metadata`). Body: `{"components": {id: {...}}}`; merge-by-id, `null` deletes an id | updated section |
| `DELETE /v1/tenant/me/aibom/components/{section}/{component_id}` | Remove one declared entry | `{"deleted": true}` |
| `POST /v1/tenant/me/aibom/snapshots` | Snapshot the current full AIBOM as an approved baseline. Body: `{"note"?, "approved_by"?}` | `{"snapshot_id", ...index entry}` |
| `GET /v1/tenant/me/aibom/snapshots` | List snapshots (index) | `{"snapshots": [...]}` |
| `GET /v1/tenant/me/aibom/snapshots/{snapshot_id}` | Fetch one full snapshot | snapshot doc |
| `GET /v1/tenant/me/aibom/drift` | Diff current AIBOM vs latest (or `?snapshot_id=`) approved snapshot | drift report (below) |

Status codes: 401 no/invalid key; 404 unknown snapshot / no snapshot for drift
(`{"detail": "no approved snapshot — POST /snapshots first"}`); 422 invalid
section name, oversized payload, or credential-shaped value; 409 reserved (not
used in v1).

**AIBOM document (JSON, maps to AIBOM Spec v1.0 sections):**

```json
{
  "bom_format": "aibom",
  "spec_version": "1.0",
  "view": "full",
  "metadata": {                       // §2 Metadata
    "application": "<tenant name>", "tenant_id": "...", "environment": "...",
    "generated_at": "ISO8601", "generated_by": "llm-shield/<version>",
    "organization": "...", "owner": "...", "git_commit": null, "deployment_id": null
  },
  "models": [ ... ],                  // §3  declared (name, provider, version, endpoint, context_window, capabilities, license, risk_rating, ...)
  "prompts": [ ... ],                 // §4  declared (prompt_id, version, owner, type, variables, secrets_used[names], injection_protection, ...)
  "agents": [ {                       // §5  observed: registry + shadow
    "agent_id", "name", "source": "registered|shadow",
    "status", "allowed_tools", "allowed_resources", "roles",
    "human_approval_required", "first_seen", "last_seen", "recent_tools_used"
  } ],
  "mcp_servers": [ ... ],             // §6  observed: gateway routes + upstream endpoint, auth mode, allowed agents
  "tools": [ ... ],                   // §7  observed: tool_definitions + tool_policies (permissions, sensitive flags, killswitch state)
  "identity": { ... },                // §8  observed: rbac roles, token issuer config, trust-registry count, key rotation via signer config
  "knowledge_sources": [ ... ],       // §9  declared
  "memory": [ ... ],                  // §10 declared + observed memory-guardrail enablement
  "guardrails": [ ... ],              // §11 observed: input/output guardrails from tenant config + custom policies (policy_id, severity, action, fail mode)
  "runtime_policies": [ ... ],        // §12 observed: tool policies, rate limits, budgets, approval rules
  "observability": { ... },           // §13 summary: metrics/audit/SIEM/webhooks configured, windows
  "supply_chain": [ ... ],            // §14 declared (version, hash, license per entry; CVEs are v2)
  "threats": [ ... ],                 // §15 static mapping: component type -> threat ids (Task 4)
  "compliance": [ ... ],              // §16 static mapping: component/guardrail -> framework controls (Task 4)
  "risk": { "per_asset": [...], "overall": "low|medium|high|critical" },  // §17 heuristic (Task 4)
  "generation_notes": [ "agent activity window is last 50 auth events", ... ]
}
```

`view=observed` returns only Shield-derived sections (empty declared sections);
`view=declared` the inverse. Every section that fails to load or is truncated
adds an explicit entry to `generation_notes` — no silent gaps.

**Risk heuristic (v1, §17 + Appendix A of the AIBOM spec).** Per asset, a
transparent lookup — not ML: base likelihood by exposure (shadow agent >
registered; internet/db/filesystem-flagged tool > plain tool), impact by
privilege (granted sensitive tools, `used_not_granted` drift), formula
`likelihood × impact` bucketed into `low/medium/high/critical`, with the inputs
echoed in the entry so the score is auditable. Weights live in one dict in
`storage/aibom.py` with tests as the contract.

**Drift report:**

```json
{
  "tenant_id": "...", "snapshot_id": "bom-...", "snapshot_created_at": "...",
  "computed_at": "...",
  "drift": {
    "agents":      {"added": [...], "removed": [...], "changed": [{"agent_id", "field", "before", "after"}]},
    "tools":       {"added": [...], "removed": [...], "changed": [...]},
    "mcp_servers": {...}, "guardrails": {...}, "runtime_policies": {...},
    "models": {...}, "prompts": {...}, "identity": {...}
  },
  "drift_count": 3, "clean": false
}
```

Volatile fields (`last_seen`, `recent_tools_used`, timestamps, metrics,
`generated_at`, `generation_notes`, `observability`) are **excluded** from the
diff so drift means configuration drift, not traffic. When `drift_count > 0`
and the tenant has a webhook subscribed to `aibom_drift_detected` (added to
`VALID_EVENTS` in `api/routes_webhooks.py`), the existing webhook dispatcher
fires with the summary (counts + section names, not the full BOM).

## 5. Security & backward compatibility

- **Purely additive.** New router + new keys; no existing endpoint, key shape,
  or default changes. No escape-hatch flag needed. `aibom_drift_detected` is a
  new webhook event type — only fires for tenants that explicitly subscribe.
- **Authz.** Tenant API key required on every route; tenant can only ever
  read/write `*:{own tenant_id}` keys. A malicious caller with a stolen tenant
  key learns that tenant's inventory (which the portal already exposes via
  governance/registry endpoints) — no new privilege, no cross-tenant surface,
  no secret material in any BOM (§3 secrets rule).
- **Input hardening on declares.** Section allowlist; per-section payload cap
  **64 KB** and max **200 component ids**; component ids sanitized
  (`[A-Za-z0-9._-]{1,128}`); credential-shape rejection (§3); values stored
  as-is otherwise (schema-light by design — the AIBOM spec's per-section fields
  are recommended, not enforced, in v1).
- **No model/LLM calls, no egress.** Generation is pure KV aggregation; the
  webhook uses the existing dispatcher and its URL-allowlist checks.

## 6. Packaging & deploy

- **New modules:**
  - `storage/aibom.py` — generator (`generate_aibom(tenant_id, view) -> dict`),
    section builders, drift differ, risk heuristic. Pure stdlib + existing
    storage imports.
  - `api/routes_aibom.py` — the router.
  - (Task 4) `storage/aibom_mappings.py` — static threat/compliance tables.
- **`Dockerfile.admin`:** `admin_app.py` will import `api/routes_aibom.py` ⇒
  add `COPY api/routes_aibom.py api/`, `COPY storage/aibom.py storage/` (and
  `storage/aibom_mappings.py` in Task 4) to the allowlist **in the same PR**.
  `tests/test_admin_dockerfile_imports.py` enforces this automatically.
- **Dependencies: none.** stdlib only (`json`, `time`, `hashlib`, `secrets`).
  No change to `requirements*.txt`. Validate in a clean venv anyway.
- **Env flags:** none required. (Webhook event fires only on subscription, so
  no kill-switch flag is needed.)
- **Images to rebuild:** admin image only. Data-plane image untouched.

## 7. Failure modes & edge cases

- **Redis down / section source fails** → fail-soft per section, exactly like
  `storage/evidence_pack._collect_data`: each builder is wrapped, a failed
  section returns `[]`/`{}` plus a `generation_notes` entry
  (`"agents: source unavailable"`). The endpoint itself returns 200 with what
  it has; **declares and snapshots fail-closed** (500/503) rather than writing
  through a broken store.
- **Empty tenant** (nothing registered, nothing declared) → valid BOM with
  empty sections and `generation_notes` explaining each; `drift` without a
  snapshot → 404 with remediation hint.
- **Huge registries** → per-section emission caps (500 agents / 500 tools / 200
  MCP routes), sorted deterministically (registered before shadow, then id);
  anything dropped is counted in `generation_notes` — no silent truncation.
- **Snapshot size** → snapshot stores the doc minus volatile fields; hard cap
  **512 KB** per snapshot (413-style 422 with the size if exceeded).
- **Concurrent declares** → last-write-wins per section (same semantics as the
  registry's `kv_set` usage today); acceptable for portal-driven config. Noted
  in the doc as not a CAS store.
- **Bounded activity window** → runtime fields derive from the last
  `RECENT_BUFFER_MAX=50` auth events; the BOM says so in `generation_notes`
  (same honesty note `routes_governance.py` uses). Absence of recent activity
  is never reported as "component gone" — drift compares configuration, not
  traffic (§4).
- **Clock/ordering** → `generated_at` is server UTC; drift uses stored snapshot
  content, never wall-clock inference.
- **Webhook endpoint down** → dispatcher's existing retry/failure handling; a
  webhook failure never fails the `/drift` request.

## 8. Test plan (Definition of Done)

Unit tests (`tests/test_aibom.py`, `tests/test_aibom_drift.py`), using the
in-memory fallback store / monkeypatched `kv_get`-style fakes as
`tests/test_governance_endpoints.py` does:

1. **Generator happy path** — seeded `agents:{t}`, `unregistered:{t}`,
   `tool_definitions:{t}`, `tool_policies:{t}`, `mcp_gateway:routes:{t}`,
   tenant config guardrails → BOM contains each mapped section;
   `bom_format`/`spec_version` present; registered vs `shadow` sources correct.
2. **Views** — `observed` omits declared sections; `declared` omits observed.
3. **Empty tenant** — valid doc, empty sections, notes populated.
4. **Fail-soft** — a builder that raises → 200, empty section, note present.
5. **Declared CRUD** — upsert/merge/delete by id; bad section → 422; >64 KB or
   >200 ids → 422; `sk-...` value → 422; id sanitization.
6. **Tenant isolation** — two tenants' declares/snapshots never bleed
   (key-format assertion + behavioral test).
7. **Snapshots** — create/list/get; index eviction at 20 with note; volatile
   fields stripped; size cap.
8. **Drift** — no snapshot → 404; identical state → `clean: true`; add an
   agent tool grant → exactly one `changed` entry (before/after); new shadow
   agent → `added`; volatile churn (`last_seen`, metrics) → still clean;
   webhook fired once on drift for subscribed tenant, not fired when clean.
9. **Risk heuristic** (Task 4) — deterministic per-asset ratings for fixed
   inputs; shadow agent with sensitive tool ⇒ ≥ high.
10. **Regression guards** — `tests/test_admin_dockerfile_imports.py` passes
    (new imports COPY'd); no new pip imports (import-scan of new modules).
11. **Clean venv** — `python -m venv /tmp/x && /tmp/x/bin/pip install -r
    requirements-test.txt` then `python -m pytest tests -q` green; CI `pytest`
    gate passes.

## Invariant risk flags

- ✅ **Off the hot path** — admin-plane read aggregation over already-written
  data; zero new code or writes on `/guardrails/*`, `cap/mint`, `tools/call` (§2).
- ⚠️ **New admin imports** — `api/routes_aibom.py` + `storage/aibom.py` must be
  added to `Dockerfile.admin` **in the same PR** (crash-loop incident class);
  guard test covers it (§6).
- ✅ **No new dependencies** — stdlib only; clean-venv validation still required (§6).
- ✅ **Non-breaking, secure by default** — additive routes/keys; new webhook
  event is subscribe-only; declares are size-capped, sanitized, and reject
  credential-shaped values; BOMs never contain secret values (§5).
- ✅ **Self-contained PRs** — each task below carries its own Dockerfile/test
  updates (§6, §8).

## Task breakdown (one small PR each, in order)

1. **PR 1 — Observed-BOM generator + `GET /aibom`.** `storage/aibom.py`
   (metadata, agents, tools, mcp_servers, guardrails, runtime_policies,
   identity, observability builders; fail-soft; notes; caps) +
   `api/routes_aibom.py` with the single GET + `Dockerfile.admin` COPYs.
   Tests 1–4, 6 (observed half), 10, 11.
2. **PR 2 — Declared components.** `components` CRUD (models, prompts,
   knowledge_sources, memory, supply_chain, metadata), validation/hardening,
   merge into `view=full|declared`. Tests 2, 5, 6.
3. **PR 3 — Snapshots + drift + webhook.** Snapshot store/index/eviction,
   volatile-field stripping, drift differ, `aibom_drift_detected` in
   `VALID_EVENTS` + dispatch. Tests 7, 8.
4. **PR 4 — Threat/compliance mappings + risk.** `storage/aibom_mappings.py`
   static tables (§15/§16: OWASP LLM Top 10, NIST AI RMF, ISO 42001, EU AI Act
   control refs per component type/guardrail) + risk heuristic (§17). Test 9 +
   mapping-table sanity tests. Docs page `docs/aibom.md` (customer-facing —
   follow the no-em-dash convention there).

## Addendum: interop tasks (approved after k8s-aibom review)

Motivated by GoogleCloudPlatform/k8s-aibom (cluster-side runtime ML-BOMs in
CycloneDX 1.6): Shield's BOM covers the governance layer, theirs the infra
layer — interop merges both into one tenant document. Same invariants apply
(admin plane, off hot path, stdlib only, additive).

5. **PR 5 — Manifest upload.** `PUT /v1/tenant/me/aibom/components` (no
   section) accepts the whole declared doc `{section: {id: comp|null}}` in one
   call — the CI-friendly `aibom.json` manifest workflow. Same per-section
   validation/caps as the per-section route; all-or-nothing (any invalid
   section rejects the request).
6. **PR 6 — CycloneDX 1.6 ML-BOM export.** `GET /aibom?format=cyclonedx` maps
   the document: models → `machine-learning-model`, knowledge_sources/memory/
   prompts → `data`, supply_chain → `library`, agents/tools/guardrails →
   `application` with `shield:*` properties, MCP servers → `services`.
   New pure module `storage/aibom_interop.py` (+ Dockerfile.admin COPY).
7. **PR 7 — BOM ingest.** `POST /aibom/ingest` accepts a CycloneDX JSON doc
   (e.g. k8s-aibom's webhook sink pointed at Shield) and merges its components
   into the declared sections by type, id-sanitized, provenance-tagged
   (`source: cyclonedx-ingest`). Credential-shaped values are *skipped* (bulk
   path) and counted in the response; post-merge section caps reject with 422
   (no silent truncation). Body cap 1 MB.

## Open questions (answer before implementation)

1. **Webhook in v1?** Recommended **yes** (PR 3) — the dispatcher and
   subscription model already exist, marginal cost is one `VALID_EVENTS` entry.
   Drop from v1 if you want drift strictly pull-based.
2. **Admin-key cross-tenant read** (`/v1/admin/tenants/{id}/aibom`) for the
   platform operator — defer to v2? Recommended **defer**.
3. **Environment field** (§2 metadata): tenant config has no
   dev/stage/prod field today. v1 takes it from declared `metadata`
   (`environment`) and reports `null` otherwise. OK, or add it to tenant
   config? Recommended **declared-only for v1**.
