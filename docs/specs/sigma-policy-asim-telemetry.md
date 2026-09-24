---
title: "Spec: Sigma policy + ASIM telemetry logging"
layout: default
nav_exclude: true
permalink: /specs/sigma-policy-asim-telemetry/
description: Log Shield telemetry in Microsoft ASIM-normalized format, and add a deterministic Votal Policy schema with Sigma-rule import/export — built on the existing telemetry pipeline, decision-audit stream, SIEM fan-out, and monitor→enforce lifecycle.
---

# Spec: Sigma policy + ASIM telemetry logging

> Status: **APPROVED — implementing.** PR1 (ASIM telemetry logging) landed on
> `feat/sigma`; PRs 2-5 (Votal Policy, Sigma import, detection engine, Sigma
> export) pending.
> Two pillars: **(A) ASIM-normalized telemetry logging** and **(B) a deterministic
> Votal Policy schema with Sigma import/export.** Both extend existing surfaces —
> the OTel telemetry pipeline (`core/telemetry.py`), the decision-audit stream
> (`storage/decision_audit.py`), the SIEM fan-out (`core/siem_dispatcher.py`), the
> webhook envelope (`core/webhook_dispatcher.py`), and the monitor→enforce
> lifecycle (`core/policy_mode.py`). **Sigma/ASIM code is greenfield** — nothing to
> reconcile, everything to integrate with.

## 1. Problem & outcome

Shield decides `allow/block/warn/redact/confirm` on every guarded call and already
ships telemetry to SIEMs (`core/telemetry.py`: Elasticsearch, Splunk HEC, OTLP,
file; `core/siem_dispatcher.py`: Splunk, Sentinel, ECS). Two capabilities security
teams expect are missing:

**A. ASIM-normalized telemetry.** Today an event's field names depend on the
exporter — the internal event dict (`core/telemetry.py:27`), the `decision_audit`
record (`storage/decision_audit.py:55-67`), the webhook envelope
(`core/webhook_dispatcher.py:92-97`), and an inline ECS mapping
(`core/siem_dispatcher.py:132-148`) are overlapping ad-hoc shapes. A Microsoft
Sentinel customer has to write custom parsers to normalize them. If Shield emits
telemetry already conformant to **ASIM (Advanced Security Information Model)** — the
schema Sentinel's built-in analytics and hunting queries expect (`ActorUsername`,
`SrcIpAddr`, `DstIpAddr`, `EventResult`, `DvcAction`, …) — those detections work
against Shield events **without a custom parser**, and the same normalized shape is
what portable Sigma rules match on.

**B. A deterministic, declarative policy language + Sigma interop.** The only
tenant-authored policy today is `custom_policy` — a **free-text prompt evaluated by
an LLM** (`guardrails/input/custom_policy.py`, `tier="slow"`) — plus
`role_based_policy` (tool+role rules, also LLM-evaluated). There is **no** way to
say, structurally and without model latency, *"when an `ai_agent` makes a
`tool_call` returning `PII` to an `external` destination and the agent is not
on the allow-list → block + alert,"* and **no** way to ingest or emit **Sigma**
rules (the portable detection format security teams standardize on across
Sentinel/Splunk/Elastic/QRadar).

**Outcome (observable success).**
1. With ASIM logging enabled, every telemetry event Shield emits carries **ASIM
   field names** (a documented Shield→ASIM mapping), with AI-native attributes
   (agent id, tool, data classification, risk) in ASIM's `AdditionalFields`. A
   Sentinel query written against the ASIM `AuditEvent`/`WebSession` schema returns
   Shield decisions unmodified. With ASIM logging **off**, telemetry is
   byte-identical to today.
2. A **Votal Policy** document (`when` / `conditions` / `actions`) that a tenant
   authors, that **validates and compiles deterministically** into existing Shield
   enforcement config, and that lands in **monitor** mode first (inherits
   `core/policy_mode.py`).
3. **Sigma import** (a Sigma YAML rule becomes a stored detection over the ASIM
   event fields) and **Sigma export** (a detection is emitted as portable Sigma).
   A detection match emits a `detection_matched` telemetry/alert event through the
   existing pipelines.
4. **Zero added guard-path latency** and **zero behavior change** until opt-in.

**Non-goals.**
- **Not** making Sigma the enforcement format (Sigma *detects*; Votal Policy
  *enforces*). Sigma is import/export interop only.
- **Not** adding an LLM call to the hot path — the Votal Policy engine is
  **deterministic structured-field matching**, never a prompt.
- **Not** replacing `custom_policy` / `role_based_policy` (kept for cases needing
  model judgment; a Votal Policy may reference them).
- **Not** reimplementing full ASIM. We map to the **subset of ASIM common fields**
  Shield can populate honestly, plus AI-native `AdditionalFields`; unmapped ASIM
  fields are simply absent (documented), not faked.
- **Not** a new telemetry transport or queue — ASIM is a **formatting stage** on
  the existing pipeline; detection consumes the existing stream.
- **Not** the cumulative-exfiltration ledger (cross-call budget accounting) — a
  ledger event is just another ASIM event this can match.
- **Not** the edge/Jetson deployment (dropped from this workstream for now).

## 2. Plane & latency contract

- **Plane:**
  - **A (ASIM logging):** **data-plane telemetry pipeline** — a pure formatting
    stage in `core/telemetry.py`, applied in the **off-thread flush/export path**,
    not in the request path.
  - **B (policy + Sigma):** **admin plane** for authoring, compilation,
    import/export (mirrors `api/routes_siem.py`, mounted in `admin_app.py`); the
    **detection engine runs off-thread** over the emitted event stream. The only
    data-plane touch is that **compiled** policy config is read by the *existing*
    guards that already read tenant config — **no new inline evaluator in v1.**
- **Touches the guard path?** **No.**
  - ASIM formatting runs where `record_event` buffers and the flush loop exports
    (`core/telemetry.py:27`, flush loop) — already off the request path (telemetry
    "errors never affect the main request", `core/telemetry_middleware.py:43`).
    **+0ms.**
  - Detection/normalization/import/export/alerting operate on the *already-emitted*
    stream, off-thread — same discipline as `audit_chain.enqueue`
    (`storage/audit_chain.py:341-385`) and `asyncio.create_task(dispatch_event)`
    (`api/routes_tool.py:588-612`).
  - Enforcement is unchanged: a Votal Policy **compiles to existing enforcement
    primitives** (tenant `input_guardrails`/`output_guardrails`,
    `data_policies:{tenant}`, `tool_policies:{tenant}`) evaluated by the current
    fast-tier guards. **No new getenv/branch/I/O** on `routes_classify.py` /
    `routes_tool.py` / `core/mcp/enforcement.py`. A future inline deterministic
    `votal_policy` guard is a **separate, later task** with its own sub-ms budget.
- **`cap/mint` / `tools/call` / `/guardrails/*`** are not modified.

## 3. Data model

### 3.1 ASIM event (pillar A) — a formatting stage, not a new store

The **ASIM-normalized event is derived**, never a second write. A pure mapper
`to_asim(event: dict) -> dict` (`core/asim.py`) maps the internal telemetry event
(and, where applicable, a `decision_audit` entry) to ASIM field names. It runs in
the flush/export path when the format is `asim`.

**Shield → ASIM field map (representative; full table in the module + docs):**

| ASIM field | Source |
|---|---|
| `EventVendor` | `"Votal"` (constant) |
| `EventProduct` | `"Shield"` (constant) |
| `EventType` | mapped from `event_type` (`guardrail_input`→`WebSession`/`AuditEvent`, `agent_tool_call`→`AuditEvent`) |
| `EventResult` | `Success`/`Failure`/`Partial` from `action` (`block`→`Failure`, `pass`→`Success`, `warn`/`redact`→`Partial`) |
| `EventSeverity` | from guardrail severity / risk level |
| `EventStartTime` | `@timestamp` / record `timestamp` |
| `DvcAction` | `action` (`block|allow|warn|redact|...`) |
| `ActorUsername` | `user_role` / `X-Device-Id` |
| `SrcIpAddr` | `source_ip` |
| `TargetAppName` / `Url` | `X-Shield-Destination` (host) |
| `RuleName` | deciding `guardrail` / `policy_id` |
| `AdditionalFields` | **AI-native**: `AgentId`, `ToolName`, `ToolServer`, `DataClassification[]`, `RiskScore`, `RiskLevel`, `DestinationTrust`, `SessionId`, `Reason` |

AI-native attributes that have no ASIM home live in `AdditionalFields` (ASIM's
sanctioned extension point), so the record stays ASIM-valid while carrying agent
context. Fields Shield cannot populate are **omitted**, not zero-filled.

Integrity: ASIM events derived from `decision_audit` entries inherit the
tamper-evident chain for free — every decision is already enqueued to
`auditchain:decisions:{tenant}` (`storage/decision_audit.py:97-102`).

### 3.2 Policy & detection stores (pillar B)

New Redis keys, tenant-scoped, mirroring `storage/policy_store.py` /
`storage/siem_store.py`. No TTL — configuration.

| Key | Shape |
|---|---|
| `votal_policies:{tenant_id}` (SET) + `votal_policy:{tenant_id}:{policy_id}` | Votal Policy JSON (§4.2) |
| `detections:{tenant_id}` (SET) + `detection:{tenant_id}:{detection_id}` | detection JSON: `title,id,status,logsource,detection,condition,level,tags[],source:"sigma|votal",enabled` |

**Tenant scoping:** every key is `{tenant_id}`-scoped; tenant resolves via the
existing `core/middleware.py` API-key path. No cross-tenant read. `decisions:global`
is admin-only, never in a tenant view.

## 4. API / interface

### 4.1 ASIM logging (config, no new endpoint)
Enabled by config/env on the existing telemetry pipeline — no request-path API.

| Var | Default | Effect |
|---|---|---|
| `VOTAL_TELEMETRY_FORMAT` | `native` | `asim` applies `to_asim()` to every exported event (file/ES/Splunk/OTLP) |
| SIEM config `type: "asim"` | — | optional ASIM formatter in `core/siem_dispatcher.py` alongside `ecs`/`sentinel` for the per-tenant SIEM fan-out |

`GET /telemetry` (existing portal, `core/app.py:201`) and the file sink
(`logs/votal-shield.json`) render whichever format is configured.

### 4.2 Votal Policy (admin plane; `/v1/tenant/me/...` like `routes_siem`)
- `POST|GET|PUT|DELETE /v1/tenant/me/policies[/{id}]` — CRUD.
- `POST .../policies/{id}/compile` — **dry-run**: returns the exact tenant-config
  diff it would produce, without applying (the reviewability the workflow wants).
- `POST .../policies/{id}/apply` — writes compiled config, lands in **monitor**
  via `core.policy_mode`; operator flips to enforce via the existing
  `.../policy-mode`. Logged via `storage/admin_audit.py`.

Policy document (deterministic):
```yaml
apiVersion: votal.ai/v1
kind: SecurityPolicy
metadata: { name: agent-sensitive-data-exfiltration, severity: critical }
when:
  actor.type: ai_agent
  event.type: [tool_call, http_request, data_transfer]
conditions:
  - { field: data.classification, operator: in,     value: [PII, PHI, PCI, SECRET] }
  - { field: destination.trust,   operator: equals, value: external }
  - { field: actor.id,            operator: not_in, value: [approved-agent-01] }
actions:
  - block
  - { create_alert: { severity: critical } }
  - { log: { include: [actor.id, tool.name, destination, data.classification, policy.id] } }
```
`operator` ∈ `{equals, not_equals, in, not_in, contains, contains_any, regex, gt,
lt, exists}` (all deterministic). `action` maps onto the existing enum `{pass,
warn, redact, block, log, pending_confirmation, monitor}` plus `create_alert`
(→ `dispatch_event`). `field` paths address ASIM/AI-native fields (§3.1).

### 4.3 Detections + Sigma interop (admin plane)
- `POST|GET|PUT|DELETE /v1/tenant/me/detections[/{id}]` — CRUD.
- `POST .../detections/import/sigma` — Sigma YAML → stored detection
  (`source:"sigma"`), fields mapped to ASIM (§3.1).
- `GET  .../detections/{id}/export/sigma` — detection → portable Sigma YAML.
- `POST .../detections/{id}/test` — run against recent ASIM events (from
  `query_decisions`, `storage/decision_audit.py:107-181`); returns matches, no
  side effects.

### 4.4 Alert on match
A match emits `detection_matched` via the existing
`dispatch_event(tenant_id, "detection_matched", asim_event)`
(`core/webhook_dispatcher.py:92`) → webhooks **and** the SIEM tail
`dispatch_to_siem` (`:136-141`), and via `record_event` into the telemetry
pipeline. Requires adding `detection_matched` to the vocabulary in
`core/siem_dispatcher.py:36-39` and the `storage/siem_store.py` docstring
(one-line extensions).

**Auth:** `X-API-Key` (tenant) for `/v1/tenant/me/*`; admin key for `/v1/admin/*`.

## 5. Security & backward compatibility

- **Default OFF / non-breaking.** `VOTAL_TELEMETRY_FORMAT` defaults to `native`
  (telemetry byte-identical to today). Policy/detection routers gate on
  `SHIELD_ENABLE_DETECTIONS` (+ master `SHIELD_ENABLE_ENTERPRISE`,
  `core/feature_flags.py`); with the flag unset and nothing configured, the
  routers are inert and the detection consumer does not run.
- **Compiled policies land in `monitor`.** A Votal Policy inherits the
  monitor→enforce dry-run of `core/policy_mode.py` (`apply` flips would-be blocks
  to allowed and tags `enforced:False` in monitor, `:56-103`), so a new policy
  cannot silently start blocking live traffic. Migration note ships with it:
  author → compile (dry-run diff) → apply (monitor) → review would-blocks →
  flip enforce.
- **Deterministic, no model on the hot path** — enforcement is via existing
  fast-tier guards reading compiled config; explicit contrast with `custom_policy`
  (slow tier).
- **Untrusted Sigma YAML.** Import is declarative-only (no code/eval),
  schema-validated, size-capped; embedded patterns compile with the **`regex`
  module's bounded `timeout=`** (the repo's ReDoS mitigation, `icap/policy.py`). A
  rule that fails validation is rejected and **never disarms existing detections**.
- **PII in ASIM logs.** ASIM events can carry sensitive attributes (usernames,
  destinations, classifications). ASIM logging honors the existing telemetry
  redaction posture; the doc states that pointing an exporter at a third party is a
  data-egress decision (same warning as `docs/ollama-backend.md`). `AdditionalFields`
  never carries raw prompt bodies (only classifications/ids), matching the ICAP
  "never log bodies" rule.
- **Authz / SSRF:** a tenant key reaches only its own policies/detections/events;
  `decisions:global` and other tenants are structurally unreachable. Alert
  destinations reuse the SIEM/webhook **SSRF guard** (`validate_outbound_url`,
  `core/webhook_dispatcher.py:112-116`).
- **Fail-open vs fail-closed:** ASIM formatting, detection, and alerting are
  **fail-open** (pure telemetry — a formatter/engine error never blocks traffic;
  on `to_asim` error, fall back to the native event rather than dropping it).
  Enforcement polarity is unchanged (it remains the existing guards).

## 6. Packaging & deploy

- **New modules:**

  | Module | Plane | Role |
  |---|---|---|
  | `core/asim.py` | data (telemetry) | `to_asim()` mapper + Shield→ASIM field table |
  | `core/detection/sigma.py` | admin | Sigma YAML ↔ detection (import/export), bounded regex |
  | `core/detection/engine.py` | admin/worker | deterministic matcher over ASIM events |
  | `core/votal_policy/schema.py` | admin | Votal Policy model + validator |
  | `core/votal_policy/compiler.py` | admin | policy → existing tenant-config primitives |
  | `storage/detection_store.py` | admin | `detections:{tenant}` CRUD |
  | `storage/votal_policy_store.py` | admin | `votal_policy:{tenant}` CRUD |
  | `api/routes_detections.py` | admin | §4.3 router |
  | `api/routes_policies.py` | admin | §4.2 router |

- **`Dockerfile.admin` (INVARIANT RISK — fix in the same PR that mounts each).**
  Add COPY lines for every admin-imported new module above, plus **`core/asim.py`
  if the admin-plane SIEM path (`core/siem_dispatcher.py`, already copied at
  `:149`) references it** for the `type:"asim"` formatter. Guarded by
  `tests/test_admin_dockerfile_imports.py` (walks the transitive import graph).
  Build-on modules already in the allowlist: `storage/decision_audit.py:140`,
  `storage/siem_store.py:148`, `core/siem_dispatcher.py:149`,
  `core/webhook_dispatcher.py:58`, `core/policy_mode.py:42`,
  `storage/policy_store.py:136`, `storage/custom_policies.py:134`.
- **Dependencies:** **none new.** ASIM/Sigma are dict/YAML transforms → `PyYAML`
  (already in `requirements.txt`); bounded matching → `regex` (already declared).
  We implement a **minimal Sigma subset** ourselves (selections;
  `contains|startswith|endswith|re` modifiers; `condition` of `and/or/not/1 of/all
  of`), same rationale as the hand-rolled ICAP server; **`pySigma` is explicitly
  rejected** to avoid a heavy transitive dep. If full Sigma coverage is needed
  later, it lands with the dep in `requirements.txt` + `requirements-test.txt`
  + `requirements-admin.txt` together.
- **Env flags:** `VOTAL_TELEMETRY_FORMAT` (`native`|`asim`), `SHIELD_ENABLE_DETECTIONS`,
  `SHIELD_DETECTION_SCAN_TIMEOUT_MS` (default 250, the per-rule regex budget).
- **Rebuild:** data-plane image (ASIM formatter in the telemetry pipeline) + admin
  image (policy/detection routers). No change to `cap/mint`/`tools/call` images'
  behavior.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| `VOTAL_TELEMETRY_FORMAT=native` (default) | Telemetry byte-identical to today. |
| `to_asim()` raises on a malformed event | Fall back to emitting the **native** event (never drop telemetry, never block traffic). Logged once. |
| Event field with no ASIM home | Carried in `AdditionalFields`; a field Shield can't populate is omitted, not faked. |
| Flag off / no policies or detections | Routers inert, consumer idle; **byte-identical to today**. |
| Malformed / unsupported Sigma on import | Rejected with a validation error; existing detections untouched. |
| Sigma construct outside the supported subset | `unsupported: <construct>`; nothing partially stored. |
| Catastrophic regex in a detection/policy | Bounded by `regex` `timeout=` (`SHIELD_DETECTION_SCAN_TIMEOUT_MS`); on expiry the rule is skipped for that event and logged. |
| Policy compiles to no effective enforcement (all-`log`) | Applied as a no-op with a warning (mirrors ICAP's all-`redact` case). |
| Conflicting policies | `priority` ordering (lower=higher, reusing `custom_policies` convention `:120`); most-severe action wins. |
| Redis down | Authoring 5xx; off-thread consumer degrades and retries; **guarded traffic unaffected**. |
| Huge event volume | Detection runs over the capped `decisions` LISTs (50k tenant / 200k global) with limit/offset; telemetry buffer is bounded (`deque(maxlen=10000)`). |
| Empty/absent fields in a match | `exists`/`in` semantics; a condition on an absent field does not match (never a crash). |
| Concurrent policy edits | Last-writer-wins on `{policy_id}` + `version` bump (as `custom_policies`); index SET idempotent. |

**Fail-open vs fail-closed, stated:** all of pillar A and the detection/alert side
of pillar B are **fail-open** (pure telemetry). Enforcement polarity is unchanged
(existing guards).

## 8. Test plan (Definition of Done)

- **ASIM mapping** (`tests/test_asim.py`): a representative telemetry event and a
  `decision_audit` entry map to ASIM field names per §3.1; AI-native attributes
  land in `AdditionalFields`; unmappable fields omitted; `EventResult`/`DvcAction`
  derive correctly from each `action`; a malformed event falls back to native
  (no drop). Assert the mapper is **pure** (no I/O, no `llm_backend` call).
- **Telemetry integration** (`tests/test_telemetry_asim.py`): with
  `VOTAL_TELEMETRY_FORMAT=asim`, exported events are ASIM-shaped; with `native`,
  **byte-identical to today** (regression); formatting happens in the flush path,
  not the request path (no hot-path call).
- **Votal Policy** (`tests/test_votal_policy.py`): schema validation (good/bad);
  every `operator` matches/does-not-match crafted ASIM events **with no
  `core/llm_backend` call** (proves deterministic); the compiler produces the
  expected `input_guardrails`/`data_policies` diff; an applied policy lands in
  **monitor** and a would-block is tagged `enforced:False`.
- **Sigma interop** (`tests/test_detection_sigma.py`): import a canonical Sigma
  rule → detection → export → Sigma, asserting a stable round-trip on the
  supported subset; unsupported construct rejected cleanly; catastrophic pattern
  bounded by the timeout (ReDoS regression).
- **Detection engine** (`tests/test_detection_engine.py`): a matching ASIM event
  emits one `detection_matched` via `dispatch_event` reaching webhook + SIEM
  fan-out (`event.kind:"alert"`) and `record_event`; a non-match emits nothing.
- **Admin packaging** (`tests/test_admin_dockerfile_imports.py`): green with the
  new COPY lines — regression guard for the Dockerfile↔imports coupling. Each new
  admin module (and `core/asim.py` if referenced by the SIEM path) is covered.
- **Backward-compat:** flag off / format native → existing guard-path, proxy, and
  telemetry tests unchanged; no new guard-path latency.
- Full suite green in a **clean venv**; CI `pytest` gate passes.

## 9. Task breakdown (one branch, ordered increments)

1. **PR1 — ASIM telemetry logging.** `core/asim.py` (mapper + field table),
   wire the `asim` format into `core/telemetry.py`'s flush/export path
   (`VOTAL_TELEMETRY_FORMAT`), optional `type:"asim"` in `core/siem_dispatcher.py`
   + `Dockerfile.admin` COPY if the SIEM path references it, `docs` field-mapping
   table. `tests/test_asim.py`, `tests/test_telemetry_asim.py`.
   *(Self-contained; pillar A ships alone.)*
2. **PR2 — Votal Policy schema + compiler + monitor gating.**
   `core/votal_policy/{schema,compiler}.py`, `storage/votal_policy_store.py`,
   `api/routes_policies.py` (CRUD + compile dry-run + apply→monitor),
   `Dockerfile.admin` COPY + import-drift test. `tests/test_votal_policy.py`.
   **No hot-path evaluator added.**
3. **PR3 — Sigma import + detection store.** `core/detection/sigma.py` (import
   subset over ASIM fields), `storage/detection_store.py`, detections CRUD +
   `import/sigma` + `test`, Dockerfile.admin COPY. `tests/test_detection_sigma.py`.
4. **PR4 — Detection engine + `detection_matched` fan-out.**
   `core/detection/engine.py`, off-thread consumer over the event stream, the
   one-line vocabulary extensions in `siem_dispatcher`/`siem_store`,
   Dockerfile.admin COPY. `tests/test_detection_engine.py`.
5. **PR5 — Sigma export + docs.** `export/sigma`, operator guide (enable ASIM
   logging in Sentinel; author→compile→monitor→enforce; import a Sigma library;
   wire SIEM/SOAR).

> **Deferred to a follow-up spec (not smuggled in):** an inline deterministic
> `votal_policy` **fast-tier guard** for conditions no existing guard can express —
> it touches the guard path and needs its own sub-ms budget + tests.

## 10. Invariant risk register

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | ASIM formatting + detection must not add latency; enforcement is on the path | ASIM runs in the off-thread flush/export path (+0ms); detection off-thread over the emitted stream; enforcement compiles to **existing** guards — no new inline evaluator in v1 (§2) |
| `Dockerfile.admin` allowlist | New admin-imported modules (+ maybe `core/asim.py` via SIEM path) | Added per-PR with the import-drift test; modules listed in §6 |
| Declare dependencies | ASIM/Sigma parsing | **No new dep** — PyYAML + `regex` already declared; `pySigma` explicitly rejected; any future heavy dep lands in all three requirements files together |
| Secure-by-default, non-breaking | New policies could block live traffic; ASIM could change existing logs | `VOTAL_TELEMETRY_FORMAT` defaults `native`; `SHIELD_ENABLE_DETECTIONS` off by default; compiled policies land in **monitor**; dry-run `compile` diff before apply |
| Self-contained PRs | Router + Dockerfile + tests land together | Enforced in §9 (each PR carries its COPY lines + tests) |
| Clean-venv + CI green | — | Clean-venv run in DoD; CI `pytest` gate |
