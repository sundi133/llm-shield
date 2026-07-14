---
title: Spec — Flight Recorder (forensic snapshot on block/kill)
layout: default
nav_order: 40
description: When a guardrail block, auto-revoke, kill-switch, or circuit-breaker event fires, Shield asynchronously assembles a forensic incident snapshot from data it already holds (decisions, taint, agent identity, revocation), persists it, and exposes it for IR and the evidence pack. Off the hot path, opt-in, non-breaking.
---

# Spec: Flight Recorder (forensic snapshot on block/kill)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until this is
signed off.

## 1. Problem & outcome

When Shield blocks an action, auto-revokes an agent instance, trips a circuit
breaker, or an operator hits the kill switch, the enterprise incident-response
question is immediate: **"what was the agent doing when you killed it?"** Today
that answer is scattered across `decisions:{tenant}` (one decision at a time),
the taint store (per session), agent-auth stats, and webhook payloads. An
analyst has to hand-stitch them, and the taint labels expire in 1 hour
(`_DEFAULT_TTL` in `guardrails/agentic/taint/taint_store.py:19`), so the context
is often gone by the time anyone looks.

**What it does.** On a containment event, Shield fire-and-forget assembles a
single **incident snapshot** from data it already holds and persists it under one
key:

- the triggering decision (guardrail, action, reason, tool, role);
- the last N decisions for that session/agent (from `storage/decision_audit.py`);
- taint labels + flow graph for the session (from the taint store), captured
  *before* they expire;
- agent identity: `agent_instance_id`, `agent_id`, `build_hash`,
  `model_version`, `user_sub` (from `request.state.identity`);
- revocation status (was the instance revoked, and why);
- optional sandbox-side state (process tree, recent file diffs, shell history)
  that the customer's broker/agent-runtime can POST in to enrich the snapshot.

**Observable success condition.** After a block/revoke, an analyst calls
`GET /v1/tenant/me/flight-recorder/incidents/{id}` (JSON or printable HTML) and
sees a complete, self-contained forensic record of that agent's recent activity
and the reason for containment — without querying four stores by hand, and after
the taint TTL would otherwise have discarded it.

**Non-goals.**
- **Not** a new guard endpoint and **not** on the guard path. We compose existing
  stores; capture runs off-thread after the block decision is already made.
- **Not** an in-sandbox agent. Shield's data plane cannot reach into a customer
  sandbox. Process tree / file diffs / shell history are collected by the
  customer's broker/agent-runtime (trusted plane, currently on the `feat-sandbox-*`
  branches, not `main`) and *pushed* to the ingest endpoint. This spec ships the
  Shield-side recorder + the ingest surface; the sandbox-side collector is
  out of scope (it belongs to the sandbox branch work).
- **Not** a replacement for the decision audit or tamper-evident audit chain.
  The snapshot references those; it does not supersede them.
- **Not** a real-time streaming/telemetry pipe. One durable snapshot per
  incident, retrieved on demand.

## 2. Plane & latency contract

- **Capture** is triggered on the **data plane** (at the block/revoke hook sites
  in `core/app.py` routers) but runs as a fire-and-forget `asyncio.create_task`
  *after* the block decision is finalized and the response is being returned —
  exactly the pattern already used for webhook dispatch at
  `api/routes_tool.py:546` and the kill switch at `api/routes_killswitch.py:63`.
- **Retrieval + ingest** routes are read/enrich, mounted on **both planes** for
  parity with the evidence and decisions routers (`admin_app.py:66,93`), primarily
  exercised on the **admin plane** (CPU portal / IR tooling).
- **Touches the GUARD PATH (`/guardrails/*`, `cap/mint`, `tools/call`)?**
  **No.** Capture is never `await`ed on the request path; it is scheduled with
  `asyncio.create_task` and wrapped so any failure is swallowed. It reads from
  Redis and writes one Redis key + one list push, off-thread. **Zero added
  latency to guarded traffic** — this is the load-bearing invariant for this
  feature and is asserted by a test (see §8).

## 3. Data model

All keys tenant-prefixed. Reuses the Redis + in-memory fallback pattern from
`storage/decision_audit.py` (`_get_redis()` / `_fallback_store`).

| Key | Type | Shape | TTL |
|---|---|---|---|
| `flightrec:{tenant_id}` | LIST | JSON incident **summaries** (newest first), capped at 5000 via `LTRIM` | none (bounded by cap) |
| `flightrec:{tenant_id}:{incident_id}` | STRING | JSON full snapshot | `SHIELD_FLIGHT_RECORDER_TTL_SECONDS`, default `2592000` (30 days) |

- `incident_id` = `uuid.uuid4().hex` (runtime code; the Workflow-only
  `Math.random`/`Date.now` restriction does not apply here).
- **Summary** (for listing) = `{incident_id, timestamp, trigger, guardrail,
  action, tool_name, agent_instance_id, agent_id, session_id, reason}`.
- **Full snapshot** = summary + `{last_decisions:[...≤50], taint:{labels, graph},
  identity:{...}, revocation:{revoked, ttl, trigger}, budget:{...|null},
  sandbox_state:{...|null}, schema_version:1}`.
- Bounds: `last_decisions` capped at 50; each `reason` truncated to 500 chars;
  taint labels capped at 200 entries; `sandbox_state` payload capped at 256 KB on
  ingest (rejected with 413 above that).
- **Tenant scoping.** `tenant_id` resolves from `request.state.tenant_id`
  (`X-API-Key`) on retrieval, identical to `api/routes_evidence.py:20`. Every key
  is prefixed by `tenant_id`; a tenant can only read/list/enrich
  `flightrec:{their_tenant_id}:*`. Ingest additionally verifies the target
  incident's stored `tenant_id` equals the caller's before merging
  (cross-tenant enrichment rejected with 404, not 403, to avoid existence
  disclosure).

## 4. API / interface

Router `api/routes_flight_recorder.py`, prefix `/v1/tenant/me/flight-recorder`,
mounted on both planes. Auth: `X-API-Key` (tenant), resolved via
`request.state.tenant_id` like the evidence router. Ingest also accepts
`X-Agent-Token` (the sandbox holds no tenant key — see sandbox design §5).

| Method | Path | Purpose | Success | Errors |
|---|---|---|---|---|
| GET | `/incidents` | List incident summaries (query: `limit`≤200 default 50, `offset`, `trigger`, `agent_instance_id`, `session_id`) | 200 `{count, incidents:[...]}` | 401 no tenant |
| GET | `/incidents/{id}` | Full snapshot; `?format=json` (default) or `html` (printable, inline-CSS, Arial — reuses the evidence-pack HTML style) | 200 snapshot / HTML | 401, 404 unknown/other-tenant |
| POST | `/incidents/{id}/sandbox-state` | Enrich an incident with sandbox-side state; body `{process_tree?, file_diffs?, shell_history?, extra?}` | 200 `{ok:true}` | 401, 404, 413 over cap, 409 already enriched (idempotent replace optional) |

Internal (not an HTTP endpoint): `storage/flight_recorder.py`:
`capture_incident(*, tenant_id, trigger, decision, request=None, session_id=None,
identity=None, revocation=None) -> dict` — assembles + persists, never raises;
`list_incidents(tenant_id, ...) -> list[dict]`; `get_incident(tenant_id, id) ->
dict|None`; `add_sandbox_state(tenant_id, id, state) -> bool`.

## 5. Security & backward compatibility

- **Default behavior: OFF.** New flag `FLIGHT_RECORDER_ENABLED` in
  `core/feature_flags.py` = `_is_enabled("SHIELD_ENABLE_FLIGHT_RECORDER")`, also
  turned on by the existing `SHIELD_ENABLE_ENTERPRISE`. When off: capture is a
  no-op (returns immediately), and the routes return `404`/empty. **No change to
  any existing behavior** — satisfies secure-by-default-but-non-breaking. No
  migration needed because nothing is on by default.
- **Escape hatch / tuning:** `SHIELD_FLIGHT_RECORDER_TTL_SECONDS` (retention),
  read live from env like `auto_revoke._revoke_ttl()`.
- **Authz.** Read/list/enrich are tenant-scoped by `X-API-Key`. A malicious
  caller cannot read another tenant's incidents (key prefix + stored-tenant
  check). The ingest endpoint accepts an agent token so a sandbox with no tenant
  key can enrich its *own* incident; the token's tenant must match the incident's
  tenant. Ingest is size-capped (256 KB) to prevent a compromised sandbox from
  ballooning Redis; sandbox-supplied fields are treated as untrusted data
  (stored, HTML-escaped on render, never executed).
- **Data sensitivity.** Snapshots may contain sensitive context (taint tags,
  tool args in decision metadata). They inherit the tenant's existing data
  boundary (same Redis, same on-prem/in-VPC deployment as decisions/audit) and
  expire at the configured TTL. No new egress. Note in docs: treat snapshots as
  IR-sensitive.

## 6. Packaging & deploy

- **New modules imported by `admin_app.py`** (it mounts the retrieval router):
  add per-file COPY lines to `Dockerfile.admin`:
  - `COPY storage/flight_recorder.py storage/`
  - `COPY api/routes_flight_recorder.py api/`
  Guarded by `tests/test_admin_dockerfile_imports.py` — the new imports MUST be in
  the allowlist or the admin image crash-loops at boot. (Its deps —
  `storage/decision_audit.py`, `storage/evidence_pack.py`,
  `core/webhook_dispatcher.py`, taint store — are already copied.)
- **New pip deps: none.** Uses stdlib (`json`, `uuid`, `os`, `time`,
  `datetime`), FastAPI (present), and existing stores. Nothing to add to
  `requirements.txt` / `requirements-test.txt` / `requirements-admin.txt`.
- **Env flags:** `SHIELD_ENABLE_FLIGHT_RECORDER` (default off),
  `SHIELD_FLIGHT_RECORDER_TTL_SECONDS` (default 2592000).
- **Rebuild:** data-plane image (capture triggers) and admin image (routes).
- **Self-contained PRs:** the Dockerfile.admin COPY lines ship in the *same* PR
  as the new modules.

## 7. Failure modes & edge cases

- **Redis down.** Capture writes to `_fallback_store` (dev) and swallows
  exceptions — mirrors `decision_audit.log_decision`. Retrieval returns `[]` /
  `404` rather than 500. Fail-open on capture (never break the served request).
- **No agent identity / no session (plain tenant-key traffic).** Capture still
  records the triggering decision + tenant; the rich fields (identity, taint,
  revocation) are `null`/empty. Snapshot is still useful and small.
- **Flag off.** `capture_incident` returns `{"skipped":"disabled"}` immediately;
  routes 404. Zero overhead.
- **Huge inputs.** `last_decisions`≤50, taint labels≤200, `reason`≤500 chars,
  ingest body≤256 KB (413). Prevents unbounded snapshots.
- **Concurrency.** `incident_id` is a fresh uuid per event → per-incident key is
  write-once; summary push is atomic `LPUSH`+`LTRIM`. Two blocks on the same
  session produce two independent incidents (correct — they are two events).
- **Capture failure.** Wrapped in try/except and scheduled via
  `asyncio.create_task`; a failure logs a warning and **never** affects the block
  decision, the guard-path response, or latency.
- **Fail policy (explicit):** **capture fails open** (best-effort forensics must
  not degrade enforcement); **retrieval/ingest authz fails closed** (no tenant →
  401; tenant mismatch → 404).
- **Missing optional module** (e.g. taint tracking disabled): each collector is
  independently `try/except`ed, like `evidence_pack._collect_data`; a missing
  source yields an empty section, not an error.

## 8. Test plan (Definition of Done)

Unit (Redis mocked / fallback store, no network), one per §7 edge case:
- capture → `list_incidents` returns the summary → `get_incident` returns the
  full snapshot with the triggering decision, last-N decisions, taint, identity.
- **Tenant isolation:** tenant A cannot list or get tenant B's incident; ingest
  with mismatched tenant → 404.
- **Flag off:** `capture_incident` no-ops; routes 404; no Redis writes.
- **Redis down:** capture uses fallback store and does not raise; retrieval
  degrades to empty.
- **No identity/session:** snapshot captured with null rich fields.
- **Bounds:** >50 decisions truncated to 50; taint >200 capped; ingest >256 KB →
  413; `reason` truncated.
- **Off-hot-path assertion:** capture is scheduled, not awaited — a test patches
  `capture_incident` to sleep and asserts the block response returns without
  waiting on it (guards against a future refactor that `await`s it on the path).
- **HTML render:** `?format=html` returns escaped, self-contained HTML (Arial,
  inline CSS), no unescaped injection from sandbox-supplied fields.
- **Regression guard (drift-prone coupling):** `test_admin_dockerfile_imports.py`
  must stay green — the two new COPY lines are the coupling; add an explicit
  assertion if not auto-covered.
- **Clean venv:** `python -m venv /tmp/x && /tmp/x/bin/pip install -r
  requirements-test.txt && python -m pytest tests -q` green; CI `pytest` gate
  passes.

## 9. Scope / task breakdown (one PR each, in order)

1. **PR 1 — storage core + retrieval API, flag OFF, no triggers.**
   `storage/flight_recorder.py` (`capture_incident`, `list_incidents`,
   `get_incident`), `api/routes_flight_recorder.py` (GET list, GET detail
   json/html), `FLIGHT_RECORDER_ENABLED` flag, mount on both planes,
   `Dockerfile.admin` COPY lines. **Zero guard-path change** (nothing calls
   capture yet). Tests: capture/list/get, tenant isolation, flag-off no-op,
   Redis-down fallback, bounds, HTML escape, Dockerfile allowlist.
2. **PR 2 — wire capture triggers (fire-and-forget), flag-gated.**
   Add `asyncio.create_task(capture_incident(...))` at the existing hook sites:
   tool block branch (`api/routes_tool.py`), input-block auto-revoke hook
   (`api/routes_classify.py`), and instance revoke (`core/auto_revoke.py`).
   Tests: block fires exactly one capture (fake redis), flag-off = no capture,
   off-hot-path (not awaited) assertion, capture failure does not break the
   block response.
3. **PR 3 — sandbox-state ingest + evidence-pack section.**
   `POST /incidents/{id}/sandbox-state` (agent-token/tenant-key auth, 256 KB cap,
   tenant match), and add a "Recent containment incidents" section to
   `storage/evidence_pack.py`. Optional: a `flight-recorder` tab in
   `static/tenant.html`. Tests: ingest enrich + size cap + tenant mismatch;
   evidence pack includes incidents when the flag is on.

## 10. Resolved decisions (approved 2026-07-14)

1. **Capture triggers (PR 2): all four.** Guardrail block, auto-revoke, operator
   kill switch (`api/routes_killswitch.py`), and circuit-breaker trips (agentic
   control plane) all capture a snapshot. These are exactly the "you killed it,
   what was it doing" moments.
2. **Sandbox-side collector: deferred.** This feature ships only the ingest
   *endpoint* (PR 3). The in-sandbox collector for process tree / file diffs /
   shell history stays with the `feat-sandbox-*` branch work, so the recorder
   lands on `main` independently.
3. **Retention default: 30 days** (`2592000s`), tunable via
   `SHIELD_FLIGHT_RECORDER_TTL_SECONDS`.

## 11. Status

- **PR 1 (storage core + read API, flag off, no triggers): implemented** on
  branch `feat/flight-recorder`. `storage/flight_recorder.py`,
  `api/routes_flight_recorder.py`, `flight_recorder_enabled()` flag, mounted on
  both planes, `Dockerfile.admin` COPY lines, `tests/test_flight_recorder.py`.
  Zero guard-path change (nothing calls `capture_incident` yet).
- PR 2 (wire triggers) and PR 3 (ingest + evidence-pack section): not started.
