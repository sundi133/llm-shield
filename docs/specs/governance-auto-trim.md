# Spec: auto-trim unused permissions (governance → enforcement)

Status: approved in session 2026-07-01 (build all three). Feature 2 of 3.

## 0. Reconciliation with docs/specs/usage-retention.md

That spec ruled: "Idleness is surfaced, never auto-revoked; Shield does not
emit a `revoke` recommendation from idleness" — because usage comes from a
bounded recent-events buffer, not full history (the quarterly-cron-tool
problem). This spec KEEPS that stance as the default:

- Default mode is `suggest` — proposals only, zero writes. The prior
  decision stays in force unless an operator explicitly opts out.
- `auto` is an explicit operator opt-in (env flag), guarded by a
  minimum-observation threshold, per-agent exemption, embedded usage
  evidence, and a one-click undo snapshot. The trim record says exactly
  which bounded window justified it.
- Trim candidates come only from `unused_grants` (granted minus used);
  drift (used-not-granted) is never auto-touched.

## 1. Problem & outcome

- Shield already SEES over-provisioning (`GET /v1/governance/agents/{id}/usage`
  → `unused_grants`, api/routes_governance.py:156) and can apply human
  revokes via review campaigns (`POST /reviews/{id}/close` → `_save_agents`).
  But there is no direct propose→approve→apply→undo loop for least-privilege
  trimming — a human must run a full certification campaign.
- Outcome: per-agent trim proposals with three operating modes
  (`suggest`/`approve`/`auto`), full audit trail with evidence, and restore.
  Observable success: in `auto` mode a trim narrows the agent's registry
  grants; the next `cap/mint` for a trimmed tool is denied by the existing
  tenant-policy check; `restore` puts the grants back.
- Non-goals: trimming `allowed_resources` (tools only in v1); company-wide
  discovery of agents not routed through Shield; longer-retention usage
  analytics (separate roadmap); changing the reviews machinery.

## 2. Plane & latency contract

- Plane: portal/governance (router mounted by BOTH `core/app.py:46` and
  `admin_app.py:49`; file already in Dockerfile.admin COPY line 60).
- Guard path: **not touched — off hot path, no guarded-traffic impact.**
  Registry write-back mutates `agents:{tenant}` exactly as a manual agent
  edit / campaign close does; `cap/mint` already reads the registry, so
  narrowed grants take effect on the next mint (live caps expire ≤60 s).
  No new reads/writes on `cap/mint`, `tools/call`, `/guardrails/*`.

## 3. Data model

Same KV conventions as review campaigns (`kv_get`/`kv_set`, no TTL):
- `governance:trims:{tenant}` — index: `{"trims": [{trim_id, agent_id,
  status, created_at}]}`; status kept in sync on transitions.
- `governance:trims:{tenant}:{trim_id}` — full record:
  `{trim_id: "trim-<ts>-<hex>", agent_id, status: pending|applied|restored,
  created_at, created_by, mode_at_creation, tools: [requested],
  evidence: {granted_tools, used_tools, unused_grants, events_seen,
  min_events_required, evidence_window}, removed: {tools: [...],
  role_permissions: {role: [...]}} (set on apply), threshold_met: bool,
  applied_at/by, restored_at/by, skipped_now_used: [...]}`.
- Undo model: `removed` records exactly which grants were deleted from
  which container (direct `tools` vs each `role_permissions[role]`);
  restore ADDS THEM BACK (idempotent union) rather than overwriting the
  whole entry — so unrelated concurrent edits are not clobbered.
- Per-agent opt-out: registry entry field `trim_exempt: true`.
- Tenant scoping: all keys embed tenant_id resolved from `X-API-Key` via
  `get_tenant_from_api_key` (same as every governance endpoint);
  cross-tenant access impossible without the other tenant's key.

## 4. API / interface

All under `/v1/governance`, auth `X-API-Key`, both planes (as today):
- `GET /agents/{agent_id}/trim-proposal` → `{mode, proposal}` — read-only
  in every mode; unknown agent → 200 with `registered: false`, empty lists
  (mirrors `/usage`).
- `POST /agents/{agent_id}/trim` — body optional
  `{"tools": [subset], "reviewer": "..."}`; `tools` must be ⊆ current
  `unused_grants` (400 otherwise); default = all `unused_grants`.
  - unknown agent → 404 (writes are strict), `trim_exempt` → 409,
    nothing to trim → 200 `{applied: false, reason}`.
  - mode `suggest` (default) → 200 `{mode, applied: false, proposal,
    note}` — **no write**.
  - mode `approve` → creates `pending` trim record → 200 `{trim}`.
  - mode `auto` → requires `events_seen >= SHIELD_TRIM_MIN_EVENTS`
    (409 `insufficient observation` otherwise) → applies immediately,
    record `applied`, `threshold_met: true`.
- `GET /trims` → index; `GET /trims/{trim_id}` → record (404).
- `POST /trims/{trim_id}/approve` — human one-click apply of a `pending`
  record (any mode). Re-validates against a FRESH proposal: tools that
  became used since proposal are skipped (`skipped_now_used`), exemption
  re-checked (409), agent gone → 404 (record stays pending). Threshold is
  NOT enforced here — a human decision overrides it; `threshold_met`
  recorded honestly. Already applied → 200 `{already_applied: true}`.
- `POST /trims/{trim_id}/restore` — undo an `applied` record: union the
  `removed` grants back into the entry, status `restored`,
  `updated_at` bumped. Only `applied` records (409 otherwise).

## 5. Security & backward compatibility

- Defaults unchanged: `suggest` writes nothing; `approve`/`auto` are env
  opt-ins (`SHIELD_GOVERNANCE_AUTO_TRIM`). Secure-by-default + escape
  hatch = the default itself.
- Authz: tenant key required (same trust level that can already edit the
  registry / close campaigns — no privilege escalation). A malicious
  tenant caller can only trim ITS OWN agents' unused grants, which is
  strictly privilege-reducing, and can restore them.
- Worst-case wrong trim = availability risk for a seldom-used tool (the
  quarterly-cron problem) — mitigated by default-suggest, min-events gate
  in auto, evidence embedded, and restore.
- Concurrency: read-modify-write via `_save_agents` matches the existing
  campaign-close convention (no etag layer in the codebase). Accepted:
  a racing manual registry edit can interleave; restore is additive-union
  so it cannot resurrect-by-overwrite. Documented, not new risk.

## 6. Packaging & deploy

- No new modules, no new pip deps, no Dockerfile changes
  (routes_governance.py already COPY'd, line 60). Env flags:
  `SHIELD_GOVERNANCE_AUTO_TRIM` = suggest|approve|auto (default suggest);
  `SHIELD_TRIM_MIN_EVENTS` (default 20). Both planes pick the change up on
  their normal image rebuild.

## 7. Failure modes & edge cases

- Redis down → `kv_get`/`get_redis_data` fall back to in-process store
  (existing behavior); a trim in that state affects only the fallback and
  is inherently non-durable — same as every governance write today.
- Empty/unknown agent, empty unused set, non-subset `tools`, exempt agent,
  double-approve, restore-before-apply, agent deleted between pending and
  approve — all enumerated in §4 with explicit statuses.
- Tool becomes used between proposal and approve → skipped, recorded.
- Huge grant lists → bounded by registry entry size (existing limit);
  trim never adds data beyond the removed-set snapshot.
- Fail-closed vs open: writes fail closed (strict 4xx); reads mirror the
  forgiving read conventions of the module.

## 8. Test plan (Definition of Done)

`tests/test_governance_auto_trim.py` (fixture pattern from
test_governance_endpoints.py — in-memory KV + monkeypatched auth/stats):
suggest-is-default no-write; approve→pending→apply narrows registry (direct
tools AND role_permissions); auto applies when threshold met; auto 409 when
below threshold (registry untouched); trim_exempt 409; non-subset and
used-tool requests 400; restore returns grants (both containers) and is
union-idempotent; approve re-validation skips now-used tools; unknown-agent
404 on POST; nothing-to-trim no-op; flag parsing defaults. Full suite green
in clean venv; CI pytest gate passes.
