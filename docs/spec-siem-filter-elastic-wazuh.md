# Spec: SIEM event-status filter + Elastic & Wazuh targets

## 1. Problem & outcome
Security operators want control over **which** guardrail events flow to their SIEM
(today every emitted event is forwarded — all-or-nothing), and native support for
two more targets they run.

Two additions:
1. **Event-status filter** — per SIEM endpoint, choose to forward *Blocked only*,
   *Warnings only*, or *Blocked + Warnings (all)*. Intuitive UI, not a raw
   event-type list.
2. **Elastic (Elasticsearch/OpenSearch) and Wazuh** as first-class SIEM types,
   with tailored auth/format, alongside the existing Splunk / Sentinel / generic
   paths. The generic HTTP-POST path already "works with any SIEM"; these two get
   native formatting so operators don't have to hand-roll the generic path.
   - **elastic** → POST ECS-shaped JSON to the operator's `_doc` URL with
     `Authorization: ApiKey <token>`.
   - **wazuh** → POST ECS-shaped JSON to the operator's indexer `_doc` URL with
     `Authorization: Bearer <token>` (decided: generic Bearer, no separate
     username field).

**Observable success:** an operator can add an Elastic or Wazuh endpoint from the
portal, set it to "Blocked only", trigger a warn and a block, and see only the
block land in their SIEM; a second endpoint set to "all" sees both.

**Non-goals**
- Forwarding *pass/allowed* traffic to SIEM (huge volume; Shield does not emit
  pass events today and this spec does not add them). "All" here = block + warn.
- Per-guardrail or per-severity-score thresholds beyond block/warn.
- Editing existing SIEM configs in place (still delete + re-add; `update_siem_config`
  stays unused by the API).
- Changing webhook behavior for existing subscribers.

## 2. Plane & latency contract
- **Plane:** primarily **admin (CPU portal)** — the SIEM CRUD router
  (`api/routes_siem.py`) mounts only in `admin_app.py`; dispatch logic lives in
  `core/siem_dispatcher.py`.
- **Guard path:** the emission *trigger* is on the data-plane guard path
  (`api/routes_tool.py`, the `tools/call` check). Today it fires
  `dispatch_event(...)` via `asyncio.create_task(...)` **fire-and-forget** only on
  `action == "block"`. This spec widens the trigger to
  `action in ("block", "warn")` — one extra fire-and-forget task on warn
  decisions. **No new synchronous work on the guard path; the guard decision
  returned to the caller is unchanged.** All filtering + Elastic/Wazuh POSTs run
  inside the already-async `dispatch_to_siem`, off the response path.
  → **Off hot path for latency; the only guard-path delta is one extra
  create_task on warn, which is negligible and non-blocking.**

## 3. Data model
Redis key unchanged: `siem:{tenant_id}` → JSON list of config dicts
(`storage/siem_store.py`). Tenant scoping unchanged (key is per-tenant; resolved
from `request.state.tenant_id` via `X-API-Key`).

**New/changed fields on each config dict:**
- `statuses: list[str]` — subset of `["block", "warn"]`. Semantics:
  - **key absent** (legacy configs created before this feature) → treated as
    `["block"]` — preserves today's behavior exactly (warn events are newly
    introduced; legacy endpoints must not suddenly receive them).
  - **empty list `[]`** → no status filter = **all** (block + warn).
  - non-empty → only those statuses.
`statuses` is the only genuinely new config field (Wazuh reuses `url` + `token`,
so no new auth fields are needed). `log_type` stays sentinel-only; `token` is
reused as API key (elastic, `ApiKey` header) / bearer token (wazuh). No TTL
(configs are durable). Example:
```json
{
  "siem_id": "a1b2c3d4e5f6",
  "type": "elastic",
  "url": "https://es.company.com:9200/shield-events/_doc",
  "token": "<api-key>",
  "statuses": ["block"],
  "events": [],
  "enabled": true,
  "created_at": 1717700000, "updated_at": 1717700000
}
```

## 4. API / interface
Router unchanged: `/v1/tenant/me/siem` (admin plane), auth via tenant `X-API-Key`.

`SIEMCreateRequest` (`api/routes_siem.py`) changes:
- `type` regex `^(splunk|sentinel|generic)$` → `^(splunk|sentinel|generic|elastic|wazuh)$`.
- add `statuses: list[str] = Field(default_factory=list)` — validated subset of
  `{"block","warn"}` (reject unknown values with 400).
- per-type required-field validation in `create_siem`:
  - `elastic` → `url` required (the `_doc`/`_bulk` endpoint) and `token` required
    (API key).
  - `wazuh` → `url` required (indexer `_doc` endpoint) and `token` required
    (bearer token).

`GET` response: `token`/`shared_key` stay redacted. Add `statuses` and `type` to
what the list UI renders.

## 5. Security & backward compatibility
- **Non-breaking default:** legacy configs (no `statuses` key) → `["block"]`, i.e.
  identical to today. New configs default (UI) to *Blocked only* as well, so the
  status dimension never silently broadens forwarding.
- **Webhooks untouched:** warn is emitted under a **new event type**
  `guardrail_warning`. `get_webhooks_for_event` filters by subscribed event type,
  so existing webhook subscribers (to `guardrail_blocked` etc.) do **not** start
  receiving warns. Block continues to use `guardrail_blocked` (unchanged).
- **Escape hatch:** warn emission is gated behind the existing `WEBHOOKS_ENABLED`
  flag (same gate as today's block emission) — set it off and behavior is exactly
  as before this change. No new default-on behavior on a fresh deploy without SIEM
  configs.
- **Authz:** unchanged — only a tenant with a valid key can CRUD its own configs;
  a malicious caller cannot target another tenant (key-scoped Redis key).
- **SSRF:** SIEM dispatch does not currently run `validate_outbound_url` (webhooks
  do). Elastic/Wazuh URLs are operator-supplied like the existing Splunk/generic
  URLs — same trust level as today; **not widening** the SSRF surface. (Optional
  hardening: run `validate_outbound_url(..., purpose="siem")` in
  `dispatch_to_siem`; flagged as a follow-up, not in scope, to avoid breaking
  on-prem endpoints that resolve to private IPs.)

## 6. Packaging & deploy
- **No new admin imports.** `Dockerfile.admin` already COPYs
  `core/siem_dispatcher.py`, `storage/siem_store.py`, `api/routes_siem.py`,
  `core/webhook_dispatcher.py`. Elastic/Wazuh are new *functions* in existing
  files — no COPY change. (`tests/test_admin_dockerfile_imports.py` still guards.)
- **No new pip deps.** Elastic/Wazuh use `httpx` (already a dep) via the existing
  `_post` helper. Nothing added to `requirements*.txt`.
- **Env flags:** none new. Reuses `WEBHOOKS_ENABLED`.
- **Rebuild:** admin image (portal UI + routes) and data-plane image (guard-path
  emission change). Both because the emission trigger is in `routes_tool.py`
  (mounted in both planes).

## 7. Failure modes & edge cases
- **Bad `statuses` value** (e.g. `["blocked"]`, `["pass"]`) → 400 at create.
- **Legacy config, no `statuses`** → block-only (covered in §5).
- **Empty `statuses`** → all (block+warn).
- **Elastic/Wazuh POST fails / times out** → `_post` already retries
  (`_MAX_RETRIES=2`, 10s timeout) and returns False; one endpoint failing never
  blocks others (`asyncio.gather(..., return_exceptions=True)`). **Fail-open** for
  the guard decision (dispatch is fire-and-forget; a SIEM outage never blocks a
  tool call) — consistent with today.
- **Redis down** → `get_siem_configs` returns `[]`, dispatch is a no-op. Guard
  path unaffected.
- **Missing token for elastic/wazuh** → rejected at create (400).
- **Non-guardrail events** (`shadow_agent_detected`, `tool_disabled`,
  `test_event`) → status is `None` → **always pass** the status gate (the filter
  only constrains block/warn severity).
- **Huge payload** → same as today; `_post` streams bytes, 10s timeout bounds it.
- **Concurrency:** config list is read-modify-write in Redis (existing pattern,
  not newly introduced); unchanged.

## 8. Test plan (Definition of Done)
New `tests/test_siem.py` (no SIEM test file exists today):
- **Status filter:**
  - config `statuses=["block"]` forwards `guardrail_blocked`, drops `guardrail_warning`.
  - `statuses=["warn"]` drops block, forwards warn.
  - `statuses=[]` forwards both.
  - **legacy config with no `statuses` key** → block-only (regression guard for
    the non-breaking default).
  - non-guardrail event (`shadow_agent_detected`) forwarded regardless of `statuses`.
- **Elastic:** `dispatch_to_elastic` posts ECS-shaped JSON with
  `Authorization: ApiKey <token>` to the configured URL (mock `_post`, assert
  headers/body/url).
- **Wazuh:** `dispatch_to_wazuh` posts with `Authorization: Bearer <token>`.
- **Dispatcher routing:** `type=elastic`/`wazuh` route to the right function;
  unknown type falls back to generic (unchanged).
- **API validation:** create with `type=elastic` and no `token` → 400; bad
  `statuses` value → 400; happy-path create persists `statuses`/`username`.
- **Webhook non-regression:** `guardrail_warning` not delivered to a webhook
  subscribed only to `guardrail_blocked` (assert `get_webhooks_for_event`).
- Full suite green in a **clean venv** (`python -m venv /tmp/x && .../pip install
  -r requirements-test.txt && python -m pytest tests -q`); CI `pytest` gate passes.

## Task breakdown (one feature branch, ordered commits — per single-branch workflow)
Branch: `feat/siem-status-filter-elastic-wazuh` (off `main`, not the current docs branch).

1. **Backend — status filter + warn emission.** `statuses` field
   (`siem_store.py` + pydantic + validation), `_event_status()` + filter in
   `dispatch_to_siem`, widen `routes_tool.py` trigger to `block|warn` with new
   `guardrail_warning` event type. Tests.
2. **Backend — Elastic & Wazuh targets.** `format_*`/`dispatch_to_elastic`,
   `dispatch_to_wazuh`, type regex + validation, dispatcher routing. Tests.
3. **UI — intuitive portal.** Per-type field hints (elastic/wazuh options),
   a status-filter segmented control ("Blocked only / Warnings only / All"),
   render type + filter in the list, wire `createSIEM()` to send `statuses`.

Each commit self-contained (tests included). One PR.
