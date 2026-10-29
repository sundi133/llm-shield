# Spec: policy scopes (global + per-team I/O policies selected by a request header)

Status: **implemented**, tasks 0 to 5 on branch `feat/policy-scopes`. Task 0b (guardrails ignoring tenant settings) is on its own branch, `fix/guardrail-per-request-settings`.
Customer guide: `docs/team-policies.md` (`/team-policies/`).

## 1. Problem & outcome

A tenant is one customer, but a customer has many teams (orgs, business units,
apps). Today a tenant has exactly one `input_guardrails` / `output_guardrails`
set, and the API key alone picks it (`api/routes_classify.py:262`,
`core/tenant_pipeline.py:180`). There is no way to say "everyone gets the global
policy, and team A also gets these extra rules."

The customer wants to:

- send a header they choose (for example `X-Org-Id`) on guarded traffic;
- keep one **global** policy for the whole tenant;
- add a **local** policy per header value;
- not have to know the header values in advance (new teams appear all the time);
- be able to change the header name later (for example `X-Org-Id` to `X-Team-Id`)
  without losing or rewriting policies.

**Outcome.** A tenant admin can turn on policy scopes by naming one or more
headers. Shield then:

1. **Discovers** every value it sees on those headers and lists them with counts,
   before any local policy exists (observe first, then write rules).
2. **Matches** a value to a local policy by exact value or by glob pattern
   (`eng-*`), so values that appear later are covered without an edit.
3. Applies a configurable **unmatched** policy to values no rule matches, so
   a brand-new team gets a sensible local baseline on its first request.
4. **Merges** global and local so the local policy can only make things stricter.
   No header value, real or spoofed, can get below the global policy.
5. Reports which scope it applied in the response and the audit log.

Observable success: with `X-Org-Id: team-a`, a prompt that only team A's local
rule blocks is blocked; the same prompt with `X-Org-Id: team-b` passes; a prompt
the global rule blocks is blocked for every value, including no header at all.

**Non-goals (v1).**
- Tool paths: `tools/call`, `cap/mint`, MCP enforcement, and `tool_allowlist` are
  untouched. A local policy may not contain `tool_allowlist`.
- Per-scope `policy_mode` (monitor/enforce). The tenant's mode applies to all scopes.
- Selecting by a verified token claim instead of a header (designed for in
  section 5, built later).
- ICAP / SWG traffic (browser requests do not carry the customer's header).
- Per-scope metrics dashboards. v1 has the audit field and the discovered-values
  list.
- Enforcing parent/child tenants. The parent routes exist (`/v1/admin/tenants/{id}/parent`, `/effective-policies`) but only record a hierarchy and report a merged view of data protection policies; nothing enforces them and they never covered I/O guardrails. Task 0 corrects the docs that said otherwise.

## 2. Plane & latency contract

- **Admin plane** (`admin_app.py`) and **data plane** (`core/app.py`) both mount
  the config router, the same way `tenant_self_router` is mounted on both
  (`admin_app.py:1096`, `core/app.py:144`). Writes go to the tenant record in Redis.
- **Data plane, guard path: yes, this touches `/guardrails/*` and the chat
  proxies.** It must add no I/O.
  - The scope config lives **inside the tenant record** the middleware already
    loads and caches per API key for 60 s (`core/middleware.py:26`, `_get_cached_tenant`).
    Selecting a scope is header reads plus dict lookups on that cached object.
  - The merged (effective) policy is computed in process the first time a
    (tenant config object, rule) pair is used, and memoized. Every later request
    on that cached config is one dict lookup. When the 60 s cache reloads the
    tenant, the new config object recomputes once.
  - **Why not precompute when policies are saved?** The global policy is written
    by many routes (`/v1/tenant/me/policies`, the custom-policy CRUD in
    `storage/custom_policies.py`, policy templates, `api/routes_policy.py`, the
    admin update route). A save hook on all of them would drift. Merging at first
    use means a global change always reaches every scope, with no hook to forget.
  - Discovery counting is in-process; a background task flushes it to Redis. No
    Redis call on the request.
  - Value-to-rule results are memoized too, per cached config object, bounded
    to 5,000 values (beyond that, lookups run uncached). The memo keeps the 4
    most recent config objects per tenant, so cache reloads don't pin stale
    configs in memory.
  - Selector headers that carry credentials (`Authorization`, `Cookie`,
    `X-API-Key`, `X-Tenant-Key`, `X-Admin-Key`, client-cert headers) are refused
    on save and skipped at read, so a credential can never land in the
    discovery store or the audit log. Exact values are a dict
    lookup; globs are pre-compiled once per config object.
  - **Budget:** tenants without `policy_scopes`: one `dict.get`, effectively 0.
    Tenants with scopes: under 50 µs p99 added for selection + memo lookup
    (measured by a microbenchmark test, section 8).
  - **Prototype measurements** (Python, laptop, 20,000 iterations each):

    | Case | median | p99 |
    |---|---|---|
    | Tenant without scopes | 0.08 µs | 0.12 µs |
    | Known value, steady state (memoized) | 0.29 µs | 0.33 µs |
    | First sight of a value, 20 rules / 20 globs, no match, plus merge | 2.5 µs | 3.2 µs |
    | First sight, 4,000 globs (the original limit, now rejected) | 279 µs | 321 µs |

    Measured again on the shipped `core.policy_scopes.resolve` (task 5), with
    a real Starlette `Headers` object, 200 rules and 100 globs, 50,000 runs:
    known value **2.5 µs median, 6.2 µs p99**; tenant without scopes 0.3 µs
    median, 0.7 µs p99. Higher than the prototype because of header lookups
    and the per-request copy of the memoized config that carries the marker;
    well inside the 50 µs budget.
  - What a local policy *enables* costs what that guardrail costs (a custom LLM
    policy is an LLM call), exactly as if the tenant had enabled it globally.
    That is the customer's choice, not Shield overhead; the preview endpoint shows
    each guardrail's tier so it is visible before saving.

## 3. Data model

One new top-level field on the tenant record (`tenant:{tenant_id}`, written by
`storage/tenant_store.py`). Absent means the feature is off for that tenant.

```json
"policy_scopes": {
  "version": 7,
  "enabled": true,
  "selectors": [
    {"header": "X-Team-Id"},
    {"header": "X-Org-Id"}
  ],
  "missing": "global",
  "unmatched": {
    "input_guardrails":  {"keyword_blocklist": {"enabled": true, "action": "block",
                          "settings": {"keywords": ["internal draft"]}}},
    "output_guardrails": {}
  },
  "rules": [
    {"id": "team-a",
     "match": {"exact": ["team-a", "teama"], "glob": []},
     "input_guardrails":  {"keyword_blocklist": {"enabled": true, "action": "block",
                           "settings": {"keywords": ["zebra"]}}},
     "output_guardrails": {}},
    {"id": "engineering",
     "match": {"exact": [], "glob": ["eng-*"]},
     "input_guardrails":  {"custom_policy_input": {"enabled": true, "action": "pass",
                           "settings": {"policies": [{"policy_id": "...", "action": "block", "...": "..."}]}}},
     "output_guardrails": {}}
  ],
  "key_bindings": {"sk-acme-1a2b": ["team-a", "eng-*"]}
}
```

| Field | Meaning |
|---|---|
| `enabled` | Master switch for this tenant. `false` keeps the config but applies global only. |
| `selectors` | Ordered header names, 1 to 5. The first header present with a non-empty value wins. Changing this list is how the header gets renamed: list the new header first and keep the old one during the migration. |
| `missing` | No selector header present: `"global"` (default; global policy only) or `"reject"` (403). |
| `unmatched` | Optional local policy for a value present but matched by no rule. Omitted = global only. |
| `rules[].id` | Stable id, `^[a-z0-9][a-z0-9_-]{0,63}$`. Policies hang off the id, not the header name or the value, so renaming either loses nothing. |
| `rules[].match.exact` | Normalized values (see below). An exact match on any rule beats every glob. |
| `rules[].match.glob` | `fnmatch` patterns, case-insensitive, at most 64 chars. Globs are tried in rule order; the first match wins. No regex (no ReDoS on the guard path). |
| `key_bindings` | Optional. Key id (the 12-char key prefix the portal already shows, `_KEY_PREFIX_LEN` in `storage/tenant_store.py`) to the values/globs that key may claim. A key with no entry may claim any value. |
| `version` | Incremented on every write; used for optimistic concurrency (section 4). |

**Value normalization** (applied to the header before matching, discovery and
logging): strip, lowercase, max 64 chars, allowed characters
`a-z 0-9 . _ - : @ /`. Anything else, a longer value, or two different values for
the same header in one request, normalizes to the reserved value `(invalid)`,
which is matched only by `unmatched`. A missing or empty header is `(missing)`.

**Limits** (enforced on save): 200 rules, 20 exact values per rule, **100 glob
patterns per tenant in total** (a prototype measured about 280 µs to miss
4,000 globs, about 7 µs to miss 100), 5 selectors,
1,000 key bindings, serialized `policy_scopes` at most 256 KB. These keep the
tenant record cheap to load; a large blob on the guard path already costs about
26 ms per call in the tool registry.

**Discovery store** (new Redis key, written only by the background flush):

Three hashes per tenant, field = normalized value. Three rather than one hash
of JSON so the count is an atomic `HINCRBY` and concurrent flushes from several
workers never lose increments:

- `policy_scope_seen:{tenant_id}`: request count (`HINCRBY`).
- `policy_scope_seen_first:{tenant_id}`: first seen, epoch seconds (`HSETNX`).
- `policy_scope_seen_last:{tenant_id}`: `"{epoch seconds}|{header}"`, the
  header the value most recently arrived on (shows a header rename's progress).
- At most 2,000 values per tenant; a flush keeps the busiest new values that
  fit and adds the rest to the `(overflow)` field.
- TTL 30 days, refreshed on each flush. A tenant that stops sending values ages out.
- In process: a buffer of at most 50,000 (tenant, value) pairs, updated under
  a lock; a daemon thread flushes it at most every
  `SHIELD_POLICY_SCOPE_FLUSH_SECONDS`, started by a request (no startup task).
  `GET /discovered` flushes its own process's buffer first.
- Every decision is recorded, refused requests included; `(missing)` and
  `(invalid)` are counted like any value. Selection errors are not recorded.
- Without Redis, the same three maps live in the in-memory fallback store.

**Tenant scoping.** Both keys are keyed by `tenant_id`, which the middleware
resolves from the API key. A header value is only ever looked up inside that
tenant's own config, so a value cannot reach another tenant's policies.

## 4. API / interface

### Config routes (new `api/routes_policy_scopes.py`, both planes)

Tenant-scoped under `/v1/tenant/me/policy-scopes`, with operator mirrors under
`/v1/admin/tenants/{tenant_id}/policy-scopes` sharing the same handlers.

| Method + path | Body | Result |
|---|---|---|
| `GET /` | | `{policy_scopes, warnings, kill_switch}`. `warnings` lists rules that no longer pass against the current global policy. |
| `PUT /settings` | `{enabled, selectors, missing, unmatched, expected_version?}` | Saved config. |
| `PUT /rules/{rule_id}` | `{match, input_guardrails, output_guardrails, expected_version?}` | Saved rule. |
| `DELETE /rules/{rule_id}` | | 204. |
| `PUT /key-bindings/{key_prefix}` | `{allowed: [...]}` | 404 if the prefix matches none of this tenant's keys; 409 if it matches more than one. |
| `DELETE /key-bindings/{key_prefix}` | | 204. |
| `GET /discovered?limit=200` | | `{discovery_enabled, total, values: [{value, count, first_seen, last_seen, header, matched_rule}]}`, busiest first, `limit` 1 to 2,000. `matched_rule` is computed against the **current** rules (ignoring `enabled`, like preview), so the admin sees what a new rule would catch; it is null for `(overflow)`. |
| `POST /preview` | `{headers: {...}, key_prefix?}` | `{value, source_header, rule, outcome, scopes_active, kill_switch, effective: {input_guardrails, output_guardrails}, guardrail_tiers}`. Reads the config fresh from the store, so it reflects a save immediately. Evaluates rules even while scopes are off for the tenant (`scopes_active: false`), so rules can be tested before turning them on. Read-only, so it needs no write scope. |

Status codes: 422 for an invalid or weakening rule (body lists every violation,
for example `"keyword_blocklist: global action is block, rule sets pass"`),
409 when `expected_version` is stale, 403 from the write gate.

**Auth.** Reads: any caller resolved to the tenant (tenant key or portal session).
Writes: `require_config_write(request, tenant_id)` (`core/auth.py:799`), the same
gate as every other tenant config write. Admin mirrors: the existing
`/v1/admin/tenants` admin auth.

### Guard path changes

| Where | Change |
|---|---|
| `core/middleware.py`, after the agent checks and before the quota check | On scoped paths only (`ShieldMiddleware._POLICY_SCOPE_PATHS`), replace `request.state.tenant_config` with the scoped copy and set `request.state.policy_scope`. After the agent checks so a refused caller is still recorded as a shadow agent; before the quota so a refused request doesn't spend it. |
| Scoped paths | `/guardrails/input`, `/guardrails/output`, `/guardrails/file`, `/classify`, `/classify_output`, `/v1/chat/completions`, `/v1/shield/chat/completions`, `/v1/shield/chat/agent`, and `/beta/litellm_basic_guardrail_api` (it calls the `/guardrails/input` handler with the same request). |
| `/guardrails/input`, `/output`, `/file` responses | New field `"policy_scope": {"rule": "team-a", "value": "team-a", "header": "X-Org-Id"}`; `rule` is `"global"` or `"unmatched"` when those applied. Absent for tenants without policy scopes. Additive. |
| Every scoped route's response | Header `X-Shield-Policy-Scope: team-a`, set by the middleware, so the chat proxies (whose bodies are the model's) carry it too. |
| Audit log (`audit_logger.log` in the classify routes) | New `policy_scope` field. |

Every consumer (`_classify_tenant`, `resolve_proxy_guardrails`) already reads
`request.state.tenant_config`, so none of them change.

## 5. Security & backward compatibility

**Default: off.** A tenant without `policy_scopes` behaves byte-for-byte as
today. Nothing changes until a tenant admin saves settings.

**Merge rule (the security core).** The effective config is global merged with
the selected local policy:

| Situation | Result |
|---|---|
| Guardrail only in global | As global. |
| Guardrail only in local | Added. |
| In both, global enabled | Stays enabled; local `enabled: false` is rejected on save (and ignored at merge if it got in some other way). |
| In both, global disabled | Local may enable it. |
| In both, action | Stricter wins: `pass < log < warn < redact < block`. An unknown action on save is a 422; at merge it keeps global. |
| In both, denylist settings (`keywords`, `patterns`, `extra_patterns`, `blocked_topics`, `competitors`, `pii_patterns`) | Unioned: more entries is stricter. |
| In both, allowlist settings (`allowed_languages`, `allowed_topics`, `trusted_domains`) | **Intersected**: more entries would be looser. An empty list means unrestricted, so empty on either side yields the other; lists with nothing in common keep global (422 on save). |
| In both, any other setting | Global, **unless** the global guardrail has `"delegable": true`, in which case local settings override (a team that needs its own threshold). `delegable` never lets a team lower the action. |
| Local `enabled: false` on any guardrail | Rejected on save, dropped at merge. Even for a guardrail global does not name: on the chat proxies (UNION mode) a disabled entry switches off a server default. |
| Local stage when global has no such stage | Rejected on save ("set a global input_guardrails first"), ignored at merge. A tenant stage *replaces* the server defaults on `/guardrails/*`, so a one-guardrail local stage would drop the rest. |
| `custom_policy_input` / `_output` | Policies unioned by `policy_id`; same id keeps the stricter action; capped like the write path (`MAX_POLICIES_PER_STAGE` for NL, `SHIELD_SIGMA_MAX_POLICIES_PER_STAGE` for Sigma, counted separately), global policies first. The caps also apply to a team-only custom policy guardrail. Over the cap: 422 on save; at merge, extra local policies dropped with a warning. |
| `tool_allowlist` | Not allowed in a local policy (422). Global passes through untouched. |

`delegable` is a new optional boolean on the global `GuardrailPolicy`
(`storage/tenant_models.py`). Absent means locked.

**What a malicious or careless caller can do.** Headers are set by the caller, so
any holder of the tenant key can claim any value.
- They cannot get below the global policy: the merge never weakens it.
- They could pick another team's local policy that is looser than their own.
  The fix is `key_bindings`: give each team its own key and bind it. A bound key
  claiming a value outside its list gets 403; a bound key with no header uses its
  binding if it has exactly one exact value, otherwise follows `missing`.
- Where the header is set by the customer's own gateway rather than by apps,
  binding is unnecessary.
- Future (not v1): `{"claim": "org_id"}` as a selector, read from verified
  workload-identity claims (`request.state.workload_identity`, `_dotted` in
  `core/identity_resolution.py`). The selector list is shaped so this is additive.

**Write safety.** The scoped config handed to the guard path is a **copy** with
a `_policy_scope` marker. `update_tenant` / `create_tenant` refuse a dict
carrying the marker, so a merged view can never be saved back as the global
policy. (`set_tenant_policies` takes stage dicts, not a whole config; task 3
keeps scoped configs off every non-guarded route, which is what protects it.)
The cached tenant dict is never mutated.

**Stale rules.** A write checks only the rule (or `unmatched`) it touches
against the current global policy, plus every structural limit. A rule saved
before a later global edit may now ask for something global forbids; the merge
already ignores that part, `GET` lists it under `warnings`, and it does not
block unrelated writes.

**Key bindings need key metadata.** A binding names the 12-char prefix from the
key's metadata record. Keys added after tenant creation (`add_api_key`, the
portal, `POST /v1/admin/tenants/{id}/api-keys`) have one; keys passed in
`api_keys` when the tenant is created do not, and binding them returns 404.
Mint a separate key per team (the intended setup anyway).

**Escape hatches.**

| Env flag | Default | Effect |
|---|---|---|
| `SHIELD_DISABLE_POLICY_SCOPES` | unset | `1`/`true`/`yes`/`on`: every tenant gets the global policy only. Read live (no restart), like `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY`. |
| `SHIELD_POLICY_SCOPE_DISCOVERY` | `on` | `off` stops recording discovered values. |
| `SHIELD_POLICY_SCOPE_FLUSH_SECONDS` | `15` | Discovery flush interval (set `1` for local testing). |

Turning a tenant on is opt-in by that tenant, so no migration note is needed for
existing tenants. The new response field is additive.

## 6. Packaging & deploy

- New modules: `core/policy_scopes.py` (pure: normalize, select, merge, validate,
  memo), `storage/policy_scopes_store.py` (persist + discovery),
  `api/routes_policy_scopes.py` (routes). `admin_app.py` imports the router, so
  **all three go in the `Dockerfile.admin` COPY allowlist** in the same PR
  (`tests/test_admin_dockerfile_imports.py` enforces it).
- No new pip dependencies (`fnmatch` is stdlib).
- Rebuild both images. Changes reach the data plane within the existing 60 s
  tenant cache, the same as global policy edits today.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Any exception while selecting or merging | **Fail to global**: log a warning, use the unscoped tenant config. Global is the floor, so this never weakens enforcement. |
| `missing: reject` and the header is absent | 403 `{"detail": "policy scope header required", "headers": [...]}`. |
| Bound key claims a value outside its binding | 403 `{"detail": "this key may not use policy scope '<value>'"}`. |
| Header present but empty | `(missing)`. |
| Header over 64 chars, bad characters, or two different values | `(invalid)`, gets `unmatched` (or global), counted in discovery. |
| Values differing only by case or whitespace | Same normalized value. |
| Rule saved with a value another rule already lists as exact | 422 (exact values must be unique across rules). |
| Two globs both match | First in rule order wins; `preview` shows which. |
| Header renamed with no overlap period | Values arrive on a header not in `selectors`, so traffic falls to `missing`. Discovery shows the old header's count dropping; the docs tell admins to list both during the switch. |
| Rule deleted while traffic flows | Values fall to `unmatched` / global within 60 s. |
| Concurrent writes by two admins | `expected_version` mismatch returns 409; without it, last writer wins (same as other config). |
| Redis down | Guard path keeps using the cached config; discovery flush fails silently and retries; config writes return 503 as other config writes do. |
| Process crash | Up to one flush interval of discovery counts lost. Best effort by design. |
| Huge config | Rejected on save by the limits in section 3. |
| Global policy edited | Next cache reload produces a new config object; memo recomputes once per rule. |
| Value with 2,000 distinct values already seen | Counted in `(overflow)`; matching is unaffected. |
| Guardrail that reads its settings once at construction | **Pre-existing bug, found while writing this spec.** `regex_pattern` (`guardrails/input/regex_pattern.py:18`) and `length_limit` (`guardrails/input/length_limit.py:17`) copy `self.settings` in `__init__`, on the shared singleton, so per-request tenant settings (`patterns`, `max_chars`) are ignored today, for global tenant policies as well as scopes. Fixed separately (task 0b, branch `fix/guardrail-per-request-settings`), which found three more guardrails with the same bug: `sentiment`, `rate_limiter`, `system_prompt_leak`. |

## 8. Test plan (Definition of Done)

### Automated

`tests/test_policy_scopes_merge.py` (task 1, pure functions)
- normalization: case, whitespace, 64-char cap, bad chars, duplicate values
- selection: first selector wins, exact beats glob, glob order, `(missing)`, `(invalid)`, `unmatched`
- merge: every row of the section 5 table, including `delegable`, list union,
  custom-policy union + cap, `tool_allowlist` rejected
- validation: each weakening attempt returns a precise 422 reason
- memo: same config object hits the memo; a new object recomputes; cached dict
  never mutated
- microbenchmark: 200 rules, select + memoized lookup p99 under 50 µs
  (asserted with a generous CI bound to avoid flakes)

`tests/test_policy_scopes_api.py` (task 2)
- CRUD round trip, limits, `expected_version` 409, key-binding prefix 404/409
- write gate: a runtime-scoped key is refused under `SHIELD_CONFIG_WRITE_SCOPE=enforce`
- preview reflects a save immediately
- admin mirror routes share behavior

`tests/test_policy_scopes_guard_path.py` (task 3)
- parity: the same request with `X-Org-Id: team-a` vs `team-b` vs no header on
  **each** guarded path in section 4 (input, output, file, and the three proxies)
- global block holds for every value, including spoofed ones
- `missing: reject` 403, key-binding 403
- tenant without `policy_scopes` gets an identical response to today (golden check)
- `SHIELD_DISABLE_POLICY_SCOPES=1` gives global only, read live
- marker tripwire: saving a scoped dict raises
- non-guarded routes (for example `GET /v1/tenant/me/policies`) see the unscoped config
- `policy_scope` in the response and the audit record; `X-Shield-Policy-Scope` header on proxies

`tests/test_policy_scopes_discovery.py` (task 4)
- counts aggregate in process and flush in one pipeline; 2,000 cap and `(overflow)`; TTL set
- `matched_rule` recomputed against current rules
- discovery `off` records nothing
- a Redis failure during flush never surfaces to a request

Regression guards: `tests/test_admin_dockerfile_imports.py` covers the three new
modules; route tests use `tests/route_tables.flat_routes` with a non-vacuity
assert (FastAPI router nesting in CI).

Full suite green in a clean venv:
`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt && /tmp/x/bin/python -m pytest tests -q`.
CI `pytest` gate passes.

### Manual walkthrough (runs after task 3; discovery steps after task 4)

Uses only `keyword_blocklist`, which needs no model, so it runs on a laptop. The
store is in memory: do not restart the server between steps.

**1. Start the data plane.**

```bash
SHIELD_ADMIN_KEY=dev-admin SHIELD_POLICY_SCOPE_FLUSH_SECONDS=1 python -m uvicorn core.app:create_app --factory --port 8077
```

```bash
B=http://localhost:8077; K='X-API-Key: sk-acme-test-0001'; A='X-Admin-Key: dev-admin'
```

**2. Create a tenant whose global policy blocks "ssn".**

```bash
curl -s -X POST $B/v1/admin/tenants -H "$A" -H 'Content-Type: application/json' -d '{"tenant_id":"acme","api_keys":["sk-acme-test-0001"],"input_guardrails":{"keyword_blocklist":{"enabled":true,"action":"block","settings":{"keywords":["ssn"]}}}}'
```

**3. Baseline (no scopes yet).** Expect `block` for the first, `pass` for the second.

```bash
curl -s $B/guardrails/input -H "$K" -H 'Content-Type: application/json' -d '{"message":"my ssn is 123"}' | jq .action
```

```bash
curl -s $B/guardrails/input -H "$K" -H 'Content-Type: application/json' -d '{"message":"project zebra launch"}' | jq .action
```

**4. Turn on discovery only: name the header, no rules.** Values are unknown, so just observe.

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/settings -H "$K" -H 'Content-Type: application/json' -d '{"enabled":true,"selectors":[{"header":"X-Org-Id"}],"missing":"global"}'
```

**5. Send traffic with values you never registered.** Wait 60 s after step 4
first (tenant cache). Every response shows `"rule": "global"`.

```bash
for v in team-a team-b Eng-Payments eng-search; do curl -s $B/guardrails/input -H "$K" -H "X-Org-Id: $v" -H 'Content-Type: application/json' -d '{"message":"hello"}' | jq -c .policy_scope; done
```

**6. See what was discovered.** Expect `team-a`, `team-b`, `eng-payments` (lowercased), `eng-search`, each with `matched_rule: "global"`.

```bash
curl -s $B/v1/tenant/me/policy-scopes/discovered -H "$K" | jq
```

**7. Add a local rule for team-a that also blocks "zebra".**

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/rules/team-a -H "$K" -H 'Content-Type: application/json' -d '{"match":{"exact":["team-a"]},"input_guardrails":{"keyword_blocklist":{"enabled":true,"action":"block","settings":{"keywords":["zebra"]}}}}'
```

**8. Check it with preview (immediate, no cache wait).** Expect `rule: team-a` and keywords `["ssn","zebra"]`.

```bash
curl -s -X POST $B/v1/tenant/me/policy-scopes/preview -H "$K" -H 'Content-Type: application/json' -d '{"headers":{"X-Org-Id":"Team-A"}}' | jq '{rule, kw: .effective.input_guardrails.keyword_blocklist.settings.keywords}'
```

**9. Check live traffic (after 60 s).** team-a: `block`. team-b: `pass`. "ssn" with any value or no header: `block`.

```bash
for v in team-a team-b; do curl -s $B/guardrails/input -H "$K" -H "X-Org-Id: $v" -H 'Content-Type: application/json' -d '{"message":"project zebra launch"}' | jq -r "\"$v \" + .action"; done
```

**10. Cover future values with a glob.** Any `eng-*` value, including ones not yet seen, also blocks "payroll".

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/rules/engineering -H "$K" -H 'Content-Type: application/json' -d '{"match":{"glob":["eng-*"]},"input_guardrails":{"keyword_blocklist":{"enabled":true,"action":"block","settings":{"keywords":["payroll"]}}}}'
```

```bash
curl -s -X POST $B/v1/tenant/me/policy-scopes/preview -H "$K" -H 'Content-Type: application/json' -d '{"headers":{"X-Org-Id":"eng-brand-new-team"}}' | jq .rule
```

**11. Give never-seen, unmatched values a local baseline.**

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/settings -H "$K" -H 'Content-Type: application/json' -d '{"enabled":true,"selectors":[{"header":"X-Org-Id"}],"missing":"global","unmatched":{"input_guardrails":{"keyword_blocklist":{"enabled":true,"action":"block","settings":{"keywords":["internal draft"]}}}}}'
```

```bash
curl -s -X POST $B/v1/tenant/me/policy-scopes/preview -H "$K" -H 'Content-Type: application/json' -d '{"headers":{"X-Org-Id":"sales-emea"}}' | jq .rule
```

Expect `"unmatched"`.

**12. Try to weaken the global rule.** Expect 422 naming `keyword_blocklist`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X PUT $B/v1/tenant/me/policy-scopes/rules/team-b -H "$K" -H 'Content-Type: application/json' -d '{"match":{"exact":["team-b"]},"input_guardrails":{"keyword_blocklist":{"enabled":false}}}'
```

**13. Rename the header.** List the new header first, keep the old one. The
team-a rule still applies, because rules are tied to values, not header names.

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/settings -H "$K" -H 'Content-Type: application/json' -d '{"enabled":true,"selectors":[{"header":"X-Team-Id"},{"header":"X-Org-Id"}],"missing":"global"}'
```

```bash
curl -s -X POST $B/v1/tenant/me/policy-scopes/preview -H "$K" -H 'Content-Type: application/json' -d '{"headers":{"X-Team-Id":"team-a"}}' | jq '{rule, source_header}'
```

Expect `rule: team-a`, `source_header: X-Team-Id`. After live traffic,
`/discovered` shows which header each value arrived on, so you can see when the
old header has gone quiet and remove it.

**14. Stop spoofing with a key binding.** Mint a second key, bind it to team-a,
then claim team-b with it. Expect 403.

```bash
curl -s -X POST $B/v1/admin/tenants/acme/api-keys -H "$A" -H 'Content-Type: application/json' -d '{"api_key":"sk-acme-teamA-0002"}'
```

```bash
curl -s -X PUT $B/v1/tenant/me/policy-scopes/key-bindings/sk-acme-team -H "$K" -H 'Content-Type: application/json' -d '{"allowed":["team-a"]}'
```

```bash
curl -s -o /dev/null -w '%{http_code}\n' $B/guardrails/input -H 'X-API-Key: sk-acme-teamA-0002' -H 'X-Org-Id: team-b' -H 'Content-Type: application/json' -d '{"message":"hi"}'
```

**15. Require the header.** Set `"missing":"reject"`; a request with no
selector header returns 403.

**16. Kill switch.** Restart with `SHIELD_DISABLE_POLICY_SCOPES=1` (or export it
in a shell that runs the server); step 9's team-a request now passes, "ssn"
still blocks.

**17. Proxy path (optional, needs an upstream model).** Send
`/v1/chat/completions` with `X-Org-Id: team-a` and check the
`X-Shield-Policy-Scope: team-a` response header.

### Worked example: many header values against one config

Config: global `keyword_blocklist` blocks `ssn`; rule `team-a` (exact `team-a`,
`teama`) adds `zebra`; rule `engineering` (glob `eng-*`) adds `payroll`;
`unmatched` adds `internal draft`; `missing: global`.

| `X-Org-Id` sent | Normalized | Rule | hello | my ssn | zebra | payroll | internal draft |
|---|---|---|---|---|---|---|---|
| `team-a` | `team-a` | team-a | pass | block | **block** | pass | pass |
| `TeamA` | `teama` | team-a (alias) | pass | block | **block** | pass | pass |
| `  TEAM-A ` | `team-a` | team-a | pass | block | **block** | pass | pass |
| `eng-payments` | `eng-payments` | engineering (glob) | pass | block | pass | **block** | pass |
| `eng-brand-new` (never seen) | `eng-brand-new` | engineering (glob) | pass | block | pass | **block** | pass |
| `sales-emea` (no rule) | `sales-emea` | unmatched | pass | block | pass | pass | **block** |
| no header | `(missing)` | global | pass | block | pass | pass | pass |
| sent twice: `team-a` and `eng-search` | `(invalid)` | unmatched | pass | block | pass | pass | **block** |
| `team-a, eng-search` (proxy-joined) | `(invalid)` | unmatched | pass | block | pass | pass | **block** |
| `X-Team-Id: eng-x` + `X-Org-Id: team-a`, selectors `[X-Team-Id, X-Org-Id]` | `eng-x` | engineering (first selector wins) | pass | block | pass | **block** | pass |

The `my ssn` column is `block` in every row: no header value gets below global.

Note: `action` is per guardrail, not per keyword. If global `keyword_blocklist`
were `warn` and a rule set it to `block`, every keyword in that guardrail would
block for that team, including the global ones. Use separate guardrails when
keywords need different actions.

## 9. Tasks (one PR each, in order)

0. **Docs fix (independent, small). Done.** `docs/enterprise-features.md`
   section 6, `docs/faq.md`, `docs/guardrails.md` and `README.md` said parent
   tenants enforce a baseline children "cannot weaken". The routes exist (an
   earlier search for them was wrong), but nothing on the request path reads
   the merge, and it covers data protection policies, not I/O guardrails.
   The docs now call parent tenants reporting only and point to team policies
   for an enforced baseline.
   - **0b. Bug fix (independent).** Make `regex_pattern` and `length_limit` read
     settings per request (section 7), with a test that two tenants with
     different `patterns` / `max_chars` get different results.
1. **`core/policy_scopes.py`**: normalize, select, merge, validate, memo. Pure
   functions, no wiring. Tests: `test_policy_scopes_merge.py`.
2. **Storage + routes**: `storage/policy_scopes_store.py`,
   `api/routes_policy_scopes.py` (including preview), mounted on both planes,
   `delegable` on `GuardrailPolicy`, the save-back marker refusal, and the
   `Dockerfile.admin` COPY lines. Tests: `test_policy_scopes_api.py`.
3. **Guard-path wiring**: middleware scoping on guarded paths, 403s, response
   field + proxy header, audit field, kill switch. Tests:
   `test_policy_scopes_guard_path.py`. Manual walkthrough steps 1 to 3 and 7 to 17.
4. **Discovery**: in-process aggregator, background flush, `/discovered`.
   Tests: `test_policy_scopes_discovery.py`. Walkthrough steps 4 to 6.
5. **Portal + customer docs**, on the existing I/O Guardrails page in
   `static/tenant.html` (no new page):
   - an "Editing policy for" switcher above the guardrail cards: Global, each
     rule, Unmatched values, "+ Team rule", plus the header names in use;
   - with a team selected, the same cards render the effective policy: global
     guardrails carry a locked "Global" badge, their action dropdown lists only
     stricter actions, their toggle cannot be switched off, and global list
     items (keywords) are locked chips while team-added items are removable;
     team-only guardrails carry a "team only" badge and are fully editable;
   - "Save changes" writes `PUT /rules/{id}` when a team is selected and the
     existing global route when Global is selected;
   - a Discovered values list (value, header, requests, policy now, "Create rule");
   - a Try it box backed by `POST /preview` plus `/guardrails/input`;
   - `docs/team-policies.md` (`/team-policies/`) built from the walkthrough (no em dashes).
