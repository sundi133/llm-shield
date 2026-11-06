# Spec: filter Telemetry by team

Status: **draft 2026-11-05, awaiting approval.** Branch
`claude/telemetry-team-filter-d47eb0`.

Builds on `docs/specs/policy-scopes.md` (team rules, PRs #530 to #535) and
`docs/specs/unified-agent-telemetry.md` (the Telemetry endpoint and its Source
filter).

## 1. Problem & outcome

A tenant admin creates teams under **I/O Guardrails** (a team rule is "when
header `x-tf-organization-id` is `x3mxvkr`", rule id `tenant1`). On the
**Telemetry** page there is no way to see one team's requests: the filters are
Search, Status, Time Range, Agent, Tool and Source, and no row says which team
it belongs to. Reported from shield.votal.ai/tenant on 2026-11-05 with two
teams, `tenant1` (`x3mxvkr`) and `rafay-ops` (`7dkgjkx`).

**Outcome:** the Telemetry page has a **Team** filter listing the tenant's own
team rules. Choosing `tenant1` shows only requests that were matched to the
`tenant1` rule (in the example, requests that carried
`x-tf-organization-id: x3mxvkr`), and the summary tiles count only those. Each
row shows the team it was matched to.

### What the investigation found (so the change is small)

| Question | Answer |
|---|---|
| Where are Telemetry rows written? | `audit_logger.log(...)` (`storage/audit_log.py`) with `metadata.kind == "agent_chat_telemetry"`, from the guard routes and the chat proxies, all on the data plane. |
| Where are they read? | `GET /v1/tenant/me/telemetry` (`api/routes_tenant_self.py:689`, `get_my_telemetry`), mounted on both planes; the portal calls it from `loadTelemetry()` in `static/tenant.html`. |
| Where is the team resolved? | `core/middleware.py` `_apply_policy_scope` (on `ShieldMiddleware._POLICY_SCOPE_PATHS`), which sets `request.state.policy_scope` to a `core.policy_scopes.Decision(rule, value, header)`. `core.policy_scopes.request_scope(request)` returns it as a dict. |
| Is the team already stored? | **Yes on the guard routes, no on the chat proxies.** Since #530, `/guardrails/input` and `/guardrails/file` (`api/routes_classify.py:399`, `:715`) and `/guardrails/output` (`api/routes_classify_output.py:619`) write `metadata.policy_scope = {"rule", "value", "header"}` (or `null` for a tenant without team rules). `/beta/litellm_basic_guardrail_api` calls those same handlers with the same request, so LiteLLM traffic is tagged too. The three chat proxies on the scoped path list, `/v1/chat/completions` (`api/routes_openai_compat.py`, 4 writes), `/v1/shield/chat/completions` (`api/routes_gateway.py`, 7 writes) and `/v1/shield/chat/agent` (`api/routes_agent_chat.py`, one helper `_log_agent_chat_telemetry`), run the team's policy but do not record which team. |
| What did #534 add? | Nothing for this page. #534 (`docs/specs/telemetry-body-structure.md`) changed the **SIEM** events in `core/telemetry.py` so `request.body.request_headers.x-tf-organization-id` survives long bodies. Those events go to the log shipper, not to `audit:{tenant}`, and the portal never reads them. |
| Why "unknown-agent / role unavailable"? | The callers send no `X-Agent-Key` or role. Unrelated to teams; out of scope (section 1, non-goals). |

So the read side and the UI are the main work. The only write change is three
chat-proxy files recording the decision the middleware already made.

**Non-goals**

- Backfilling old records. Chat-proxy records written before this change, and
  any record from before #530, have no team and cannot get one: the header
  value was never stored in `audit:{tenant}`.
- Filtering by raw header value. The filter is by team (rule id); the value is
  shown on the row.
- Teams on coding-agent hook rows (Source = Coding agent), MCP gateway
  `tools/call` rows (`core/mcp/gateway.py`) and the admin portal's own test chat
  (`admin_app._log_agent_chat_telemetry`). None of these paths select a team.
  The portal test chat calls `/guardrails/input` on the data plane, which writes
  its own record.
- The team in SIEM/ASIM events (`core/telemetry.py`, `core/asim.py`).
- Rows for rules that were deleted: those rows keep their rule id on the tag,
  but the dropdown lists current rules only.
- Fixing "unknown-agent / role unavailable".

## 2. Plane & latency contract

| Part | Plane | Guard path? |
|---|---|---|
| Record the team on chat-proxy rows | **Data plane** (`core/app.py`): `api/routes_openai_compat.py`, `api/routes_gateway.py`, `api/routes_agent_chat.py` | On the request path of the chat proxies, not on `/guardrails/*`, `cap/mint` or `tools/call`. |
| `team` filter on `GET /v1/tenant/me/telemetry` | **Both planes** (the router is mounted by `core/app.py` and `admin_app.py`); the portal uses the admin plane | Off the hot path. A read endpoint. |
| Team dropdown and row tag | Portal (`static/tenant.html`) | Off the hot path. |

**Latency contract for `/guardrails/*`: no change.** No code on
`/guardrails/input`, `/guardrails/output`, `/guardrails/file` or the LiteLLM
route changes; they already record the team. `cap/mint` and `tools/call` are
untouched.

**Chat proxies:** the added work per telemetry write is one
`request_scope(request)` call (a `getattr`, an `isinstance`, a 3-key dict, under
1 µs) and one extra key in a dict that is already being built. No I/O. The
Redis write itself is unchanged: `audit_logger.log` already hands it to a
thread-pool executor (`storage/audit_log.py:70`), so it is not awaited by the
request. Record size grows by about 80 bytes for teams-enabled tenants only.

**Read endpoint:** it already loads every `audit:{tenant}` entry in the time
range and filters in Python. The team filter adds one dict lookup and one
string compare per entry. No new Redis call.

## 3. Data model

No new Redis keys. Existing key: `audit:{tenant_id}`, a ZSET of JSON records
scored by epoch seconds (`storage/audit_log.py`), 30-day per-entry retention
(`AUDIT_TTL_SECONDS`), unchanged.

Field used, inside each record's `metadata` (already written by the guard
routes, newly written by the chat proxies):

```json
"policy_scope": {"rule": "tenant1", "value": "x3mxvkr", "header": "x-tf-organization-id"}
```

| `rule` | Meaning | Portal label |
|---|---|---|
| a rule id, e.g. `tenant1` | the value matched that team rule | the rule id, e.g. **tenant1** |
| `global` | no team header, or a value that matched no rule while the tenant has no "Other values" policy | **Global** |
| `unmatched` | a value that matched no rule, and the tenant has an "Other values" policy | **Other values** |

`global` and `unmatched` are reserved: `validate_rule` refuses them as rule ids
(`core/policy_scopes.py:715`), so a team can never be confused with them.

**When no team is recorded** (`policy_scope` absent or `null`): the tenant had
no team rules or they were off (`enabled: false`, or the kill switch
`SHIELD_DISABLE_POLICY_SCOPES`), the record predates #530, or it is a
chat-proxy record from before this change. The chat proxies record **nothing**
in this case (the key is omitted, not set to `null`), so tenants without teams
get byte-identical records. The guard routes keep writing `null`, as today.

**Tenant scoping.** `policy_scope` is computed from the requesting tenant's own
config (the middleware resolves the tenant from the API key first), and the
record goes to `audit:{that tenant}`. The read endpoint reads only
`audit:{caller's tenant}` and also checks `metadata.tenant_id` (existing). The
dropdown is filled from `GET /v1/tenant/me/policy-scopes`, which returns the
caller's own rules only.

## 4. API / interface

### `GET /v1/tenant/me/telemetry` (existing, both planes)

New optional query parameter:

| Param | Values | Rows returned |
|---|---|---|
| `team` omitted or empty | | all rows (today's behaviour) |
| `team=<rule id>` | `^[a-z0-9][a-z0-9_-]{0,63}$` | chat rows whose `metadata.policy_scope.rule` equals it |
| `team=global` | | chat rows with `policy_scope.rule == "global"` |
| `team=unmatched` | | chat rows with `policy_scope.rule == "unmatched"` |
| `team=(none)` | | rows with no team recorded: chat rows with `policy_scope` absent, `null` or not an object, **and** coding-agent rows |

- A value that is none of the above (bad characters, over 64 chars) is a
  **422**, so a typo can't silently show an empty page that looks like "no
  traffic". A well-formed rule id that is not one of the tenant's rules is not
  an error; it just matches nothing (rules can be deleted, and the endpoint
  should not need the tenant config to answer).
- When `team` is set to anything but `(none)`, coding-agent rows are excluded
  (they never have a team).
- The filter applies before paging and before the summary, so `total` and the
  tiles count the team's rows only.
- Each chat row gains `"policy_scope": {...} | null` (copied from the record).
  Coding-agent rows get `"policy_scope": null`.
- The response echoes `"team": "<value>" | null`. The portal uses the echo to
  tell an older server (which ignores unknown params and would return every
  row) from a real result, and shows "This server does not support the Team
  filter yet" instead of unfiltered rows.

Auth: unchanged (`_require_tenant`: tenant key or portal session). No write.

### Portal (`static/tenant.html`, Telemetry tab)

- **Team** dropdown after Source, filled on tab load from
  `GET /v1/tenant/me/policy-scopes` (`PS_BASE`, already used by I/O
  Guardrails):
  - **All teams** (default, no `team` param)
  - **Global** (`global`)
  - one option per rule, label `<rule id> (<first exact value>)`, e.g.
    `tenant1 (x3mxvkr)`, value = rule id; label text escaped
  - **Other values** (`unmatched`), only when the tenant has an `unmatched`
    policy
  - **No team recorded** (`(none)`)
- If the tenant has no `policy_scopes` or no rules, the dropdown is hidden and
  nothing changes on the page. If the policy-scopes call fails, the dropdown is
  hidden and the rest of the page loads.
- Selecting a team and pressing **Apply** sets `team` on the telemetry call
  (same flow as the other filters).
- **Row tag:** in the Source cell, under the Chat / Coding agent badge, a small
  team tag when the row has a `policy_scope`: the rule id, "Global" or "Other
  values", with the header and value in a `title` tooltip
  (`x-tf-organization-id: x3mxvkr`). No tag when there is no team. A tag, not
  a new column, so the 8-column layout, the detail `colspan` and the mobile
  layout don't change.
- The filter grid gets one more column.

## 5. Security & backward compatibility

- **Default unchanged.** Without `team`, the endpoint returns the same rows
  and summary as today, plus a `policy_scope` field on each row and a `team:
  null` echo (additive). Tenants without team rules see no new UI and get
  byte-identical chat-proxy records.
- **Chat-proxy records** gain `metadata.policy_scope` only when the middleware
  made a decision. Consumers that read `audit:{tenant}` see one more key.
  Additive; no escape-hatch flag needed. The existing
  `SHIELD_DISABLE_POLICY_SCOPES` kill switch stops decisions, and so stops the
  field.
- **Isolation.** A tenant can only filter its own rows: the `team` value is
  compared against records already restricted to `audit:{caller}`; it is never
  used to build a key or look up another tenant. Passing another tenant's rule
  id returns only the caller's rows that happen to use the same id (usually
  none). The dropdown lists only the caller's rules.
- **Data exposure.** The header value (e.g. `x3mxvkr`) was already in the
  record for guard-route rows and is already shown to the same admin on the
  I/O Guardrails page (Discovered values). Selector headers that carry
  credentials are refused by `_FORBIDDEN_HEADERS`, so a credential can't be a
  team value.
- **XSS.** Rule ids, values and header names are rendered with `escapeHtml`
  (option labels, tag text and `title`).

## 6. Packaging & deploy

- No new module, no new dependency, no Dockerfile change: `admin_app.py`
  already imports `api.routes_tenant_self`; the chat-proxy files already import
  from `core` and `core/policy_scopes.py` is already in the data-plane image.
  `tests/test_admin_dockerfile_imports.py` keeps guarding this.
- No new env flag.
- Rebuild both images (data plane for the chat-proxy records; admin plane for
  the endpoint and `static/tenant.html`). Order doesn't matter: the read side
  works on guard-route records the day it ships.

## 7. Failure modes & edge cases

| Case | Result |
|---|---|
| Tenant has no team rules | No dropdown, no tags, records unchanged. |
| `policy_scope` is `null`, absent, or not an object (old or odd record) | Treated as "no team": matches only `team=(none)`, no tag. Never raises. |
| `policy_scope.rule` missing or not a string | Same as no team. |
| Team rule deleted after traffic | Its rows keep the tag; still reachable by `team=<old id>` via the API; not in the dropdown. |
| Rule's values changed after traffic | Rows keep the rule they matched at request time (that is what ran). |
| Same value moved to another rule | Old rows stay under the old rule. |
| Degraded selection (selection error, global applied) | Recorded as `global`, as the guard routes do today. |
| Request refused by the scope check (403 missing header / key binding) | No telemetry row, as today. |
| `team` param malformed | 422 with the allowed forms. |
| Policy-scopes call fails in the portal | Dropdown hidden; telemetry still loads unfiltered. |
| Older server ignores `team` | Response has no `team` echo; the portal shows a notice instead of unfiltered rows. |
| Redis down | Unchanged: the write is best-effort, the read returns no rows. |
| A huge range (30 days) | Same cost as today plus a dict lookup per entry. |

Fail-open vs fail-closed: telemetry never affects enforcement. Recording the
team can't fail a request: `request_scope` doesn't raise, and the write is
already wrapped in the logger's own try/except.

## 8. Test plan (Definition of Done)

New `tests/test_telemetry_team_filter.py`:

1. **Chat proxies record the team.** For each of `/v1/chat/completions`,
   `/v1/shield/chat/completions` and `/v1/shield/chat/agent`, with a tenant
   whose rule `tenant1` matches `x-tf-organization-id: x3mxvkr` and a stubbed
   upstream model: the `agent_chat_telemetry` record has
   `metadata.policy_scope == {"rule": "tenant1", "value": "x3mxvkr", "header":
   "x-tf-organization-id"}`. Covers the pass path and an input-block path.
2. **No team, nothing new.** Same calls for a tenant without `policy_scopes`:
   no `policy_scope` key in `metadata`.
3. **Every write site is covered.** A source-level check that every
   `"kind": "agent_chat_telemetry"` dict in the three proxy files (and the
   agent-chat helper) includes `policy_scope`, so a new write site can't drift.
   Sabotage-checked by removing one.
4. **Filter by team.** Seed `audit:{t}` with rows for `tenant1`, `rafay-ops`,
   `global`, `unmatched`, `null`, absent, and a non-dict `policy_scope`, plus a
   coding-agent decision. `team=tenant1` returns only the `tenant1` rows;
   `global`, `unmatched` and `(none)` each return exactly theirs; `(none)`
   includes the coding-agent row; no `team` returns all.
5. **Summary and paging follow the filter:** `total`, `summary.messages` and
   `by_status` count the team's rows only; `offset`/`limit` page within them.
6. **Rows carry `policy_scope`**, and the response echoes `team`.
7. **422** for `team=Bad Value!` and a 65-char id; 200 for an unknown
   well-formed id with zero rows.
8. **Isolation:** two tenants, both with a rule `tenant1`; tenant A's
   `team=tenant1` never returns tenant B's rows, and tenant A's key can't read
   B's rules for the dropdown.
9. **Portal static checks** (in the style of
   `tests/test_policy_scopes_portal.py`): the Team select exists in the
   Telemetry filter grid; `loadTelemetry` sets `team`; the dropdown is filled
   from `PS_BASE`; option labels and the tag use `escapeHtml`; the script still
   parses; the "server does not support" notice keys off the `team` echo.
10. **End to end** through `TestClient`: a `/guardrails/input` call with
    `x-tf-organization-id: x3mxvkr` and one with `7dkgjkx`, then
    `GET /v1/tenant/me/telemetry?team=tenant1` returns only the first. This is
    the done condition.
11. Existing `tests/test_telemetry_merge.py`, `tests/test_policy_scopes_*.py`
    and `tests/test_delegation_visibility.py` stay green.

Full suite `python -m pytest tests -q` green in a clean venv; CI `pytest` gate
passes.

**Manual:** on a local Shield with two team rules, send requests with each
header value, open Telemetry, choose each team, check rows, tags and tiles.

## 9. Tasks (one PR, one commit each)

1. **Data plane: record the team on chat-proxy telemetry.** Add
   `policy_scope` (only when `request_scope(request)` is not `None`) to every
   `agent_chat_telemetry` write in `api/routes_openai_compat.py`,
   `api/routes_gateway.py` and `api/routes_agent_chat.py`. Tests 1 to 3.
2. **Read: `team` filter on `GET /v1/tenant/me/telemetry`.** Param
   validation, filter before paging and summary, `policy_scope` on each row,
   `team` echo. Tests 4 to 8 and 10.
3. **Portal: Team dropdown and row tag** in `static/tenant.html`, plus the
   old-server notice. Test 9 and the manual walkthrough.
