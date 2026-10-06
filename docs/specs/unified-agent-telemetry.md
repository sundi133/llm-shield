# Spec: unified agent activity in the Telemetry tab

Status: DRAFT, awaiting approval.

## 1. Problem & outcome

The Telemetry tab (`GET /v1/tenant/me/telemetry`) shows only **agent-chat**
events: entries in the audit log with `metadata.kind == "agent_chat_telemetry"`,
written by the chat proxies and `/guardrails/input`. The **coding-agent hook**
decisions — prompt checks, tool-call checks, result redactions from Claude Code
and Codex — are written by `log_decision` to a different store
(`decisions:{tenant_id}`, read by `GET /v1/shield/decisions/{tenant}`). So an
operator looking at Telemetry sees chat traffic and the old `/guardrails/input`
probes, but none of the coding-agent blocks, even though they happened. There
is no single place to see everything an agent did.

**Outcome.** The Telemetry tab shows **both** streams in one list: agent-chat
requests and coding-agent hook decisions (prompt blocked/warned, tool call
denied, tool result redacted/withheld), each as a row with time, agent,
message/action, status, stage, latency. A **Source** filter (`chat` /
`coding-agent`) and the existing Agent / Status / Tool / search filters narrow
it. The summary tiles count both.

**Observable success.**
- With the agent-hooks prompt check on, "encrypt a file" blocked in Claude
  Code appears in the Telemetry tab as a `coding-agent` row, status `block`,
  agent `hooks-test`, message the policy name (from the #473 summary),
  **never the prompt text**.
- Filtering Source = coding-agent hides chat rows and vice versa.
- A tool-result redaction shows as status `redact` with the tool name.

**Non-goals.**
- No change to how decisions are made or recorded; this is a **read-side**
  merge of two existing stores.
- No prompt or result content in Telemetry rows beyond what each store already
  holds (the hook store holds a hash and length, never the text — unchanged).
- Not merging infra/robot runtime events (OpenShell, embodied) into this tab;
  those keep their own views. Scope is coding-agent hooks (`source ==
  "claude_code"`, kinds the hook route writes).
- No new store, no schema migration.

## 2. Plane & latency contract

- **Admin/read plane only.** `GET /v1/tenant/me/telemetry` is a read endpoint,
  off the guard path. It already fans out one store read; this adds a second
  (`decisions:{tenant}` / the runtime-event audit entries) and merges in
  memory.
- **Guard path untouched.** `/guardrails/*`, `cap/mint`, `tools/call`, and the
  hook routes are unchanged. No new write on any decision path — both stores
  are already written today.
- **Budget:** the endpoint reads at most `limit`-bounded slices of each store
  (today it over-reads 1000 audit rows and filters; the merge keeps the same
  bound per store). Response stays well under the page's existing latency.

## 3. Data model

No new keys. Two existing sources, read and merged:

| Source | Store | Written by | Row fields used |
|---|---|---|---|
| chat | audit log, `metadata.kind == "agent_chat_telemetry"` | chat proxies, `/guardrails/input` | as today |
| coding-agent | `decisions:{tenant_id}` (`guardrail == "runtime_boundary"`, `tool_name` in `runtime:dlp` / `runtime:exec` / `runtime:file` / `runtime:net`) **or** audit entries with `metadata.path == "runtime_event"` and `source == "claude_code"` | the hook routes via `log_decision` / `rt_events` | agent_key, action, tool_name, reason, session_id, timestamp, metadata.detail (hook, verdict, policy/tool names, prompt_len) |

Tenant scoping is unchanged: both stores are already keyed by `tenant_id`, and
the endpoint resolves the tenant from the API key as today.

**Decision on which store to read for coding-agent rows** (open question for
review): `decisions:{tenant}` holds only non-allow decisions (blocks,
redactions), which is what an operator usually wants; the runtime-event audit
entries hold allow + non-allow but are heavier. Proposed: read
`decisions:{tenant}` (non-allow only) by default, and add `include=allowed`
later if wanted. This keeps the tab focused on what Shield acted on.

## 4. API / interface

`GET /v1/tenant/me/telemetry` gains:
- `source` query param: `chat` | `coding-agent` | omitted (both).
- Each returned row gains `"source": "chat" | "coding-agent"` and `"stage"`
  (`input` for prompt checks, `tool` for tool/result checks, unchanged for
  chat).
- Coding-agent rows map to the existing row shape:
  `message` = the decision summary (`coding-agent prompt block: <policy>` from
  #473), `status` = the verdict (`block`/`redact`/`warn`/`monitor`/`allow`),
  `agent_key`, `tool_name`, `latency` (from the event, when present), `time`.
- Summary tiles (messages / blocked / warnings / tool calls) count the merged
  set; "blocked" includes coding-agent `block`, "warnings" includes `warn` and
  `redact`.
- Existing params (`agent_key`, `status`, `tool_name`, `q`, `since`, `until`,
  `limit`, `offset`) apply across both; sort by time desc, then page.

The portal Telemetry tab adds a **Source** dropdown and a Source column; no new
page.

## 5. Security & backward compatibility

- **Additive and opt-viewable.** Default (no `source`) now returns both
  streams. A caller that depended on Telemetry being chat-only sees extra rows;
  mitigated by the `source=chat` param and documented. Escape hatch:
  `SHIELD_TELEMETRY_INCLUDE_CODING_AGENT=0` restores chat-only.
- **No new content exposure.** Coding-agent rows carry only what the decisions
  store already holds — the summary, verdict, policy/tool names, prompt hash and
  length. The prompt and result text are not in that store and are not added.
- **Authz unchanged:** same tenant-key scoping; a tenant sees only its own rows
  from both stores.
- **No cross-tenant risk:** both reads are tenant-keyed; the merge filters
  `tenant_id` on each side as the endpoint does today.

## 6. Packaging & deploy

- Data/admin plane: `api/routes_tenant_self.py` (the endpoint), a small reader
  for `decisions:{tenant}` (reuse `storage/decision_audit.query_decisions`),
  and `static/tenant.html` (the Source filter/column).
- No new module imported by `admin_app.py` beyond what it already imports
  (`storage.decision_audit` is already in the image — confirm in the task and
  add to `Dockerfile.admin` if not; guarded by
  `tests/test_admin_dockerfile_imports.py`).
- No new pip dependency. Env flag `SHIELD_TELEMETRY_INCLUDE_CODING_AGENT`
  (default on).
- Rebuild: admin plane (portal) and data plane (the endpoint is on the tenant
  self router).

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| `decisions:{tenant}` store empty or unavailable | return chat rows only; log a warning; never fail the whole endpoint |
| A coding-agent decision with no latency recorded | row shows blank latency, not 0 |
| Monitor-mode coding-agent decision (`verdict: monitor`) | status `monitor`, counted under warnings, not blocked |
| Merge exceeds `limit` | sort by time desc across both, then truncate to `limit`; `offset` paginates the merged list |
| Old agent-chat rows without `source` | labelled `chat` by default |
| `source=coding-agent` but the flag is off | return empty coding-agent set (flag wins), documented |
| Huge reason text | already capped (300 chars) at write time |

## 8. Test plan (Definition of Done)

- Endpoint returns both sources; `source` filter selects each; a coding-agent
  block from the hook route shows with the policy-name summary and `status:
  block`, no prompt text in the row.
- Summary tiles count merged blocks/warnings/redactions.
- `agent_key` / `status` / `tool_name` / `q` / `since` / `until` apply across
  both stores; time-desc sort and `offset` paging over the merged list.
- `SHIELD_TELEMETRY_INCLUDE_CODING_AGENT=0` restores chat-only (regression
  guard for the escape hatch).
- Decisions store down → chat-only, no error.
- `tests/test_admin_dockerfile_imports.py` still green (any new admin import
  added to `Dockerfile.admin`).
- Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each)

1. **Endpoint merge:** read `decisions:{tenant}` for coding-agent rows, map to
   the telemetry row shape, add `source`/`stage`, merge + sort + page, summary
   tiles, the env flag. Tests.
2. **Portal:** Source dropdown + column on the Telemetry tab; counts; verified
   in the browser at desktop and phone width.

Depends on #473 (the decision summary) for readable coding-agent `message`
text; land that first.
