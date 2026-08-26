# Spec: Enrich MCP gateway telemetry MESSAGE label

## 1. Problem & outcome
In the tenant portal Telemetry table, MCP gateway rows show only
`mcp_call:<tool>` in the MESSAGE column, while chat rows show real agent text.
Operators reading the table can't tell, at a glance, which route a gateway call
went through or what the enforcement decision was — they have to open Details.

**Outcome:** gateway rows render a single-line, non-sensitive enriched label,
e.g. `mcp_call:card_details_get · banking · redacted`, built from metadata
already present in the audit event (tool, route, decision/action). Chat rows are
unchanged.

**Non-goals (explicit):**
- Do **NOT** store MCP tool arguments, prompt text, or output content. That is a
  standing invariant (`docs/spec-mcp-gateway-audit.md`, and the code comment at
  `core/mcp/gateway.py`: "Records the tool NAME only, never arguments").
  This spec adds only tool name + route + decision, all already recorded.
- No new UI/frontend change. `static/tenant.html` already renders `input_text`
  verbatim and shows the last non-empty line in the column; a single-line label
  needs no template change.
- No new "source/type" badge (that was Option B; not chosen).

## 2. Plane & latency contract
- **Plane:** data plane (GPU/vLLM guardrail server) — the change is in
  `core/mcp/gateway.py::_audit_decision`, the audit sink for the MCP gateway.
- **Guard path:** the gateway *is* on the guard path, BUT `_audit_decision` runs
  inside `audit_logger.log`, which is already fire-and-forget
  (`run_in_executor`, not awaited — see the docstring at
  `core/mcp/gateway.py:194`). This change only alters an f-string built from
  fields already read from `event`. **No new I/O, no new awaits, no measurable
  latency added to the guarded call.**

## 3. Data model
- No new keys, shapes, or TTLs. Same audit record written to the same store via
  `storage.audit_log.audit_logger.log`.
- Only the value of the existing `input_text` field changes:
  - before: `f"mcp_call:{tool}"`
  - after: `f"mcp_call:{tool}"` plus ` · {route}` when route is present, plus
    ` · {label}` where `label` is a human word for the decision derived from
    `allowed` + `action` (e.g. `blocked`, `redacted`, `masked`, `monitored`,
    `allowed`). All three parts come from fields already in `event`.
- Tenant scoping unchanged (record still dropped when `tenant_id` is empty).

## 4. API / interface
No endpoint or router change. `GET /v1/tenant/me/telemetry`
(`api/routes_tenant_self.py`) already maps `message = input_text`; it will carry
the richer string automatically.

## 5. Security & backward compatibility
- **Content safety:** every added token is metadata the record already stores
  (`tool`, `route`, `action`, `allowed`). No argument/prompt/output text is
  introduced. Route names are tenant config identifiers, not user data.
- **Backward compatibility:** the `mcp_call:<tool>` prefix is preserved, so any
  reader keying off that prefix still matches. Detail-panel fields
  (`tool_calls`, `block_reason`, `action_taken`, `route`, `mode`) are untouched.
- **Default behavior:** this is a display-label refinement of an existing row,
  not a behavior change to enforcement. No escape-hatch flag needed; it does not
  gate, block, or alter any guarded decision. (If desired we can keep it
  unconditional — no config surface.)
- **Authz:** unchanged; same tenant-scoped telemetry read.

## 6. Packaging & deploy
- No new module, no new `admin_app.py` import → **no `Dockerfile.admin` change.**
- No new pip dependency → no `requirements*.txt` change.
- No env flag. Rebuild the **data-plane image** (the one running
  `core/app.py` / the gateway) on rollout. Admin image unaffected.

## 7. Failure modes & edge cases
- **Empty route** (`event["route"]` missing/empty): omit the route segment;
  label degrades to `mcp_call:<tool> · <decision>`.
- **Empty action** on the legacy pre-sanitize path: fall back to `allowed` /
  `blocked` from the `allowed` boolean, so the decision word is always present.
- **Weird/long tool or route strings:** the column preview already truncates via
  `telemetry-row-message` CSS + last-line logic; no new truncation needed. No
  newlines are introduced, so the ` · ` label stays on one line.
- **Audit disabled / tenant missing / logger raises:** unchanged — the function
  still early-returns and still swallows exceptions (`audit must never fail a
  call`). Fail-open preserved.

## 8. Test plan (Definition of Done)
- Unit tests (extend the existing gateway-audit test module) asserting the
  `input_text` written to a stubbed `audit_logger` for:
  1. allowed call with a route → `mcp_call:<tool> · <route> · allowed`
  2. input-blocked call → `... · blocked`
  3. output redact/mask decision (deferred path) → `... · redacted` / `masked`
  4. monitor-mode / would-block → `... · monitored`
  5. empty route → no ` · <route>` segment, decision word still present
- Regression guard: assert the label still starts with `mcp_call:<tool>` so
  prefix-based consumers don't break.
- Full suite green in a clean venv; CI `pytest` gate passes.

## Scope / PR breakdown
Single small PR on the current feature branch:
1. Edit `core/mcp/gateway.py::_audit_decision` — build the enriched
   `input_text` from existing event fields; add a tiny helper mapping
   (allowed, action) → decision word.
2. Add/extend gateway-audit unit tests per §8.

One task, one PR. No companion Dockerfile/dep fixes needed (verified in §6).
