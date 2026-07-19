# Spec: MCP tool-call guard parity

## 1. Problem & outcome

`core/mcp/enforcement.py::_tool_guard_chain()` runs a 4-guard subset (RBAC, data
access, allowlist, validation) of what the REST path runs in
`api/routes_tool.py::_CHECK_GUARDS` (7 guards). The MCP path skips
`ToolUseControl`, `ToolCallRateLimiting`, and `SensitiveActionConfirmation`.
`SHIELD_MCP_TOOL_PARITY` restores the guard *set* but defaults to `"0"`, and a
grep of every compose file, Dockerfile, and `openshift/` manifest confirms the
flag is set in **zero** deployments.

Separately, `core/mcp/enforcement.py` never verifies a capability token and never
calls the approval gate at `api/routes_agent_auth.py:249` (grep for `verify_cap`,
`mint_cap`, `approval` in `core/mcp/*.py` returns nothing). So an MCP-routed
`transfer_funds` or `delete_records` today receives no human-approval check on
either the guard-chain path or the capability path.

**Two findings that make this bigger than a flag flip:**

1. **Parity-on does not currently deliver HITL.** The MCP context dict
   (`enforcement.py:141-149`) omits `session_id`.
   `SensitiveActionConfirmationGuardrail.check()` returns `pass` at line 22-24
   when `session_id` is falsy. So an operator who sets `SHIELD_MCP_TOOL_PARITY=1`
   today gets the guard in the chain, where it no-ops. `core/mcp/http_enforcer.py:103`
   hardcodes `"session_id": ""`, confirming the gap on that path too.
   `tests/test_mcp_tool_parity.py` pins the guard *set*, not that the guards fire,
   so the regression test passes while the control is inert.
2. **There is no return channel for a confirmation token.** The guard emits
   `pending_confirmation` plus a token (`sensitive_action_confirmation.py:66-69`),
   but MCP `tools/call` has no field for the caller to send it back on retry.
   Without a transport decision, a sensitive tool would deadlock rather than gate.

**Outcome:** an MCP-routed tool call is subject to the same guard set as the REST
path, the HITL guard actually fires, and confirmation is completable over MCP.
Observable success: with parity in `enforce`, a `tools/call` for a tool listed in
`require_confirmation` returns a `pending_confirmation` error carrying a token,
and the same call replayed with that token in `_meta` succeeds exactly once.

**Non-goals:**
- Capability-token verification on the MCP path (real gap, separate spec).
- Changing `core/risk.py` scoring (`send`/`publish`/`create` under-tiering).
- Any change to the REST chain or to `routes_tool.py`.
- Fixing fail-open defaults in budget/scope/memory guards (separate spec).

## 2. Plane & latency contract

**Plane:** data plane only (`core/app.py`). No admin-plane file changes, no new
`admin_app.py` import, so `Dockerfile.admin` is untouched.

**Touches the guard path: YES** — `tools/call` is named in the invariant. Budget
and justification:

| Guard | tier | Cost per call |
|---|---|---|
| `ToolUseControl` | `fast` | In-process only. Iterates `settings["rules"]`, `datetime.now()`, one `enforcer.resolve_role()` dict lookup. No I/O. |
| `ToolCallRateLimiting` | `fast` | 1-3 `agentic_state.increment()` (global, per-tool, per-session windows) |
| `SensitiveActionConfirmation` | `fast` | 0 ops when the tool is not in `require_confirmation` (returns at line 27-29 before touching state). 1 get+delete or 1 set when it is. |

Worst case adds ~4 Redis round trips; typical case (tool not sensitive, rate
limits configured) is 1-3. All three are `tier = "fast"` and none call an LLM.

The justification that matters: `ToolCallValidationGuardrail` is **already** in the
MCP base chain and delegates entirely to `evaluate_payload_policy_llm`, so every
`tools/call` already blocks on an LLM inference. Adding sub-millisecond Redis ops
behind an existing model round trip is well inside noise. The chain also early-exits
on first block (`enforcement.py:160-161`), so a denied call gets cheaper, not
dearer.

**Latency budget:** p50 delta < 5 ms, p99 delta < 15 ms, measured against the
existing chain. Task 4 pins this with a benchmark rather than asserting it.

## 3. Data model

No new Redis keys. Reuses keys the REST path already writes:

| Key | Written by | Shape | TTL |
|---|---|---|---|
| `confirm:{session_id}:{token}` | `sensitive_action_confirmation.py:58` | `{tool_name, agent_key, tool_params, created_at}` | `confirmation_ttl_seconds`, default 300 |
| rate-limit counters | `tool_call_rate_limiting.py:30,42,54` | int | per-window |

**Tenant scoping.** `session_id` is the isolation-critical field here. It MUST be
derived from the verified agent-token claim, never from a caller-supplied header.
Agent tokens already carry `session_id` (`core/agent_tokens.py`). A caller-supplied
`Mcp-Session-Id` would let an agent rotate its own session to reset rate-limit
buckets and to mint confirmation tokens against another session's namespace.

Because `confirm:` keys are namespaced by an authenticated `session_id`, and
sessions are minted per-tenant, cross-tenant collision is not reachable without
forging an Ed25519-signed token. Note the existing key is not tenant-prefixed;
that is acceptable only because `session_id` is unforgeable. Task 1 adds a test
asserting the session is read from claims and that a header cannot override it.

## 4. API / interface

No new endpoints. Two interface changes to the existing MCP surface:

**a) Context enrichment** (`core/mcp/enforcement.py:141-149`) adds:

```python
"session_id": session_id,   # from verified agent-token claim
"workflow": workflow,       # from _meta, optional
"confirmation_token": confirmation_token,  # from _meta, optional
```

`enforce_tool_call()` gains matching keyword-only params, all defaulting to `None`
so existing callers (`core/mcp/proxy_server.py:100`, `api/routes_openapi_mcp.py:174`,
`core/mcp/http_enforcer.py:87`) keep compiling unchanged.

**b) Confirmation transport.** MCP `tools/call` params carry a reserved `_meta`
object in the JSON-RPC spec, which is the idiomatic place for
protocol-level-but-not-tool-level data and is passed through by MCP clients
without being confused for tool arguments. Proposed:

Request:
```jsonc
{"method": "tools/call",
 "params": {"name": "transfer_funds",
            "arguments": {...},
            "_meta": {"shield/confirmation_token": "a1b2c3...",
                      "shield/workflow": "finance-approval"}}}
```

Response when confirmation is required (JSON-RPC error, so clients surface it):
```jsonc
{"error": {"code": -32001,
           "message": "Tool 'transfer_funds' requires human confirmation",
           "data": {"shield/confirmation_token": "a1b2c3...",
                    "expires_in": 300,
                    "action": "pending_confirmation"}}}
```

Rationale for `arguments` being wrong: a token in `arguments` would be forwarded
to the upstream tool as a real parameter and would change the `params_hash`,
breaking any future binding to the approval grant.

**Auth:** unchanged. Data plane mounts the MCP routers as today.

## 5. Security & backward compatibility

**Default behavior change: yes, and this is the risk to manage.**

`SHIELD_MCP_TOOL_PARITY` becomes three-state, replacing the boolean:

| Value | Behavior |
|---|---|
| `off` | **Remains the default.** Current 4-guard chain, byte-identical to today. |
| `monitor` | Opt-in. All 7 guards run. Results recorded in `results[]` and `would_block[]`. The 3 added guards can never change `allowed`, regardless of tenant `policy_mode`. |
| `enforce` | Opt-in. All 7 guards run and block, subject to tenant `policy_mode` as usual. |

**Revised 2026-07-19 (was: default to `monitor`).** `monitor` is not
side-effect-free, so defaulting to it is not safe for running production:

- `sensitive_action_confirmation.py:59` writes the token to Redis *before*
  returning `pending_confirmation`, so every sensitive call in monitor mints a
  token nobody redeems (bounded by the 300 s TTL, but a real hot-path write).
- `tool_call_rate_limiting` calls `agentic_state.increment()`, so counters begin
  accumulating.
- `_record_metrics` emits guardrail names operators' dashboards have not seen,
  which can trip alerting rules that assume a fixed set.

None of those change an allow/deny outcome, but "your latency moved and new
alerts fired, though nothing was blocked" is still a customer incident. The only
default that cannot break anyone is the current one.

Accepted cost: the gap stays open unless an operator acts. Mitigate with a
startup log line when the MCP path is active and parity is `off`, which changes
no runtime behavior. If `monitor` is later made the default, it must first
suppress the token mint.

Backward-compat rules:
- `"1"`, `"true"`, `"yes"` continue to parse as `enforce` so any operator who
  already opted in keeps their behavior. `"0"`, `"false"` parse as `off`.
- In `monitor`, the added guards are filtered out of the `allowed` computation at
  `enforcement.py:166-169` before `policy_mode.apply()`. This is deliberately
  independent of tenant `policy_mode`: a tenant already in `enforce` mode must not
  start blocking on guards they have never run.
- `pending_confirmation` is already handled in the `allowed` expression at line 167,
  so no change is needed there for `enforce`.

**Migration note** (ships with Task 3, `docs/`): set `monitor`, read `would_block`
counts per tool from the metrics `_record_metrics` already records, add
legitimate high-volume tools to allowlists or rate-limit exemptions, then set
`enforce`. Both steps are operator-initiated; no default changes.

**Two caveats that must appear in any release note.** `enforce` may be inert for
some deployments for reasons unrelated to this flag:

1. The lite/small-team gateway never calls `load_config()`
   (`core/mcp/gateway_lite.py::main`), so `apply_rbac` at `core/mcp/lite.py:114`
   creates a bare `ShieldConfig` and every settings-driven guard resolves to
   `{}` — `require_confirmation` is empty there regardless of the flag.
   Reproduced; tracked separately.
2. `ToolCallValidationGuardrail` fails **open** when its LLM is unreachable
   (observed: "LLM payload risk evaluation error … All connection attempts
   failed", call proceeded).

So the honest claim is "Task 3 enables HITL on the main data plane, where config
is loaded", not "Task 3 enables HITL".

**Malicious caller.** Cannot self-approve: the token is minted server-side into
Redis under an authenticated `session_id` and burned on use
(`sensitive_action_confirmation.py:48`). Cannot suppress a guard: `_meta` supplies
only `workflow` and `confirmation_token`, both fail-closed if absent or wrong.
Cannot widen a rate-limit window by forging a session, because `session_id` comes
from the signed token.

**Known weakness, documented not fixed here:** this guard-chain confirmation is
weaker than the Ed25519 approval grants in `core/approvals.py`, which bind
tool+resource+`params_hash`+instance and are non-replayable. Wiring the MCP path
to the real approval gate is the follow-up spec; this spec closes the parity gap
without pretending to deliver grant-strength HITL.

## 6. Packaging & deploy

- **New pip deps:** none. All three guards are already imported by the REST path.
- **`Dockerfile.admin`:** no change. Data plane only, no new `admin_app.py` import.
- **`requirements*.txt`:** no change.
- **Env flags:** `SHIELD_MCP_TOOL_PARITY` gains `monitor`/`enforce`/`off` values;
  legacy truthy/falsy values keep working.
- **Images to rebuild:** data plane only.
- **Rollout:** deploy on default (`monitor`), observe `would_block` for one release,
  then set `SHIELD_MCP_TOOL_PARITY=enforce` per tenant readiness.

## 7. Failure modes & edge cases

| Case | Behavior | Open / closed |
|---|---|---|
| `session_id` absent from token claims | Confirmation + per-session rate limits skip. Log a WARN once per session, and surface `session_unavailable` in `results[]` so it is visible rather than silent. | Fail-open, deliberate: matches today, and a hard block would break every legacy token. Called out as a known limitation. |
| Redis down | `agentic_state` ops raise or return None. Confirmation cannot mint a token. | **Fail-closed in `enforce`** for tools in `require_confirmation`; unavailable approval must not mean automatic approval. Rate limiting fails open (matches REST). |
| Confirmation token expired | Existing path: `passed=False`, "expired or invalid" (line 39-42). Client re-requests and gets a fresh token. | Closed |
| Token replayed | Key deleted on use (line 48), so second use hits the expired branch. | Closed |
| Token for a different tool | Rejected at line 43-46. | Closed |
| `_meta` absent, malformed, or not a dict | Treated as no token and no workflow. | Closed |
| Tool not in `require_confirmation` | Returns at line 27-29 before any Redis op. Zero added latency. | n/a |
| `default_policy: deny` in `tool_use_control` | Would deny every MCP tool with no matching rule. Default is `allow` (`config/default.yaml:269`), so unchanged out of the box, but the migration note must flag it for tenants who set `deny`. | Closed |
| Concurrent identical calls | Two calls mint two tokens under distinct keys; each burns once. No lost-update. | n/a |
| Legacy `SHIELD_MCP_TOOL_PARITY=1` | Parses to `enforce`. | Preserved |

## 8. Test plan (Definition of Done)

Extends `tests/test_mcp_tool_parity.py`; new file `tests/test_mcp_confirmation.py`.

**Flag parsing**
- `off` / unset-legacy-`0` yields the 4-guard base set
- `monitor` (and unset) yields all 7
- `enforce`, `1`, `true`, `yes` all yield all 7 and block

**Monitor semantics (the non-breaking guarantee)**
- In `monitor`, a call that the 3 added guards would block returns `allowed=True`
  and names them in `would_block`
- Same, for a tenant whose `policy_mode` is `enforce` — proves the added guards
  are independent of tenant mode
- In `monitor`, a base-chain block still blocks (no regression)

**Confirmation flow**
- `enforce` + sensitive tool + no token yields `pending_confirmation` and a token
  in the error `data`
- Replaying with that token succeeds
- Replaying twice fails the second time (burn)
- Token for tool A rejected on tool B
- Expired token rejected

**Session integrity**
- `session_id` is read from token claims
- A caller-supplied `Mcp-Session-Id` header cannot override the claim
- Missing `session_id` surfaces `session_unavailable` rather than silently passing

**Failure modes**
- Redis unavailable + `enforce` + sensitive tool blocks (fail-closed)
- Malformed `_meta` (string, null, list) does not raise

**Regression guards**
- Existing `test_parity_chain_covers_rest_guard_set` still passes
- New: assert `SensitiveActionConfirmationGuardrail` actually *fires* under parity,
  not merely that it is present in the chain. This is the test whose absence let
  the inert-guard bug through.

**Latency**
- Benchmark asserting the 7-guard chain adds < 5 ms p50 over the 4-guard chain
  with a stubbed LLM in `ToolCallValidation`

**Gates:** full suite green in a clean venv
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`);
CI `pytest` gate passes.

## 9. Task breakdown (one PR each, in order)

| # | Task | Status | Why separate |
|---|---|---|---|
| 1 | Plumb `session_id` from the verified agent-token claim into the MCP guard context; add `session_unavailable` surfacing; fix `http_enforcer.py:103` hardcoded `""` | **Done** (`2950bd4`) | Pure plumbing. Behaviorally inert while parity is `off`, so it lands with near-zero risk and makes every later task testable. |
| 2 | `_meta` transport for `confirmation_token` + `workflow`; shape the JSON-RPC error on `pending_confirmation` | **Done** (`5fab0d6`) | Protocol surface. Reviewable on its own; still inert while parity is `off`. |
| 2a | Freeze the parity-off path as a compatibility contract | **Done** (`e0dbf79`) | Added in response to the production-safety requirement. Converts "verified once" into "CI fails if anyone breaks it". Mutation-checked. |
| 3 | Three-state flag (`off` default), monitor-filtering in the `allowed` computation, startup warning, migration note | Not started | The only behavior-changing PR. Small and isolated because 1 and 2 landed first. |
| 4 | Latency benchmark | Not started | Proves the hot-path claim in §2 with numbers rather than reasoning. |

`workflow` moved from Task 1 to Task 2: it shares the `_meta` transport with the
confirmation token, so plumbing it in Task 1 would have added an always-`None`
parameter with no source.

Task 1 was the highest-value single PR: without it, `SHIELD_MCP_TOOL_PARITY=1`
gave operators a false belief that HITL was active on the MCP path.
