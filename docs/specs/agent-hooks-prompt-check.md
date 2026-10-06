# Spec: prompt check for coding agents (UserPromptSubmit)

Status: DRAFT, awaiting approval. Extends
[agent-hooks-tool-policies.md](agent-hooks-tool-policies.md) (PRs #470, #471).

## 1. Problem and outcome

Today Shield judges a coding agent one tool call at a time. A request such as
"encrypt ~/Downloads/a.txt" is refused only when a command matches a pattern
or the Tool calls rule catches the call, and the agent can try one tool after
another (seen live on 2026-10-05: Bash blocked, then the Terminal panel tool
ran `openssl enc`). The request itself is never judged.

**Outcome.** Before the agent sees a prompt, Claude Code and Codex send it to
Shield (`UserPromptSubmit` hook). Shield runs the tenant's **input custom
policies** (the natural-language and Sigma policies on the I/O Guardrails
page, stage `input`), and optionally other input guards, on the prompt.

- A prompt a policy blocks is **refused before the agent runs**: the user sees
  "Blocked by Votal Shield: <policy name>: <reason>", the prompt never reaches
  the model, and no tool is tried.
- A `warn` lets the prompt through and adds a short note to the agent's context
  naming the policy (Claude Code only; see section 4.3).
- Every decision is a runtime event with the policy names, never the prompt.

**Observable success.**
- With an input custom policy "Block requests to encrypt, password-protect or
  lock files", the prompt "encrypt file ~/Downloads/a.txt" in a Claude Code
  session with the hooks gets "Blocked by Votal Shield: ..." and no tool call
  happens. "Explain how TLS works" passes.
- The same in Codex.
- The console's runtime events show a `dlp` event with verdict `block`, the
  policy name, `prompt_sha256` and `prompt_len`, no prompt text.

**Non-goals.**
- Rewriting the prompt (Claude Code and Codex cannot replace a submitted
  prompt; a hook can only block it or add context).
- Conversation history. The hook gets `transcript_path`, a file on the
  laptop; the server sees only the prompt. Multi-turn custom policies judge
  this prompt alone.
- Exception requests for blocked prompts (the existing prompt-exception flow
  can be wired in later).
- Cowork and chat (no hooks there; see the agent-hooks spec section on
  surfaces).
- Scoping custom policies to "coding agents only" inside the custom-policy
  model. This spec selects policies per agent profile instead (section 3).

## 2. Plane and latency contract

- **Plane:** data plane only (`core/app.py`): the existing hook routes
  `POST /v1/shield/hooks/claude-code` and `/codex` (`api/routes_hooks.py`).
  No admin-plane module changes; the profile validator in
  `core/runtime_policy/model.py` already ships in both images.
- **Guard path:** not touched. `/guardrails/*`, `cap/mint` and `tools/call`
  are unchanged. The hook route calls the same in-process pipeline function
  `/guardrails/input` uses (`core/tenant_pipeline.run_tenant_pipeline`,
  `stage="input"`, `mode=REPLACE`), so it adds no latency to guarded traffic.
- **Latency the user feels:** every prompt waits for the check before the
  agent starts. Natural-language custom policies are LLM calls (`tier="slow"`,
  one call per policy, run concurrently); Sigma policies are deterministic.
  Expect about the same as one `/guardrails/input` call with those policies
  (measured in task 0). Bounded by `check_timeout_s` (default 20 s) and the
  hook's own timeout (30 s in the example settings).

## 3. Data model

No new Redis keys. Everything is read from what exists:

| Read | Key | Notes |
|---|---|---|
| Agent profile | runtime profile, as today | new keys below |
| Input custom policies | `tenant:{tenant_id}` record, `input_guardrails.custom_policy_input.settings.policies[]` | stage `input`, enabled only |
| Other input guards (optional) | `tenant:{tenant_id}` record, `input_guardrails.*` | only if the profile lists them |
| Tenant policy mode | tenant record `policy_mode` | `monitor` downgrades blocks, as on `/guardrails/input` |

**Profile keys** (in the existing `tool_policies` block, validated like its
other keys; absent = today's behaviour, so existing profiles keep their hash):

```json
"tool_policies": {
  "before_prompt": true,
  "prompt_guards": ["custom_policy_input"],
  "prompt_policy_ids": []
}
```

- `before_prompt` (bool, default `false`): turn the prompt check on.
- `prompt_guards` (list of input guard names, default
  `["custom_policy_input"]`, at most 20): which of the tenant's input guards
  run on prompts. `"*"` means every enabled input guard (prompt injection, PII,
  and so on). The default is custom policies only, because coding prompts
  routinely contain logs, emails and code that general guards flag.
- `prompt_policy_ids` (list of custom policy ids, default empty = all enabled
  input policies, at most 50): run only these custom policies on prompts, so a
  policy written for coding agents ("no file encryption") need not apply to the
  tenant's chat apps, and the reverse.
- `check_timeout_s` (existing) also bounds the prompt check.

**Tenant scoping.** The tenant comes from the caller exactly as for tool
calls: the tenant key (`X-API-Key`, resolved by `AuthMiddleware`) or the
device key's record. The pipeline is given only that tenant's guard config;
a key for tenant A cannot run tenant B's policies.

## 4. API and interface

### 4.1 Request (unchanged routes)

`POST /v1/shield/hooks/claude-code` and `/codex`, body = the agent's
`UserPromptSubmit` hook input. Fields used:

| Field | Claude Code | Codex |
|---|---|---|
| `hook_event_name` | `"UserPromptSubmit"` | `"UserPromptSubmit"` |
| `prompt` | the submitted text | the submitted text |
| `session_id`, `cwd` | yes | yes (`turn_id` extra, ignored) |

Headers as today (`X-API-Key`, `X-Agent-Key`, `X-Shield-User`,
`X-Device-Id`, or a device key). Body limit stays 4 MiB; prompts longer than
`max_output_chars` (default 200,000) are not sent to the model (section 7).

### 4.2 Dispatch

`_handle` gains one branch: `UserPromptSubmit` goes to `_user_prompt_submit`.
Unknown events still return `{}`.

### 4.3 Responses

| Shield decision | Claude Code | Codex |
|---|---|---|
| allow / log / pass | `{}` | `{}` |
| warn | `{"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": "Votal Shield: this request falls under your organization's policy '<name>'. Follow that policy."}}` | `{}` (task 0 checks whether Codex accepts additionalContext here; if it does, same as Claude Code) |
| block | `{"decision": "block", "reason": "Blocked by Votal Shield: <policy name>: <reason>"}` | same |
| redact (custom policy label) | treated as **block**, reason "remove the sensitive data and send it again" (a prompt cannot be rewritten) | same |
| tenant or fleet in monitor mode | `{}`; the event records what enforce would have done | same |

`<reason>` is the policy's own name plus the guard's message, passed through
`hook_policies.scrub` against the prompt so no token of 8 or more characters
from the prompt is echoed. At most 300 characters.

### 4.4 The command script (`claude_code_hook.sh` / `.ps1`)

- Detects `"hook_event_name":"UserPromptSubmit"` like it detects PostToolUse.
- Passes through `{}`, an answer with `"decision":"block"`, or one with
  `additionalContext`.
- On a failure (no answer, bad answer, timeout) it follows a new config line
  `ON_UNREACHABLE_PROMPT=allow|block` (default **allow**: blocking every prompt
  during an outage stops all work; tool calls stay fail-closed before a call).
  `block` prints `{"decision":"block","reason":"Votal Shield could not check this request"}`.

### 4.5 Settings files and plugin

`UserPromptSubmit` has no matcher in either agent. Added to
`examples/agent-hooks/claude-settings.json`, `claude-settings-fail-closed.json`,
`codex-hooks.json` and the plugin's `hooks/hooks.json`, plus the device agent's
embedded copies via `sync_hook_scripts.py`.

## 5. Security and backward compatibility

- **Opt-in.** Nothing changes until a profile sets `before_prompt: true` and
  the settings file registers the hook. Existing profiles validate unchanged.
- **Escape hatch.** `SHIELD_HOOK_PROMPT_CHECK=0` turns the check off
  fleet-wide (the route answers `{}` for `UserPromptSubmit`).
- **No prompt text is stored.** Unlike `/guardrails/input`, which writes up to
  500 characters to the audit log, this path records only `prompt_sha256` and
  `prompt_len` (the `dlp` event rules forbid `prompt`/`text`/`content` keys).
  Coding prompts often carry code and secrets. The optional rule-redacted
  `excerpt` is written only when the tenant turned on `privacy.capture_excerpt`.
- **Reasons never echo the prompt** (scrubbed, section 4.3).
- **What a malicious caller can do:** with a tenant key, run that tenant's
  input policies on text of their choice, the same as `/guardrails/input`
  allows today. No new capability. Each call costs model time; the route
  inherits the existing per-tenant rate limits.
- **What a user can do:** remove the hook from their own settings (as with any
  user-level hook). Managed settings or the plugin via org rollout prevent
  that; out of scope here.

## 6. Packaging and deploy

- No new modules on the admin plane; no new dependencies.
- Data plane: `api/routes_hooks.py`, `core/runtime_policy/hook_policies.py`,
  `core/runtime_policy/model.py` (shared, already in `Dockerfile.admin`).
- Scripts: `core/runtime_policy/hook_scripts/claude_code_hook.{sh,ps1}`,
  regenerated copies in the device agent and the plugin.
- Env flag: `SHIELD_HOOK_PROMPT_CHECK` (default on, only matters for profiles
  that opt in).
- Rebuild: data plane image. The portal needs no change to save the new
  profile keys once its build includes the validator change (the same
  `model.py`).

## 7. Failure modes and edge cases

| Case | Behaviour |
|---|---|
| Empty or whitespace prompt | allow, no model call |
| Prompt over `max_output_chars` | Sigma policies run; LLM policies skipped; event marks `unjudged`; follows the fail setting below |
| Pipeline error, guard error, or `check_timeout_s` exceeded | follows the Tool Registry policy's "If a check can't run" (`fail_closed`): block the prompt, or allow it marked `unjudged`. One switch for every hook check |
| A custom policy errors inside the guard | the guard's own rule (`SHIELD_CUSTOM_POLICY_FAIL_OPEN`), unchanged |
| No input custom policies, `prompt_guards` default | allow, no model call |
| `prompt_policy_ids` names a policy that no longer exists | ignored; if none remain, allow, no model call |
| Tenant config missing (device key path) | loaded via `tenant_store`; if unavailable, as a pipeline error above |
| Shield unreachable (script) | `ON_UNREACHABLE_PROMPT` (default allow) |
| Shield unreachable (Claude Code HTTP hook) | Claude Code lets the prompt through (HTTP hooks fail open) |
| The contextvar for custom policies not set | a missing `_request_configs` makes `custom_policy_input` pass silently (`tenant_pipeline.py` docstring). The check must go through `run_tenant_pipeline`, and a test proves a policy actually fires |
| Monitor (tenant `policy_mode` or fleet mode) | allow; event carries `would_block` |
| Codex `turn_id` | ignored |

## 8. Test plan (Definition of Done)

- **Core** (`tests/test_hook_prompt_check.py`): block, warn, pass, redact-as-block;
  only selected guards run; `prompt_policy_ids` filter; empty prompt; oversize
  prompt; timeout and error under both fail settings; monitor mode; reasons
  scrubbed of prompt tokens; a real `custom_policy_input` run (stubbed LLM)
  proving the policy list reaches the guard (the contextvar trap).
- **Route** (Claude Code and Codex): each response shape in 4.3 on the real
  app; the event is `dlp` with verdict, policy names, `prompt_sha256`,
  `prompt_len` and no prompt text; device key path; fleet `off` and `monitor`;
  `SHIELD_HOOK_PROMPT_CHECK=0`; a profile without `before_prompt` answers `{}`.
- **Validator:** new keys accepted, bounds enforced, unknown keys rejected,
  existing profiles' hashes unchanged.
- **Script:** run for real under sh and dash against a fake Shield: block and
  context passed through; failure under `ON_UNREACHABLE_PROMPT` allow and
  block; tool-call failure behaviour unchanged. PS1 checked by contract test.
- **Examples and plugin:** every settings file registers `UserPromptSubmit`;
  plugin copy identical; manifests validate.
- **Sabotage checks** on each safeguard (scrub, no prompt in events, block
  shape, fail setting).
- Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each)

0. **Live check** (no code): with Claude Code 2.1.104 and Codex 0.155,
   confirm the `UserPromptSubmit` input fields and that `decision: block`
   refuses the prompt with the reason shown; whether Codex applies
   `additionalContext` on this event; measure `/guardrails/input` latency on
   production with two natural-language input policies. Results recorded here.
1. **Core:** `hook_policies.check_prompt` (pipeline call, guard selection,
   decision mapping, scrub, fail setting) and the validator keys.
2. **Route:** `UserPromptSubmit` on both routes, responses, events, monitor
   modes, env flag.
3. **Scripts, settings files, plugin, README:** `UserPromptSubmit` everywhere,
   `ON_UNREACHABLE_PROMPT`, regenerated copies, end-to-end test steps.

## 9.1 Task 0 results (2026-10-06)

Run from the user's Terminal with a probe hook (records its input, answers a
fixed decision); no Shield code involved.

| Check | Result |
|---|---|
| Claude Code 2.1.289, `{"decision":"block","reason":...}` | **Verified.** Prompt refused before the model runs: "UserPromptSubmit operation blocked by hook: <reason>", then "Original prompt: ...". |
| Claude Code input fields | `cwd`, `hook_event_name`, `permission_mode`, `prompt`, `prompt_id`, `session_id`, `transcript_path`. `prompt_id` goes into the event detail. |
| Claude Code `additionalContext` (warn) | Not run (CLI sign-in expired). Documented as supported; checked in task 2's live test. |
| Codex 0.155.1, `codex exec` | **The hook never fired**, in a git repo, trusted project, `--dangerously-bypass-hook-trust`, hooks feature on (Codex accepted the flag: it warned that `codex_hooks` is deprecated in favour of `hooks`). Codex's docs list `UserPromptSubmit` with the same `decision: block` shape. Either `exec` mode does not emit it or project hooks are not loaded there. **Codex is unverified**: task 3 tests it in an interactive session with `~/.codex/hooks.json`; if it does not fire, the Codex half ships documented as unsupported, the route still answering correctly. |
| Production `/guardrails/input` latency, tenant `bankco` (4 natural-language input policies, 1 Sigma) | 2.7 to 7.5 s, usually 3 to 4.5 s per prompt. Matches section 2. |
| bankco input policies on "encrypt file ... with openssl", "zip ... with a password" | All passed: no policy covers encryption yet. Section 10 step 1 adds it. |

Amendment from task 0: the route records `prompt_id` (Claude Code) and
`turn_id` (Codex) in the event, to tie a blocked prompt to its session.

## 10. How you will test it

1. Console, I/O Guardrails, custom policies: add an **input** policy, action
   block: "Block requests to encrypt, password-protect, lock or ransom files,
   or to disable security tools."
2. Profile `coding-agents`: `"before_prompt": true` and that policy's id in
   `prompt_policy_ids`.
3. Settings: the `UserPromptSubmit` entry from the updated example (or the
   updated plugin).
4. New Claude Code session: "encrypt file ~/Downloads/a.txt" gets
   "Blocked by Votal Shield: ..." immediately, with no tool calls.
   "what does gpg --symmetric do?" passes (a question, not a request; the
   policy wording decides this).
5. The same in Codex.
6. Console runtime events: a `dlp` event, verdict `block`, the policy name,
   no prompt text.
