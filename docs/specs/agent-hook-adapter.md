---
title: "Spec: Coding-agent hook adapter"
layout: default
nav_exclude: true
permalink: /specs/agent-hook-adapter/
description: Make Claude Code on employee laptops ask Shield before every command, file write and fetch, so the agent's runtime profile (for example "no file encryption", "no writes outside the project") is enforced there too, deployed by MDM with nothing to install.
---

# Spec: Coding-agent hook adapter

> Status: **APPROVED 2026-10-03** (user: "approved"); revision 2 (task 0
> findings, threat coverage matrix, starter profile, session limits, `ask`)
> approved 2026-10-03 (user: "approved, start task 1"). Task 0 done (one
> check left for the user, see section 9). Tasks 1 to 4 built; their live
> check findings are folded into sections 4.1, 4.3, 7, 9 and 10.
> Customer guide: `docs/claude-code-runtime-guardrails.md`.
> Builds on: `docs/specs/infra-guardrails.md` (runtime profiles,
> `/v1/shield/runtime/check`, shipped in #444).
> Claude Code behaviour below was checked against its documentation on
> 2026-10-03 (`code.claude.com/docs/en/hooks`, `/settings`,
> `/managed-settings`) and then against Claude Code 2.1.104 itself in task 0
> (section 9).

## 1. Problem & outcome

Runtime profiles say what an agent may run, write and reach: for example, deny
`openssl enc`, `gpg -c`, `zip -e`; write only inside the project; reach only
named hosts. They are enforced in OpenShell sandboxes and on MCP tool calls.
A coding agent on a laptop (Claude Code) runs commands and edits files
directly, so nothing checks it.

Claude Code has **PreToolUse hooks**: before every tool call it can ask an
external program or URL, which can deny the call with a reason the agent sees.
Organisations can deploy hooks as **managed settings** that users cannot
override, by file or by MDM profile.

**Outcome**

1. An admin assigns a runtime profile to a "Claude Code" agent in the portal.
2. Laptops get one MDM profile (or file) that points Claude Code's hooks at
   Shield. Nothing is installed.
3. Before Claude Code runs a command, writes or edits a file, or fetches a
   URL, Shield checks it against that profile. A denied call does not run, and
   Claude Code is told why ("command matches denied pattern 'openssl enc*'").
4. Every decision is in the tenant's audit log with the user, the device, the
   session and the reason.

**Non-goals (v1)**

- Other agents (Cursor, Codex, Gemini CLI). Their hook formats differ; the
  route is built so a second format is one more mapping.
- Stopping a determined user. A user who runs commands themselves, outside
  Claude Code, is not covered. This governs the agent.
- Inspecting file contents or command output (PostToolUse). v1 decides before
  the call.
- Approvals (asking a human). v1 allows or denies. Claude Code's own `ask` is a
  later option.

## 2. Plane & latency contract

- **Data plane.** One new route, `POST /v1/shield/hooks/claude-code`.
- **It is a decision path** for the agent, like `/v1/shield/runtime/check`,
  which it reuses. The check is deterministic: the compiled profile is cached,
  with no model call. Budget: **under 20 ms server-side at p95**, plus the
  network round trip. Claude Code waits for it before every matched tool
  call, so the hook timeout is set to **5 seconds**.
- `/guardrails/*`, `cap/mint` and `tools/call` are not touched.
- The audit row is written in the background, after the answer.

## 3. Data model

None new. It uses the existing runtime profiles and the agent registry: the
admin registers an agent (for example `claude-code`) and assigns it a profile,
as for any other agent today. Decisions go to the existing audit log and
runtime events (`kind` exec, file or network; `decision` allow or deny).

## 4. API / interface

### 4.1 The route

`POST /v1/shield/hooks/claude-code`, tenant key in `X-API-Key`, agent in
`X-Agent-Key`, optional `X-Shield-User` and `X-Device-Id`.

**Request:** Claude Code's PreToolUse input, unchanged. Seen in task 0:
`session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`,
`tool_name`, `tool_input`, `tool_use_id`. Unknown fields are ignored.
`permission_mode` goes into the audit row: a deny holds even in
`bypassPermissions` mode (verified).

**Paths.**

- Claude Code already makes a relative `file_path` absolute against `cwd`
  before calling the hook (verified). Shield still resolves `~`, `.` and `..`
  lexically, as `/runtime/check` does.
- **Home.** Only the user's own home becomes `~`. Claude Code's
  `transcript_path` (`<home>/.claude/projects/...`) names it, so
  `/Users/Shared/x` stays `/Users/Shared/x` and another user's
  `/Users/other/proj` does not match `~/proj` (found in the task 1 live
  check). Without a `transcript_path`, any `/Users/<name>` or `/home/<name>`
  becomes `~`, as in a sandbox.
- `cwd` arrives as the real path (`/private/tmp/...` on macOS), while a path
  the model typed keeps its alias (`/tmp/...`). Shield rewrites the macOS
  aliases `/tmp`, `/var` and `/etc` to `/private/...` in both before
  comparing, so a rule cannot be dodged by spelling. Other symlinks are not
  resolved, because Shield does not see the laptop's disk.
- **`@project`** in a profile's `filesystem` paths means the session's `cwd`.
  A laptop has no fixed work directory, so "write only inside the project" is
  `read_write: ["@project"]`.
- Reads (`Read`, `Glob`, `Grep`) are checked against `filesystem.deny` only.
  A coding agent reads widely (system headers, other repos), so reads are
  limited by naming what is off-limits, not what is allowed.

**What is checked:**

| `tool_name` | Checked as | From |
|---|---|---|
| `Bash` | a command (`exec`) | `tool_input.command` |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | a file write | `tool_input.file_path` (or `notebook_path`), made absolute against `cwd` |
| `Read`, `Glob`, `Grep` | a file read | the path argument, against `cwd` |
| `WebFetch` | a network request | `tool_input.url`, `method` |
| `mcp__*` | the tool call, as `/v1/shield/tool/check` does | `tool_name`, `tool_input` |
| anything else | allowed, not checked | |

**Response (always HTTP 200 for a decision):**

- Denied:
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Blocked by Votal Shield: <reason>"}}`
- Allowed: `{}`. Shield does not grant permission; Claude Code's own
  permission prompts still apply.

### 4.2 Deployment: managed settings, nothing installed

The hook is an **HTTP hook**, so laptops need no script or binary. One
managed setting, delivered either way:

- **MDM:** a configuration profile for the `com.anthropic.claudecode`
  preference domain (Jamf, Kandji, Intune for Mac).
- **File:** `/Library/Application Support/ClaudeCode/managed-settings.json`
  (macOS), `/etc/claude-code/managed-settings.json` (Linux),
  `C:\Program Files\ClaudeCode\managed-settings.json` (Windows).

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*",
      "hooks": [{
        "type": "http",
        "url": "https://api.guardrails.votal.ai/v1/shield/hooks/claude-code",
        "headers": {"X-API-Key": "<tenant key>", "X-Agent-Key": "claude-code",
                    "X-Shield-User": "$USER"},
        "allowedEnvVars": ["USER"],
        "timeout": 5
      }]
    }]
  },
  "allowManagedHooksOnly": true
}
```

The portal's Runtime Profiles page gets a "Claude Code" panel that shows this
file filled in for the tenant, and a downloadable `.mobileconfig`.

### 4.3 Fail-closed option: a command hook

Claude Code does **not** block a tool call when an HTTP hook fails or times
out: the call continues (verified for a timeout and for an HTTP 500). If
Shield is unreachable, an HTTP hook enforces nothing. For organisations that
need the opposite, v1 also ships a small **command hook** that calls the same
route and **exits 2 (deny) when Shield cannot be reached or answers with an
error** (verified: unreachable and 500 both denied, with the reason shown to
the agent). It must be installed on the laptop (by MDM or the device agent),
so it is the second option, not the default.

Task 0 found a trap: **a command hook that exits with any code other than 2
lets the call through.** A script that crashed on a missing argument (exit 1)
did not block. So the hook:

- is a POSIX `sh` script using `curl` (`core/runtime_policy/hook_scripts/claude_code_hook.sh`),
  plus a PowerShell twin for Windows. Not Python: on a Mac without developer
  tools, `python3` is a stub that fails, which would fail open;
- treats every failure as exit 2: no URL or key configured, `curl` missing,
  timeout, any non-200, or a body that is not JSON;
- reads its URL and key from its own config file
  (`/Library/Application Support/Votal/hook.conf` and the Linux and Windows
  equivalents), written by the same MDM profile, not from the environment.
  The file is parsed, never sourced. `--config <path>` may be fixed by the
  admin in the managed setting;
- sends the key through a private headers file (`curl -H @file`), so it is
  not in the process list;
- passes a deny on as exit 2 with the reason on stderr (no JSON to get
  wrong), and an `ask` as JSON it builds itself, with the reason stripped of
  quotes, backslashes and control characters.

Two deployment rules, both found in the task 2 live check:

- **The managed command ends in `|| exit 2`**
  (`/bin/sh '/Library/Application Support/Votal/claude_code_hook.sh' || exit 2`).
  Without it, a missing or unrunnable script exits 127 and the call goes
  through.
- **`SHIELD_TIMEOUT` stays below the hook's `timeout`** (defaults 4 and 10
  seconds). When Claude Code's own timeout stops the hook first, the call
  goes through.

## 5. Security & backward compatibility

- **Opt-in.** Nothing changes until an organisation deploys the managed
  setting. The route is new.
- **Tenant from the key only.** Nothing in the hook body selects a tenant.
- **The tenant key is readable on the laptop** (managed settings are readable
  by the user). Use a key made for this, with the `runtime` scope; with
  `SHIELD_REGISTRY_WRITE_SCOPE=enforce` such a key cannot change policies or
  the registry.
- **The user identity is self-reported** (`$USER`). It is for attribution,
  not authorization. The profile is per agent, not per user.
- **What this does not stop** (stated in the docs, not hidden):
  - commands the user runs outside Claude Code;
  - an agent that writes its own program to do what a denied command did (for
    example encrypting with a Python script instead of `openssl`). A deny list
    of commands is a speed bump. The real controls are the profile's write
    paths (`filesystem.read_write`) and network allowlist, which this adapter
    also enforces;
  - with HTTP hooks, anything while Shield is unreachable (section 4.3).
- **`disableAllHooks`.** Task 0 confirmed that a `--settings` flag with
  `disableAllHooks: true` switches off project hooks. Whether a user,
  project or flag setting can switch off a **managed** hook needs a
  root-owned managed file, so the user runs that check (section 9). If it
  can, the customer guide says so and tells admins to deploy the
  fail-closed command hook through MDM and watch for sessions that stop
  sending hook calls (the portal shows "last hook call" per device).
- **The agent must not edit its own hook.** The starter profile (section 10)
  denies writes to Claude Code's settings files (`~/.claude/settings*.json`,
  `@project/.claude/settings*.json`) and to the hook's config file.

## 6. Packaging & deploy

- New module `api/routes_hooks.py` (data plane only; not imported by
  `admin_app.py`). No new dependency.
- `core/runtime_policy/hook_scripts/claude_code_hook.sh` and `.ps1` (under
  `core/` so every image ships them for the portal's rollout files;
  `.dockerignore` drops `examples/`), documented in `examples/runtime/README.md`.
- `core/runtime_policy/templates/coding_agent_baseline.json` (the starter
  profile); `limits` added to the profile model.
- Portal: the Claude Code panel on Runtime Profiles (admin plane;
  `static/tenant.html` only).
- Docs: `docs/claude-code-runtime-guardrails.md` (customer guide).

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Agent has no runtime profile | `{}`: allowed, as `/runtime/check` does today. The audit row says "no profile" |
| Missing or invalid tenant key | 401. An HTTP hook then lets the call through (Claude Code's rule); the command hook denies it |
| Relative or `~` paths | Made absolute against `cwd` before checking; `..` is resolved |
| `/tmp/x` against a `cwd` of `/private/tmp/...` | Aliases rewritten first, so both compare as `/private/tmp/...` |
| Command hook crashes or exits non-2 | Would fail open, so the script maps every failure to exit 2 (section 4.3) |
| A compound command (`a && b`, pipes) | Each segment is checked, as the runtime check already does |
| Very long command or input | Capped as `/runtime/check` caps (8 KB); longer is denied as unparseable |
| A command with 256 or more parts (`;`, `&&`, `\|`, newlines) | Denied as not checked: checking it would cost more than the latency budget, and no agent needs it (an 8 KB command of 4,096 parts took 16 ms) |
| Unknown tool | Allowed, not checked, and recorded |
| Shield slow | The hook times out after 5 s; HTTP hook: the call proceeds; command hook: denied |

## 8. Test plan (Definition of Done)

- Every tool in the table maps to the right check and value, including
  relative paths, `~`, `..`, compound commands and MCP tools.
- Deny returns exactly Claude Code's documented JSON; allow returns `{}`.
- No profile, no key, wrong tenant, device-key refusal.
- Audit rows and runtime events carry user, device, session and reason; no
  file contents.
- The command hook: deny on Shield's deny, deny on unreachable (exit 2), allow
  on `{}`; deny on every other failure (no config, non-200, bad JSON); no
  dependency beyond `sh` and `curl`.
- Portal panel renders the managed settings for the tenant.
- Full suite green in a clean venv; CI `pytest` gate passes.
- **Live check (task 0 and after task 1):** a real Claude Code session with
  the hook pointed at a local Shield: an encryption command and a write
  outside the project are denied with the reason shown in Claude Code; normal
  work is unaffected.

## 9. Task 0 results (2026-10-03, Claude Code 2.1.104, macOS)

Method: a real Claude Code, with its model replaced by a local scripted
Messages API that returns one fixed, harmless tool call per scenario, and a
local stand-in for the Shield route that logs every hook call and denies by
marker. The scripted API also records the tool result, which is exactly what
the agent sees.

| Check | Result |
|---|---|
| PreToolUse body | Fields as in section 4.1; Bash sends the whole command string; Write sends an absolute `file_path` |
| HTTP hook deny | Call not run; the agent sees `Blocked by Votal Shield: <reason>` as an error result |
| Deny in `bypassPermissions` mode | Still denied |
| Write outside the project | Denied; file not created |
| Normal command and in-project write | Allowed; Claude Code's own result unchanged |
| HTTP hook times out (6 s against a 3 s timeout) | **Call runs** (fail open) |
| HTTP hook gets a 500 | **Call runs** (fail open) |
| Command hook, Shield denies | Denied, reason shown |
| Command hook, Shield unreachable or 500, exit 2 | Denied, the script's stderr shown to the agent |
| Command hook crashes (exit 1) | **Call runs** (fail open), hence section 4.3 |
| `--settings '{"disableAllHooks": true}'` | Project hook off |
| User, project or flag `disableAllHooks` against a **managed** hook | **Open:** needs `sudo`; the user runs `test_managed.sh` |
| Task 2: shell hook, Shield denies, asks or allows | Denied with the reason; `ask` shown; allowed call unchanged |
| Task 2: shell hook, Shield unreachable | Denied |
| Task 2: managed command points at a missing script, with `\|\| exit 2` | Denied |
| Task 2: the same, without `\|\| exit 2` | **Call runs** (exit 127), hence the first rule in section 4.3 |
| Task 2: hook `timeout` 2 s, Shield answers after 6 s | **Call runs**, hence the second rule in section 4.3 |

**Task 1 live check (same method, real route).** A local Shield (in-memory
store) with a laptop profile assigned to `claude-code`, and the hook pointed
at `/v1/shield/hooks/claude-code`. Denied, with the reason shown to the agent
and nothing written: `openssl enc` on a project file, a Write to
`/Users/Shared`, a Read under `~/.ssh`, a Write to the project's
`.claude/settings.local.json`. Allowed and unchanged: an `echo` into the
project, a Write in the project, a WebFetch to an allowed host. `git push`
(an `ask_commands` entry) did not run in `-p` mode. The run found the home
directory bug fixed in section 4.1.

## 10. Threat coverage and the starter profile

What an admin can block from Shield settings, by ATT&CK technique. "Enforced"
means the hook denies it before it runs. "Partial" means the hook catches the
usual commands, but an agent can do the same thing another way (for example
in a script it writes), so the profile's write paths and network allowlist
are the real limit. "Out of scope" means the hook cannot see it; the device
agent or the secure web gateway covers it.

| Technique | Hook control (profile field) | Coverage |
|---|---|---|
| T1486 Data encrypted for impact | Deny encryption and archive-with-password commands (`process.deny_commands`); writes only in `@project` (`filesystem.read_write`) | Commands: enforced. In-script encryption: partial (limited to the project by write paths) |
| T1490 Inhibit system recovery | Deny snapshot, backup and restore-point deletion commands | Enforced for commands |
| T1485 Data destruction | Deny recursive deletes outside `@project` and disk-wipe tools; Write and Edit outside `@project` denied | Enforced for tools and commands; partial for scripts |
| T1562 / T1070 Impair defenses, indicator removal | Deny commands that stop security agents or clear logs and shell history; deny writes to Claude Code settings and the hook config | Enforced for commands and writes |
| T1552 / T1555 Credentials in files and stores | `filesystem.deny` for `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.env` files, browser profiles; deny keychain query commands | Read, Grep, Glob: enforced. Bash `cat` of those paths: enforced by path match in the command. Scripts: partial |
| T1021 Remote services (lateral movement) | Deny remote shell and remote copy commands unless listed in `allow_binaries` | Enforced for commands |
| T1219 Remote access tools | Deny installing or launching remote-access tools; deny piping downloads into a shell | Partial: catches the usual commands |
| T1041 / T1567 Exfiltration | `network.allow` for WebFetch and for hosts named in `curl` and `wget` commands; MCP tools through the tool check | WebFetch and MCP: enforced. Commands: partial. Any other process: out of scope (device agent and SWG) |

**Starter profile.** The portal's Runtime Profiles page gets a built-in
template, **"Coding agent: baseline"**, that fills in the rows above: writes
only in `@project`, the credential paths in `filesystem.deny`, the
destructive and evasion command patterns in `process.deny_commands`, and an
empty `allow_binaries` (any binary not denied may run). The admin copies it,
edits it, and assigns it to the `claude-code` agent. It is a template, not a
default: nothing is enforced until it is assigned (section 5, opt-in). The
exact pattern list lives in `TEMPLATES["coding-agent-baseline"]` in
`core/runtime_policy/model.py` (not a separate JSON file: the admin image
imports the model, and a data file would need its own `Dockerfile.admin`
line), reviewed in the task 3 PR, not in this spec.

**Session limits.** A profile may set `limits.max_writes_per_minute` and
`limits.max_deletes_per_session` for hook sessions (keyed by a hash of
`session_id`). A session over a limit has further writes (until the next
minute) or deletes (for the rest of the session, 24 hours from its first
delete) denied with "too many file changes in this session", which catches
mass modification however it is done through Claude Code's tools. Off unless
set; stored only when set, so existing profiles keep their hash; every
export lists them as enforced by the hook checks only.

- **What counts** (`hooks.file_changes`, per call, never per file): a
  Write, Edit, MultiEdit or NotebookEdit; in Bash, each redirect into a file
  and each `cp`, `mv`, `tee`, `touch`, `install`, `ln`, `rsync`, `dd` or
  `truncate` segment as a write, and each `rm`, `rmdir`, `unlink`, `shred`,
  `find -delete` or `find -exec rm`, `git rm` or `git clean` segment as a
  delete, also behind `sudo`, `xargs` or `env`; MCP tools by name.
- **Cost:** one `INCRBY` (plus `EXPIRE` for a new window) per counted call,
  off the event loop, only under a profile with limits. Calls the profile
  denies do not count; calls over a limit do.
- **Store down:** the limit is not applied, unless the profile sets
  `fail_closed`.

**`ask`.** A profile may list `process.ask_commands` (same pattern syntax as
`deny_commands`; checked only after nothing denied the call). Shield then
returns `permissionDecision: "ask"`, and Claude Code asks the person at the
laptop to confirm. This is a local confirmation, not an admin approval; admin
approvals on the hook path are a later spec. `ask_commands` is stored only
when set, so existing profiles keep their hash and no sandbox sees drift.
Verified in task 1: in a non-interactive session (`-p`) with
`bypassPermissions`, there is no one to ask, so the call does not run and
the agent sees the reason, as for a deny.

## Tasks

0. **Verify Claude Code's behaviour.** Done, see section 9; the managed-hook
   override check is the user's to run.
1. **The route** (built): mapping, path normalization (`@project`, macOS aliases),
   decision via the existing runtime check, `ask`, response format, audit and
   runtime events, tests.
2. **The command hook** (built): `sh` + `curl`, PowerShell twin, every
   failure mapped to exit 2, with tests under `sh` and `dash`. The
   PowerShell hook is held to the same contract by a test that reads it,
   and runs in CI only where `pwsh` is installed; it has not yet run on a
   Windows laptop.
3. **Deployment and starter profile** (built): the "Claude Code on laptops"
   card on Runtime Profiles builds the rollout files from
   `core/runtime_policy/hook_kit.py` (`POST /v1/tenant/me/hooks/claude-code/kit`,
   both planes; the key is used and not stored): managed settings, a
   `.mobileconfig`, a root install script for macOS and Linux that never
   overwrites managed settings it did not write, and, for the fail-closed
   variant, `hook.conf` and the hook. It lists each laptop's latest hook call
   (`core/runtime_policy/hook_seen.py`, written after the answer, at most once
   a minute per laptop unless the decision changes). The
   `coding-agent-baseline` template, and the customer guide with the coverage
   matrix. The `.mobileconfig` payload (`com.anthropic.claudecode`) has not
   been installed on a Mac yet; the guide says to try it on one first.
4. **Session limits** (built): `limits.max_writes_per_minute` and
   `limits.max_deletes_per_session` on the hook path
   (`core/runtime_policy/hook_limits.py`), with tests. Live check: one real
   Claude Code session writing five files under a limit of three a minute
   wrote three; the fourth and fifth were denied with the reason shown.
