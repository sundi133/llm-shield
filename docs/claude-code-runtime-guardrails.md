---
title: Claude Code guardrails
layout: default
nav_order: 30
permalink: /claude-code-runtime-guardrails/
description: Make Claude Code on employee laptops ask Votal Shield before every command, file write and fetch, so a runtime profile (no file encryption, no writes outside the project, no credential reads) is enforced there too. Deployed by MDM, managed from the portal.
---

# Claude Code guardrails: admin guide
{: .no_toc }

Claude Code runs commands, edits files and fetches web pages on the
developer's laptop. Votal Shield can check each of those actions before it
happens, against a runtime profile you control in the portal, and stop the
ones the profile does not allow. Claude Code is told why, and every decision
is in your audit log.

1. TOC
{:toc}

## How it works

Claude Code has **hooks**: before a tool call (a shell command, a file
write or edit, a file read, a web fetch, an MCP tool), it can ask an outside
program or URL, which may deny the call. Organisations can install hooks as
**managed settings** that users cannot change.

Shield answers those hook calls at `POST /v1/shield/hooks/claude-code`, using
the runtime profile assigned to the agent the laptop names (for example
`claude-code`):

| Claude Code tool | What Shield checks |
|---|---|
| Bash | the command against the profile's denied and "ask" patterns, the paths it names, the files it redirects into, and the URLs it gives to `curl` or `wget` |
| Write, Edit, MultiEdit, NotebookEdit | the file against the profile's writable paths and denied paths |
| Read, Glob, Grep | the path against the denied paths (reads are not otherwise limited) |
| WebFetch | the URL against the network allow-list |
| MCP tools | the tool's file, command and URL arguments, as for any agent |

In a profile, `@project` means "the folder Claude Code was started in", so
`"read_write": ["@project", "/tmp"]` lets Claude Code write in the project and
`/tmp` and nowhere else.

Decisions are deterministic (no model call) and take well under a
millisecond in Shield, plus the network round trip.

## Choose a variant

| | HTTP hook | Fail-closed hook |
|---|---|---|
| On the laptop | Nothing to install: managed settings only | A small script (`sh` and `curl`, or PowerShell on Windows) and its config file |
| If the laptop cannot reach Shield | **Claude Code goes ahead** | **The action is denied** |
| Good for | Getting started, monitoring, organisations that accept "Shield down means unchecked" | Organisations where every action must be checked |

Both were tested against a real Claude Code. Start with the HTTP hook on a
pilot group, then move to the fail-closed hook.

## Set it up

### 1. Create the profile

In the portal, open **Runtime Profiles**, pick the template
**coding-agent-baseline (Claude Code on laptops)**, name the profile, review
it and save. The template:

- lets Claude Code write only in the project and `/tmp`;
- denies reading credential stores (`~/.ssh`, `~/.aws`, cloud CLIs, keychains,
  browser profiles, `.env` files) and editing Claude Code's own settings or
  the hook's files;
- denies the usual commands for file encryption, deleting snapshots and
  backups, wiping disks, stopping security tools, clearing history, remote
  shells and remote-access tools;
- asks the developer to confirm `sudo`, force pushes and package publishing;
- allows web fetches only to a short list of developer hosts.

Edit it to fit your teams. In particular, add the hosts your developers fetch
documentation and packages from: anything not on the allow-list is denied.
The **Advisor** on the same page turns denied fetches into suggested
allow-list entries for you to approve.

Optionally, limit how fast one Claude Code session may change files:

```json
"limits": {"max_writes_per_minute": 60, "max_deletes_per_session": 200}
```

A session that writes more than 60 files in a minute has further writes
denied until the next minute; one that runs more than 200 delete commands
has further deletes denied for the rest of the session. This catches mass
changes (an agent rewriting or deleting a whole tree) whatever each single
change looks like. Writes are Claude Code's write and edit tools, Bash
redirects into files and commands such as `cp`, `mv` and `tee`; deletes are
commands such as `rm`, `find -delete` and `git clean`. Each tool call or
command counts once, however many files it touches. Pick numbers above what
your developers' normal sessions reach: the Laptops list and the audit log
show when a limit is hit.

### 2. Register the agent

In **Agent Registry**, register an agent with id `claude-code` (or one id per
team, for example `claude-code-payments`) and set its `runtime_profile` to the
profile from step 1. An agent without a profile is not checked.

### 3. Create a key for laptops

Create a tenant API key for the laptops, ideally one with the `runtime`
scope only. It is readable on every laptop, so do not reuse an admin key.

### 4. Build the files

On **Runtime Profiles**, in the **Claude Code on laptops** card, choose the
variant and the operating system, check the agent id and the Shield URL, paste
the key, and click **Build files**. The key is used to build the files and
is not stored. You get:

| File | What it is | Where it goes |
|---|---|---|
| `managed-settings.json` | Claude Code managed settings with the hook | macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\` |
| `votal-claude-code.mobileconfig` (macOS) | The same settings as a configuration profile | Your MDM (Jamf, Kandji, Intune) |
| `install-votal-claude-code.sh` (macOS, Linux) | Installs everything in one step, as root | An MDM policy script |
| `hook.conf` (fail-closed) | The hook's Shield URL, key and agent | macOS `/Library/Application Support/Votal/`, Linux `/etc/votal/`, Windows `C:\ProgramData\Votal\` |
| `claude_code_hook.sh` / `.ps1` (fail-closed) | The hook | macOS `/Library/Application Support/Votal/`, Linux `/opt/votal/`, Windows `C:\Program Files\Votal\` |

If you already manage Claude Code settings, merge the `hooks` and
`allowManagedHooksOnly` keys into your file. The install script never
overwrites managed settings it did not write; it stops and leaves its version
next to yours as `managed-settings.json.votal`.

### 5. Deploy

- **macOS and Linux:** run `install-votal-claude-code.sh` as root from your
  MDM, or upload the `.mobileconfig` (HTTP hook). Try the `.mobileconfig` on
  one Mac first.
- **Windows:** copy the files to the paths above (and, for the fail-closed
  hook, keep the command exactly as built: it ends in `|| exit 2`).
- Developers restart Claude Code to pick up the settings.

### 6. Check one laptop

In Claude Code on a pilot laptop, ask for something the profile denies, for
example "encrypt notes.txt with openssl". Claude Code reports
**Blocked by Votal Shield: command matches denied pattern 'openssl enc*'** and
the file is not changed. Ask for ordinary work and it runs as before.

For the fail-closed hook, also set a wrong `SHIELD_URL` in `hook.conf` and ask
for something harmless: it is denied with "Shield could not be reached".

### 7. Watch

- The **Laptops** list in the card shows each laptop's latest call, its user,
  profile and decision. A laptop whose last call keeps getting older while
  its developer is working may have lost the hook or its route to Shield.
- Every denial and every "ask" is in the decision audit (guardrail
  `runtime_boundary`, source `claude_code`) with the user, laptop, session and
  reason. Every call goes to telemetry and your SIEM. File contents are never
  recorded: only the command, path or URL.

## What it blocks

Coverage by MITRE ATT&CK technique. **Enforced**: denied before it runs.
**Partial**: the usual commands are denied, but an agent can do the same
thing another way (for example in a program it writes), so the profile's
writable paths and network allow-list are the real limit. **Out of scope**:
the hook cannot see it; Votal's device agent or secure web gateway covers it.

| Technique | Profile setting | Coverage |
|---|---|---|
| T1486 Data encrypted for impact | Encryption commands denied; writes only in the project | Commands: enforced. In a program: partial, limited to the project by the write paths |
| T1490 Inhibit system recovery | Snapshot, backup and restore-point deletion denied | Enforced for commands |
| T1485 Data destruction | Recursive deletes outside the project and disk wipes denied; writes outside the project denied; optional per-session limits on writes and deletes | Enforced for Claude Code's tools and commands; partial for programs |
| T1562, T1070 Impair defenses, remove indicators | Stopping security services, clearing logs and history, editing Claude Code or hook settings denied | Enforced for commands and writes |
| T1552, T1555 Credentials in files and stores | Credential paths denied for reads, writes and in commands; keychain queries denied | Enforced for Claude Code's tools and commands; partial for programs |
| T1021 Remote services | Remote shell and copy commands denied | Enforced for commands |
| T1219 Remote access tools | Remote-access tools and piped installers denied | Partial |
| T1041, T1567 Exfiltration | Network allow-list for web fetches, `curl` and `wget`, and MCP tools | Web fetch and MCP: enforced. Commands: partial. Other programs: out of scope |

## Limits to know

- **It governs the agent, not the person.** Commands a developer runs
  themselves, outside Claude Code, are not checked.
- **HTTP hook and outages.** With the HTTP hook, an action goes ahead when
  Shield cannot be reached or answers with an error. Use the fail-closed hook
  where that is not acceptable.
- **Fail-closed hook rules.** Keep `|| exit 2` at the end of the hook
  command (without it, a missing script lets actions through) and keep
  `SHIELD_TIMEOUT` (4 seconds) below the hook's `timeout` (10 seconds): when
  Claude Code stops a slow hook itself, the action goes ahead.
- **"Ask" needs a person.** In a non-interactive session (`claude -p`, CI)
  there is no one to confirm, so an "ask" stops the action.
- **Switching hooks off.** Managed settings with `allowManagedHooksOnly`
  stop users adding their own hooks. Whether a user setting such as
  `disableAllHooks` can switch off a managed hook is being confirmed; until
  then, watch the Laptops list for laptops that go quiet.
- **Paths are compared as text.** Symlinks on the laptop are not resolved.
  `/tmp`, `/var` and `/etc` on macOS are treated as their `/private/...`
  real paths.
- **Windows.** The PowerShell hook is built to the same rules and tested
  against them, but has not yet been run on a Windows laptop. Pilot it first.

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| Nothing is ever denied | The agent id on the laptop has no profile, or the hook is not installed | Check the Laptops list: "none: not checked" means no profile for that agent id |
| Every action is denied with "Shield could not be reached" (fail-closed) | The laptop cannot reach `SHIELD_URL`, or the key is wrong (HTTP 401) | Fix `hook.conf`; `curl` the URL from the laptop |
| Web pages the developer needs are denied | The host is not on the profile's allow-list | Approve the Advisor's suggestion, or add the host |
| A normal command is denied | A deny pattern is too broad | Narrow the pattern in the profile; the denial's reason names it |
| "too many file changes in this session" | The session passed a limit in `limits` | Raise the limit, or start a new Claude Code session |
