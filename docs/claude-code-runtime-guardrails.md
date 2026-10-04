---
title: Claude Code guardrails
layout: default
nav_order: 30
permalink: /claude-code-runtime-guardrails/
description: Make Claude Code on employee laptops ask Votal Shield before every command, file write and fetch, so a runtime profile (no file encryption, no writes outside the project, no credential reads) is enforced there too. Turned on per device fleet from the portal; the Votal device agent installs it.
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
program, which may deny the call. Organisations can install hooks as
**managed settings** that users cannot change.

Shield answers those calls using the runtime profile of the agent the laptop
is checked as (for example `claude-code`):

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

## Two ways to roll it out

| | With the Votal device agent (recommended) | Without it |
|---|---|---|
| What you deploy | Nothing new: the device agent you roll out for Device DLP (version 0.2.0 or later) installs and maintains the hook | Managed settings, and for fail-closed a small script and its config, by MDM |
| Keys on laptops | None: each laptop uses its own device key | A tenant key, readable on every laptop |
| Turning it on and off | Per fleet, in the portal, within a sync (a few minutes) | Push new files |
| Pilot without blocking | Monitor mode: Shield records what it would block | Not available |
| If Shield cannot be reached | Your choice per fleet: allow or deny | HTTP hook: allowed. Fail-closed hook: denied |

## With the Votal device agent

You need laptops enrolled with the Votal device agent 0.2.0 or later (Device
DLP, rollout kits). Fleets are the groups you created kits for.

### 1. Turn it on

In the portal, open **Runtime Profiles**. In the **Coding agents on laptops**
card, click **Turn on for Claude Code**. Shield:

- creates the profile **coding-agent-baseline** from the template, or keeps
  yours if one with that name exists (it never overwrites a profile);
- registers the agent `claude-code` with that profile, or binds your existing
  `claude-code` agent to it. If that agent already uses another profile,
  Shield asks before changing it;
- covers Claude Code on your fleets. Every fleet stays **off** until you set
  its mode.

### 2. Review the profile

The baseline profile:

- lets Claude Code write only in the project and `/tmp`;
- denies reading credential stores (`~/.ssh`, `~/.aws`, cloud CLIs, keychains,
  browser profiles, `.env` files) and editing Claude Code's own settings or
  the hook's files;
- denies the usual commands for file encryption, deleting snapshots and
  backups, wiping disks, stopping security tools, clearing history, remote
  shells and remote-access tools;
- asks the developer to confirm `sudo`, force pushes and package publishing;
- allows web fetches only to a short list of developer hosts.

Edit it under **Edit profile** to fit your teams. In particular, add the hosts
your developers fetch documentation and packages from: anything not on the
allow-list is denied. The **Advisor** on the same page turns denied fetches
into suggested allow-list entries for you to approve.

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
command counts once, however many files it touches.

### 3. Pilot one fleet in monitor mode

In the **Fleets** table, set a pilot fleet to **monitor**, leave **If Shield
can't be reached** at **allow**, and click **Save fleet modes**.

At their next sync the fleet's laptops install the hook, and the fleet's row
shows them as **hook active**. Claude Code sessions started from then on are
checked; sessions already open are checked once they are restarted.

In monitor mode nothing is blocked: Shield records what it would have done.
The **Laptops** list shows calls as "would be denied", and the decision audit
has them with `monitor: true`.

### 4. Tune, then enforce

Read the would-be denials for a few days. Widen the allow-list or narrow a
pattern where they were normal work. Then set the fleet to **enforce**, and
choose what happens when a laptop cannot get an answer from Shield:

- **allow**: Claude Code goes ahead, with a warning (the Shield service or the
  network is down, or the device agent is stopped);
- **deny**: the action is blocked until Shield answers again.

Shield's own denials always block, whichever you choose.

Changes to a fleet's mode reach running Claude Code sessions on the next tool
call; there is nothing to restart.

### 5. Check one laptop

On a laptop in an enforcing fleet, start Claude Code and ask for something the
profile denies, for example "encrypt notes.txt with openssl". Claude Code
reports **Blocked by Votal Shield: command matches denied pattern
'openssl enc*'** and the file is not changed. Ask for ordinary work and it runs
as before.

On the laptop, `votal-device-agent claude-code-hook` (as an administrator)
shows where the agent writes Claude Code's settings and which hook it ships.

To check a whole deployment from the outside instead (the routes exist,
ordinary work is allowed, a denied command is denied), run
`scripts/smoke_agent_hooks.sh` with `SHIELD_URL` and a tenant key, or the
**Smoke check coding-agent hooks** workflow (`gh workflow run
smoke-agent-hooks.yml`) once the `SHIELD_SMOKE_TENANT_KEY` secret is set.

### 6. Watch

- The **Fleets** table shows, per fleet, how many laptops have the hook
  **active**, are in **settings conflict**, report an **error**, or have
  **not reported** (agent older than 0.2.0, or not synced yet).
- The **Laptops** list shows each laptop's latest call, its fleet, user,
  profile and decision. A laptop whose last call keeps getting older while its
  developer is working may have lost the hook or its route to Shield.
- Every denial, every "ask" and every monitor-mode would-be denial is in the
  decision audit (guardrail `runtime_boundary`, source `claude_code`) with the
  user, laptop, fleet, session and reason. Every call goes to telemetry and
  your SIEM. File contents are never recorded: only the command, path or URL.

### Claude Code settings you already manage

The agent never overwrites a Claude Code managed settings file it did not
write. If one exists, the laptop shows **settings conflict** and the agent
leaves it alone: merge the `hooks` and `allowManagedHooksOnly` keys (the
**Laptops without the Votal agent** section shows them) into your file, or
remove your file and the agent takes over at its next sync.

## Without the Votal device agent

For laptops that do not run the Votal device agent (including Linux).

1. **Profile and agent.** Follow steps 1 and 2 above, or create the profile
   under **Edit profile** and choose it in **Agent Registry** (the agent's
   **Runtime profile** field).
2. **A key for laptops.** Create a tenant API key, ideally with the
   `runtime` scope only. It is readable on every laptop, so do not reuse an
   admin key.
3. **Build the files.** Open **Laptops without the Votal agent** in the card,
   choose the hook and the operating system, check the agent id and the
   Shield URL (your Shield API address, not the portal's), paste the key, and
   click **Build files**. The key is used to build the files and is not
   stored.
4. **Deploy** with your MDM:

| File | What it is | Where it goes |
|---|---|---|
| `managed-settings.json` | Claude Code managed settings with the hook | macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\` |
| `votal-claude-code.mobileconfig` (macOS) | The same settings as a configuration profile; try it on one Mac first | Your MDM (Jamf, Kandji, Intune) |
| `install-votal-claude-code.sh` (macOS, Linux) | Installs everything in one step, as root; never overwrites managed settings it did not write | An MDM policy script |
| `hook.conf` (fail-closed) | The hook's Shield URL, key and agent | macOS `/Library/Application Support/Votal/`, Linux `/etc/votal/`, Windows `C:\ProgramData\Votal\` |
| `claude_code_hook.sh` / `.ps1` (fail-closed) | The hook | macOS `/Library/Application Support/Votal/`, Linux `/opt/votal/`, Windows `C:\Program Files\Votal\` |

Developers restart Claude Code to pick up the settings. Check one laptop as in
step 5 above. For the fail-closed hook, also set a wrong `SHIELD_URL` in
`hook.conf` and ask for something harmless: it is denied with "Shield could
not be reached". `ON_UNREACHABLE=allow` in `hook.conf` lets actions through
instead when Shield cannot answer; Shield's own denials still block.

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
  themselves, outside Claude Code, are not checked. Neither are programs an
  agent without hooks runs.
- **Turning a fleet on for the first time** covers Claude Code sessions
  started after the laptop's next sync. Sessions already open are covered
  once restarted. Later changes, including switching the fleet off, reach
  running sessions straight away.
- **A revoked laptop** keeps getting answers from Shield for up to 30 seconds,
  then follows its fleet's "if Shield can't be reached" choice.
- **"Ask" needs a person.** In a non-interactive session (`claude -p`, CI)
  there is no one to confirm, so an "ask" stops the action.
- **Switching hooks off.** Managed settings with `allowManagedHooksOnly`
  stop users adding their own hooks. Whether a user setting such as
  `disableAllHooks` can switch off a managed hook is being confirmed; until
  then, watch the Laptops list for laptops that go quiet.
- **Paths are compared as text.** Symlinks on the laptop are not resolved.
  `/tmp`, `/var` and `/etc` on macOS are treated as their `/private/...`
  real paths.
- **Without the agent**, keep `|| exit 2` at the end of the fail-closed hook
  command (without it, a missing script lets actions through) and keep
  `SHIELD_TIMEOUT` (4 seconds) below the hook's `timeout` (10 seconds). The
  agent's settings already do both.
- **Windows.** The Windows hook is built and tested to the same rules, but how
  Claude Code runs a hook command on Windows is still being confirmed on a
  real laptop. Pilot Windows fleets in monitor mode first.

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| Nothing is ever denied | The fleet is off or in monitor mode, the agent id has no profile, or the session started before the hook was installed | Check the fleet's mode, the status line in the card, and restart Claude Code |
| A fleet shows laptops as **not reported** | Those laptops run an agent older than 0.2.0, or have not synced since | Update the agent (new rollout kit or your MDM) and wait for a sync |
| A laptop shows **settings conflict** | Claude Code managed settings the agent did not write are already there | Merge the hooks block into them, or remove them |
| Every action is denied with "Shield could not be reached" | The laptop cannot reach Shield (or the agent is stopped) and the fleet denies when unreachable | Check the laptop's network and the agent (`votal-device-agent status`) |
| Web pages the developer needs are denied | The host is not on the profile's allow-list | Approve the Advisor's suggestion, or add the host |
| A normal command is denied | A deny pattern is too broad | Narrow the pattern in the profile; the denial's reason names it |
| "too many file changes in this session" | The session passed a limit in `limits` | Raise the limit, or start a new Claude Code session |
