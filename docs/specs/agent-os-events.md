---
title: "Spec: Agent OS events from osquery and Sysmon"
layout: default
nav_exclude: true
permalink: /specs/agent-os-events/
description: See what every AI agent on a laptop actually does at the OS level (the programs it starts, the files they change, the connections they make), whether or not the agent has hooks, by attributing osquery (macOS) and Sysmon (Windows) events to agents and checking them against the agent's runtime profile.
---

# Spec: Agent OS events from osquery and Sysmon

> Status: **APPROVED 2026-10-04** (user: "ok then build and dont use nexus
> fully"). Built in Shield's device agent, with no runtime dependency on the
> Votal Nexus agent or server. What Nexus already proves in production is
> reused by porting it: its bundled osquery, its queries (checked against
> osquery 5.23.1) and its parent-chain tracing (`nexus/agent/internal/events`).
> Task 1 (server) built 2026-10-04: `core/dlp/agent_os_events.py` (policy block,
> per-fleet bundle, escape hatch), `core/runtime_policy/os_events.py` (field
> checks, verdict with the hook route's checks, alerts and hourly counts),
> ingest sources `osquery` and `sysmon`, heartbeat `os_events`, `os_events` in
> `PUT /v1/tenant/me/hooks/fleets` and `GET /v1/tenant/me/hooks/os-events`;
> `tests/test_runtime_os_events.py`. `PUT /fleets` now replaces hook fleets only
> when `fleets` is sent, so an OS-events-only update keeps them. Creating the
> `codex`, `gemini-cli` and `cursor-agent` registry entries moves to task 4
> (portal), with the card.
> Builds on: `docs/specs/agent-hook-adapter.md` (#460) and
> `docs/specs/claude-code-fleet-rollout.md` (#461), the Votal device agent and
> rollout kit, and the runtime event ingest (#444).
> Related: `docs/specs/agent-context-for-detections.md` (draft) joins run
> context and exposure onto agent events and adds Sigma runtime rules. It has no
> endpoint sensor. This spec is that sensor's input, and uses its field names.

## 1. Problem & outcome

Hooks (#460, #461) stop a coding agent's own tool calls before they run. They
cannot see:

- **agents without hooks:** Codex, Gemini CLI, Cursor's agent today, and any
  custom agent;
- **what a launched program does:** when an agent runs `python tool.py`, the
  hook sees that command line, not the files the script writes or the hosts it
  contacts;
- **anything outside a tool call.**

The OS sees all of it. osquery (macOS, through Apple's Endpoint Security) and
Sysmon (Windows) already collect process, file and network events reliably and
are widely deployed. Shield adds what neither has: which AI agent an event came
from, and whether the agent's runtime profile allows it.

**Outcome**

1. On laptops with the Votal device agent, an admin turns on **OS events** per
   fleet, in the same Fleets table as the hooks.
2. The device agent reads the OS events locally, keeps only those that come
   from an AI agent's process tree, masks secrets in command lines, and sends
   them to Shield. Everything else stays on the laptop.
3. Shield labels each event with the agent (`AgentId`) and checks it against
   that agent's runtime profile (`ShieldProfileVerdict`: `expected`,
   `outside_profile`, `no_profile`).
4. The portal shows, per laptop and agent, what agents did. Events outside the
   profile appear in the decision audit, the SIEM and as alerts.

Observable success: in a session where Claude Code writes and runs a script
that writes outside the project, the script's write appears attributed to
`claude-code` as `outside_profile`, although the hook allowed the command. The
same holds for Codex, Gemini CLI and a custom agent, none of which has a hook.

**Non-goals (v1)**

- **Blocking.** v1 observes and alerts. Blocking at the OS is phase 2, a
  separate spec: Shield generates rules for Santa (macOS) and Windows App
  Control from runtime profiles, as it already compiles profiles for OpenShell
  and Kubernetes.
- **Our own kernel or Endpoint Security sensor.** osquery and Sysmon do the
  collecting.
- **Inside containers.** On a laptop, Docker runs containers in a Linux VM that
  macOS and Windows cannot see into. Container hosts use Falco or Tetragon,
  which `/v1/shield/runtime/events` already accepts. They are documented, not
  built here.
- **Network connections on macOS.** osquery's macOS network events are weak.
  On macOS v1 records that a network tool ran (`curl`, `wget` and similar),
  with its command line; Windows records the connection itself (Sysmon event
  3).
- ~~**Linux laptops**, which the device agent does not support.~~ Now in
  scope: see section 10 (approved).
- **Replacing the customer's EDR.** This adds agent attribution and profile
  verdicts; it is not an EDR.

## 2. Plane & latency contract

- **Laptop:** collection, attribution and filtering run in the device agent,
  in the background. Nothing waits on them: no Claude Code call, no prompt
  check, no proxy decision.
- **Data plane:** the existing `POST /v1/shield/runtime/events`, which already
  accepts device keys, answers 202 and writes to its sinks after the answer.
  The verdict is computed in that background task.
- **Both planes:** the fleet setting and a read route for the portal.
- **Guard path untouched:** `/guardrails/*`, `cap/mint`, `tools/call` and the
  hook route are not changed. Off hot path, no guarded-traffic impact.
- **Volume:** only agent-tree events leave the laptop. A per-device budget of
  1,000 events a minute applies (the remainder is counted, not sent). This sits
  under the tenant's existing ingest limit of 6,000 a minute.

## 3. Data model

**Device policy (existing record, new optional field)**, signed into each
fleet's bundle like `agent_hooks`, and stored only when set:

```json
"agent_os_events": {
  "agents": {"claude_code": "claude-code", "codex": "codex", "gemini_cli": "gemini-cli",
             "cursor_agent": "cursor-agent"},
  "signatures": [{"label": "build-bot", "match": "(^|/)build-bot($|\\s)"}],
  "default": {"mode": "off"},
  "fleets": {"eng": {"mode": "on"}}
}
```

| Field | Meaning |
|---|---|
| `agents` | Each recognised agent label mapped to the registered agent whose runtime profile gives the verdict. A label with no mapping is recorded with `no_profile` |
| `signatures` | Extra agents to recognise: up to 50 custom agents, each a label and a regular expression (checked for complexity) on the executable path or command line |
| `fleets`, `default` | Per-fleet mode: `off` or `on` |

Built-in signatures cover `claude_code`, `codex`, `gemini_cli`,
`cursor_agent` and `aider`, including when they run under `node`.

**Event** (the existing canonical shape; kinds `process`, `file`, `network`;
source `osquery` or `sysmon`, both new). The new `detail` fields:

| Field | Value |
|---|---|
| `agent_label` | Which agent's process tree |
| `run` | `"<root pid>:<root start time>"`, stable across PID reuse |
| `pid`, `ppid`, `image` | The acting process |
| `command_line` | Process events only. Masked by the bundle's rules on the device, then cut to 1,024 characters |
| `path`, `op` | File events: `create`, `write`, `rename`, `delete` |
| `dest_host`, `dest_ip`, `dest_port` | Network events (Windows) |
| `cwd` | The agent root's working directory, used as `@project` for the verdict |
| `user` | The OS user |

Never file contents, never network payloads.

**Joined on ingest** (server, background):
- `AgentId`: from `agents`.
- `ShieldProfileVerdict`: computed with the same checks as the hook route
  (`core/runtime_policy/hooks.py` session view, with the agent root's `cwd` as
  `@project`). Command lines go through the exec check, files through the
  write or read check, connections through the network check.
- **Where events go:** `outside_profile` events go to the decision audit
  (action `log`, severity `medium`). All events go to telemetry and the SIEM.

**New Redis keys**

| Key | Value | TTL |
|---|---|---|
| `agent_os_alerts:{tenant}` | Capped list (500) of recent `outside_profile` events | 7 days |
| `device_seen:{tenant}` (existing hash) | The heartbeat gains `os_events: {collector, state, version, sent, dropped}` | As today |

`state` is one of `active`, `missing`, `no_permission` or `error`.

**Tenant scoping:** as the ingest route today, the tenant comes from the device
key, never from the event.

## 4. API / interface

### 4.1 On the laptop: collectors in the device agent

**macOS: osquery.**
- The device agent runs its own `osqueryd` instance: its own config, database,
  pidfile and extensions socket, with extensions off and osquery's watchdog
  capping CPU and memory. This is the design Nexus runs in production.
- That instance runs a scheduled query over `es_process_events`
  (`event_type = 'exec'`, joined to `processes` for two levels of parents and
  the responsible app, as Nexus does) and one over `es_process_file_events`.
  The filesystem logger writes into the agent's state folder, and the agent
  tails those results.
- File events need `--disable_endpointsecurity_fim=false`. Nexus turns them
  off, so their volume on a developer laptop is measured in task 0 before this
  is shipped on.
- osquery's notarized binary already carries Apple's Endpoint Security
  entitlement, so Votal does not need its own. It needs Full Disk Access,
  granted by a PPPC payload in the rollout kit's `.mobileconfig` (bundle
  `io.osquery.agent`, team `3522FA9PXF`).

**Windows: osquery, with Sysmon where present.**
- By default the same bundled osquery reads `process_etw_events`
  (`type = 'ProcessStart'`), with no extra install. This is the source Nexus
  uses on Windows. It gives processes only.
- Where Sysmon runs (the customer's own, or installed by the kit when the
  admin opts in), the agent also reads the `Microsoft-Windows-Sysmon/Operational`
  channel through the Windows Event Log API. That adds:
  - 3: network connect;
  - 11: file create;
  - 23 and 26: file delete;
  - 22: DNS query, to name the hosts behind connections.
- Without Sysmon, Windows has process events only, and the portal says so.

**Already deployed.**
- **Sysmon:** where the customer already runs it, the agent reads the existing
  channel and reports which needed event IDs are missing.
- **osquery:** where the customer already runs it (for example through Fleet),
  `OsqueryResultsLog` in the MDM settings points the agent at their results
  log, and they add the Votal pack. Otherwise the agent runs its own instance.

**Attribution** (`attribution.py`, shared by both collectors):
- The agent keeps a process table keyed by pid and start time, built from the
  process events.
- A process belongs to an agent when its executable or command line matches a
  signature, or when its parent belongs to one. Labels are inherited down the
  tree, through `sh -c`, `python`, `node` and `sandbox-exec`.
- Events from other trees are discarded on the laptop.

**Upload:**
- Batches of up to 200 events every 30 seconds to `/v1/shield/runtime/events`,
  with the device key.
- If Shield cannot be reached, the batches go into a bounded on-disk queue
  (10,000 events, oldest dropped and counted), the same pattern as the audit
  upload.

### 4.2 Server

- **Event ingest:**
  - `SOURCES` gains `osquery` and `sysmon`.
  - `normalize()` accepts the new `detail` fields and caps their sizes.
  - The background task computes `AgentId` and `ShieldProfileVerdict` and
    writes `agent_os_alerts`.
- **`PUT /v1/tenant/me/hooks/fleets`** (both planes) also accepts
  `os_events: {fleet: "on"|"off"}`. `GET` adds each fleet's mode and laptop
  counts by collector state.
- **`GET /v1/tenant/me/hooks/os-events?since=`** (both planes): recent
  `outside_profile` events, and per-laptop, per-agent counts for the last 24
  hours, from telemetry counters.
- **Escape hatch:** `SHIELD_DEVICE_AGENT_OS_EVENTS=off` resolves every fleet to
  off in bundles, and the ingest drops these sources.

### 4.3 Portal

- **Fleets table:** an **OS events** column (off or on) and the collector
  states.
- **New card, "What agents did":** per laptop and agent, counts of commands,
  file changes and connections, and the recent `outside_profile` events with
  the command or path and the reason.
- **Agent Registry:** gains the agents `codex`, `gemini-cli` and
  `cursor-agent`, created on first use from `agents`, unbound until a profile
  is chosen.

### 4.4 Rollout kit

- The kit gains an **OS events** option.
- **osquery** is bundled in the device agent's installers (`.pkg`, `.msi`)
  with its licence file, as Nexus bundles it: a pinned version, verified when
  the installer is built, so laptops download nothing at install time.
- **macOS:** a PPPC payload grants Full Disk Access to the bundled
  `osquery.app` and the agent.
- **Windows, optional:** Sysmon is downloaded from Microsoft's official
  location with a pinned SHA-256 at install time, never redistributed. The
  Votal Sysmon configuration is installed with it. Customers who already run
  Sysmon skip this; the agent reads their channel.

### 4.5 Next to the Votal Nexus agent

Some laptops run both agents. They stay independent:

- **Two osquery instances.** Each agent runs its own, with its own state,
  pidfile and extensions socket. Nexus documents that it never touches an
  osquery it did not start; Shield's agent does the same. Task 0 confirms that
  two Endpoint Security clients run side by side.
- **The loopback port.** Both agents listen on `127.0.0.1:47823` today
  (Nexus for browser device checks, Shield for its local API and the Claude
  Code hook route), so they cannot run on the same laptop. Shield's agent
  moves to a new default, `127.0.0.1:47833`, in task 2. It keeps reading
  `local_port` from its settings, and its native-messaging host and hook
  configuration follow the port it actually uses.

## 5. Security & backward compatibility

- **Opt-in per fleet; the default is off.** Tenants that never set
  `agent_os_events` keep identical policy hashes and bundles (the same rule as
  `agent_hooks`). Agents older than the release ignore the field.
- **Privacy:** only events from AI agents' process trees leave the laptop.
  Command lines are masked with the tenant's rules on the device and cut to
  1,024 characters. File events carry paths only. The portal says this where
  the setting is switched on.
- **What the admin is granting:** osquery with Full Disk Access sees every
  file event on the Mac. That is the customer's decision, made in their MDM,
  and the kit says so. The Votal agent reads osquery's results and discards
  everything not from an agent.
- **Tampering:** a local admin can stop osquery or Sysmon. The heartbeat then
  reports `missing`, the portal shows it, and a laptop that keeps running
  Claude Code hooks with no OS events is listed. This is detection, not
  prevention, as with the device agent today.
- **Not a decision path:** a verdict never blocks anything, so a wrong
  attribution cannot stop work. It can create a false alert, which the tests
  in section 8 guard against.
- **Licences:**
  - osquery is dual-licensed Apache-2.0 / GPL-2.0, and we use it under
    Apache-2.0;
  - Sysmon is fetched from Microsoft on the laptop and never redistributed by
    Votal. Task 0 confirms its terms allow this install path.

## 6. Packaging & deploy

- **Server:** changes in `core/runtime_policy/events.py`,
  `core/dlp/device_policy.py`, a new `core/dlp/agent_os_events.py`, and
  `api/routes_hooks_portal.py`, which is already in `Dockerfile.admin`. Any
  new module that `admin_app.py` imports is added to `Dockerfile.admin`.
- **Device agent:** new `collectors/osquery.py`, `collectors/sysmon.py` and
  `attribution.py`.
  - The Votal osquery pack and Sysmon configuration ship as Python constants,
    since PyInstaller bundles modules, not data (as in #461). Each has a drift
    test.
  - The Windows Event Log API is reached through `ctypes`, so no new pip
    dependency.
- **Installers:** osquery bundled, pinned and verified at build time; its
  licence file included. The installer workflows check it is present.
- **Kit:** the PPPC payload, and the optional Sysmon fetch step with a pinned
  hash.
- **Deploy order:** server first, then the agent release, then new kits. Each
  step is inert until the next one, and until a fleet is switched on.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| osquery not installed, or no Full Disk Access | Heartbeat `missing` or `no_permission`; nothing sent; the portal shows it |
| Sysmon config lacks event 11 or 3 | Heartbeat `active`, with the missing IDs listed; those kinds are absent |
| PID reused | Runs and the process table are keyed by pid and start time |
| An agent runs a build that writes thousands of files | Per-device budget of 1,000 a minute; the remainder is counted as `dropped`. Writes inside `@project` are summarised per directory, not sent one by one |
| `node` processes that are not agents | Recognised only with an agent package in the arguments; plain `node` is not an agent |
| A process started by a terminal the agent opened, then left running | Still in the agent's tree, so attributed. The run ends when the root exits |
| Container writes on a mounted folder | Not attributed (Docker's VM process wrote them). Documented; containers use Falco or Tetragon |
| Shield unreachable | On-disk queue (10,000 events), oldest dropped and counted |
| The bundle cannot be trusted (fallback) | The last applied setting stays, as with `agent_hooks` |

## 8. Test plan (Definition of Done)

- **Attribution:** recorded fixtures from real `eslogger`, osquery and Sysmon
  output (captured in task 0) for Claude Code, Codex, Gemini CLI, Cursor's
  agent, a custom agent, a script an agent writes and runs, and container
  tooling. Every case lands under the right agent, and nothing from other
  processes is kept.
- **Masking:** command lines carrying secrets are masked before they leave
  the device.
- **Verdicts:** expected, outside_profile and no_profile, for each kind,
  including `@project` from the root's `cwd`.
- **Device policy:** the field is optional, so tenants without it keep the
  same hash; per-fleet resolution; the escape hatch.
- **Ingest:** the new sources, size caps, the alerts list, telemetry fields
  matching `agent-context-for-detections.md`'s names.
- **Agent:** budget, queue, heartbeat states, and both collectors, from
  fixtures.
- **Kit:** the osquery and Sysmon steps carry pinned hashes; the PPPC payload
  is present only with the option; the drift tests.
- **Portal:** wiring and escaping tests.
- **Suite:** full suite green in a clean venv; CI `pytest` passes.
- **Live:** on a real Mac and a real Windows machine, the observable-success
  session in section 1.

## 9. Amendment: blocking unapproved agent actions

> **APPROVED 2026-10-04** (user: "approve the amendment"; asked for: "ensure
> agent actions from any agent, sandbox, docker, native app if not approved can
> be blocked"). Phase 2, after v1 ships; v1's scope above is unchanged.

**Goal:** for each kind of place an agent runs, an action its runtime profile
does not approve can be **blocked**, not only reported. The profile stays the
one source of truth; Shield compiles it to whatever enforcement that place
already has, as it does today for sandboxes and clusters.

| Where the agent runs | Enforcement point | Status |
|---|---|---|
| Coding agents with hooks (Claude Code) | The hook route, per tool call | Shipped (#460, #461) |
| Agents calling tools through Shield (MCP gateway, SDK) | `tools/call` and capability checks | Shipped |
| Sandboxes and Kubernetes | Runtime profiles compiled to OpenShell, Kubernetes, Cilium, Squid | Shipped (#444) |
| Docker on a developer laptop | Run agent containers under a compiled profile (network and filesystem limits at container start) | New: phase 2 |
| Native agents and the programs they start, macOS | An allow or deny decision at program start and file access, from an Endpoint Security authorization client (Santa), with rules generated from profiles | New: phase 2 |
| Native agents and the programs they start, Windows | Windows App Control policy generated from profiles, deployed through the device agent or Intune | New: phase 2 |

**How phase 2 rolls out**

- **Per fleet, with the same switch:** `off`, `monitor` (v1: report only),
  `enforce` (block what the profile does not approve).
- **Approval before blocking:** an action that was reported as
  `outside_profile` in monitor mode becomes blockable only after an admin
  either approves it into the profile (the existing Advisor flow) or leaves
  it out. So switching a fleet to enforce blocks only what admins have
  already seen.
- **Scoped to agents:** rules apply to AI agents' process trees, never to the
  person's own programs.
- **Same escape hatch** and per-fleet off switch as the hooks.

**What phase 2 needs that v1 does not**

- A Santa (or equivalent) deployment on macOS, through the rollout kit. Its
  authorization role and the entitlement it needs are confirmed in phase 2's
  task 0.
- App Control policy delivery on Windows, and its interaction with policies
  the customer already deploys.
- A profile-to-rules compiler for each, tested like the existing compilers.

Phase 2 keeps v1's order: v1 ships first (it produces the monitor-mode data
that admins approve from), and phase 2 gets its own task list once this
amendment is approved.

## 10. Amendment: Linux

> **APPROVED 2026-10-04** (user: "approve the linux amendment"; asked for: "will
> it work for windows & linux, can you ensure"). Adds Linux workstations,
> servers and containers; supersedes the "Linux laptops" non-goal in section 1.

**Where things stand.**
- The **server** handles events from all three operating systems. Task 1 was
  checked with events as osquery and Sysmon report them: programs by full path
  (`/usr/bin/openssl`, `"C:\...\openssl.exe"`), Windows drive paths and
  `C:\Users\<name>` homes, Linux `/home/<name>` homes. Commands and paths are
  put in one POSIX form before the profile check (`os_events.norm_command`,
  `norm_path`), so one profile works on every OS.
- The **collectors** exist for macOS (task 2) and Windows (task 3) only. The
  Votal device agent has no Linux build.

**What Linux needs**

| Linux machine | Collector | Work |
|---|---|---|
| Developer workstation or VM | The device agent's Linux build running osquery: `bpf_process_events` (or `process_events` through audit where BPF is not available) and `process_file_events` | Device agent for Linux: a systemd service, `.deb` and `.rpm` packages, keys in a root-only file, and the osquery collector from task 2 with Linux tables |
| Server or Kubernetes node running agents in containers | Falco or Tetragon, which Shield already accepts as runtime event sources | Server-side attribution for those sources: the agent is recognised from the process ancestry they report (Falco `proc.aname`, `proc.acmdline`; Tetragon process ancestors), then the same verdict |
| Docker Desktop on a Mac or Windows laptop | Not visible from the host (the containers run in a VM) | Covered by phase 2's compiled container run profile (block), not by observation |

**Tasks (added after v1's task 3; approved)**

- **L1:** Linux device agent build (systemd, `.deb` and `.rpm`, root-only key
  file), enrollment and heartbeat, tests.
- **L2:** the osquery collector's Linux tables, with fixtures captured on a
  real Linux machine, as task 0 does for macOS and Windows.
- **L3:** agent attribution and the verdict for Falco and Tetragon events on
  servers and nodes, with fixtures.
- **L4:** release (`.deb`, `.rpm`) and a live check on a Linux machine.

## Tasks

0. **Measure, no Shield code.**
   - On the Mac: the `eslogger` capture and analyser (in progress), then the
     same session through `osqueryi`'s `es_process_events` and
     `es_process_file_events`.
   - On Windows: Sysmon with the candidate config, for the same agents.
   - Record fixtures, events per minute for a normal session, and the
     attribution accuracy.
   - Confirm that two `osqueryd` instances coexist, the PPPC payload, and the
     Sysmon install path and terms.
   - If attribution is unreliable for an agent, that agent is dropped from v1.
1. **Server:**
   - the `agent_os_events` policy block and bundle;
   - ingest sources and fields;
   - verdict and alerts;
   - escape hatch;
   - tests.
2. **Device agent, macOS:**
   - the attribution engine (porting Nexus's parent-chain tracing);
   - the osquery supervisor and collector;
   - budget and queue, heartbeat;
   - the local port move to 47833;
   - tests from fixtures.
3. **Device agent, Windows:** osquery ETW collector, the optional Sysmon
   reader, tests from fixtures.
4. **Installers, kit and portal:**
   - bundled osquery in the `.pkg` and `.msi`;
   - the PPPC payload and the optional Sysmon step;
   - the OS events column;
   - the "What agents did" card.
5. **Release and docs:** agent release, customer guide, live Mac and Windows
   checks.

**Phase 2 (section 9, approved), after v1 ships:**

6. **Measure, no Shield code:** Santa's authorization mode and entitlement on
   macOS next to osquery; App Control policy delivery on Windows next to the
   customer's own policies; starting an agent container under a compiled
   profile on Docker Desktop.
7. **Profile-to-rules compilers:** Santa rules, App Control policy and the
   container run profile, each listing what it cannot express, like the
   existing compilers; tests.
8. **Enforce mode per fleet:** the `enforce` value for OS events, blocking only
   actions admins approved or left out after monitor mode; rule delivery
   through the device agent; heartbeat state; portal.
9. **Release and live checks** on a real Mac and Windows machine.
