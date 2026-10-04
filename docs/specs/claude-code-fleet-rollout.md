---
title: "Spec: Coding-agent guardrails as a fleet switch (Claude Code first)"
layout: default
nav_exclude: true
permalink: /specs/claude-code-fleet-rollout/
description: Enterprises turn on Claude Code guardrails per device fleet in the portal; the Votal device agent they already deploy installs and maintains the hook, so there is no extra MDM package, key or file to handle.
---

# Spec: Coding-agent guardrails as a fleet switch (Claude Code first)

> Status: **APPROVED 2026-10-04** (user: "approved, start task 0"). Task 0 in
> progress: four checks done (section 9), two need the owner's machines.
> Task 1 (server) built: `core/dlp/agent_hooks.py`, device policy and bundle,
> device keys on the hook route with a 30 s lookup cache, fleet modes,
> monitor records, escape hatch; `tests/test_runtime_hooks_devices.py`.
> Renamed `claude_code` to `agent_hooks` (one entry per coding agent) before
> task 2. Task 2 (portal and admin API) built: `/v1/tenant/me/hooks/enable`
> and `/fleets` in `api/routes_hooks_portal.py`, heartbeat `agent_hooks`
> state, the card (status, fleets, laptops, standalone section, URL default
> from `SHIELD_DEVICE_AGENT_SHIELD_URL`), the Agent Registry runtime profile
> field; `tests/test_runtime_hooks_portal.py`.
> Task 3 (device agent) built: `votal_device_agent/agent_hooks.py` (apply per
> bundle, verified or grace bundles only; checksum conflict rule; `{}` when
> off after on), `POST /v1/local/claude-code/hook` forwarding with the device
> key (3 s, then `on_unreachable`), the hook scripts' `ON_UNREACHABLE` and
> `SHIELD_LOCAL_SECRET_FILE`, heartbeat state; scripts embedded through
> `packaging/sync_hook_scripts.py` (PyInstaller bundles modules, not data);
> `tests/test_runtime_hooks_agent.py`. The version stays 0.1.0 until task 4
> publishes the 0.2.0 installers, because kits pin the agent's version.
> Task 4 in progress: agent and kit pin at 0.2.0; `votal-device-agent
> claude-code-hook` reports the bundled hook scripts, and both installer
> workflows (PR build and release) now fail if the frozen binary lacks them;
> customer guide rewritten around the fleet switch. Left: the
> `device-agent-v0.2.0` release (no signing secrets are set, so it would be an
> unsigned pre-release), and the real Mac and Windows end-to-end checks.
> Builds on: `docs/specs/agent-hook-adapter.md` (shipped in #460) and the
> device agent and rollout kit (`docs/specs/device-dlp-agent.md`,
> `docs/specs/device-rollout-kit.md`).

## 1. Problem & outcome

Turning on Claude Code guardrails today takes four separate jobs, done by
two teams:

1. Save a runtime profile.
2. Bind it to the `claude-code` agent. This is only possible through the
   API: the Agent Registry form has no runtime profile field.
3. Build the rollout files in the portal. The card fills in the portal's own
   URL, which does not serve the hook route, so the files must be corrected
   by hand.
4. Create a laptop key, paste it in, and push a second MDM package next to
   the Votal device agent kit IT already deploys.

On top of that, an admin must choose between the HTTP and fail-closed
variants before knowing what either means in practice.

**Outcome.** For a tenant that already runs the Votal device agent:

1. In the portal, the admin clicks **Turn on for Claude Code** once. Shield
   creates the profile from the `coding-agent-baseline` template (or keeps
   the admin's existing one) and binds it to the `claude-code` agent.
2. The admin sets a mode for each device fleet: **off**, **monitor** or
   **enforce**, plus what happens when Shield cannot answer: **allow** or
   **deny**.
3. Within one bundle sync (minutes), every enrolled laptop in that fleet has
   Claude Code asking Shield before each tool call. IT pushes nothing new.
   No key is created, pasted or distributed: each laptop uses the device key
   it already has.
4. The portal shows, per fleet and per laptop, whether the hook is active,
   whether the laptop has its own Claude Code managed settings that need
   merging, and each laptop's last hook call.

In **monitor** mode, Shield records what it would have denied and lets
everything through. A team can pilot the baseline without blocking anyone,
read the would-be denials, tune the profile, then switch to enforce.

**Non-goals**

- Laptops without the Votal device agent. They keep the standalone path
  from #460 (the "Build files" card), which stays as it is apart from the
  URL fix in section 4.4.
- Linux. The device agent ships for macOS and Windows only.
- Other coding agents (Cursor, Codex). The same agent mechanism could carry
  them later; this spec does Claude Code only.
- Changing what the hook checks or how decisions are made. That is #460.

## 2. Plane & latency contract

- **Data plane:**
  - The hook route `POST /v1/shield/hooks/claude-code` also accepts device
    keys.
  - The signed DLP bundle carries each fleet's Claude Code setting.
- **Both planes:** the new enable and fleet settings routes, the Agent
  Registry change, and the portal.
- **Device agent** (`packages/votal-device-agent`): it installs the hook and
  forwards hook calls to Shield.
- **Guard path untouched:** `/guardrails/*`, `cap/mint` and `tools/call`
  are not changed. The hook route is the coding agent's decision path, as
  in #460.
- **Latency on the hook path:**
  - The local hop (Claude Code to the agent on `127.0.0.1`) adds well under
    5 ms.
  - Authenticating a device key on the server takes three store reads
    today (`caller_device`). Successful lookups are cached in process for
    30 seconds, so a busy session pays that cost once every 30 seconds, not
    on every call. Section 5 covers what the cache means for revocation.
  - The per-fleet mode comes from the device policy, which is already
    cached.
  - Server-side budget is unchanged: under 20 ms at p95.

## 3. Data model

**Device policy (existing record, new optional field).** This rides in the
signed bundle, like `fleet_modes`:

```json
"agent_hooks": {
  "agents":  {"claude_code": "claude-code"},
  "default": {"mode": "off", "on_unreachable": "allow"},
  "fleets": {
    "eng-pilot": {"mode": "monitor", "on_unreachable": "allow"},
    "eng":       {"mode": "enforce", "on_unreachable": "deny"}
  }
}
```

Renamed from `claude_code` on 2026-10-04 (user: "approved, rename to
agent_hooks"), so other coding agents with pre-action hooks (Cursor, Gemini
CLI, Codex) are new keys in `agents`, not a new policy field.
`core/dlp/agent_hooks.py` `CODING_AGENTS` lists the supported ones; today
only `claude_code`. A fleet's mode and `on_unreachable` apply to every
covered coding agent on its laptops. Any OS event from any process (agents
without hooks, programs an agent writes) needs an endpoint sensor and is a
separate spec.

- **`mode`:** `off`, `monitor` or `enforce`.
- **`on_unreachable`:** `allow` or `deny`. It applies when the laptop cannot
  get an answer from Shield (Shield is down, the network is down, or the
  agent is stopped).
- **`agents`:** for each covered coding agent, the registered agent whose runtime profile decides.
- **Fleets:** at most `MAX_FLEETS` (100), with ids validated like
  `fleet_modes`.
- **Validation and backward compatibility:** validated strictly, like the
  rest of the policy. When the field is missing, every fleet is `off`.
- **Bundle delivery:** `for_fleet()` resolves it to the one fleet's
  `{"agents", "mode", "on_unreachable"}`, so a device never sees other
  fleets' settings.

**Device heartbeat (existing, new optional field).**

```json
"agent_hooks": {"claude_code": {"state": "active", "settings_hash": "sha256:...", "hook_version": "1"}}
```

`state` is one of:

| State | Meaning |
|---|---|
| `active` | The agent wrote the managed settings and the hook |
| `off` | The fleet's mode is off and nothing is installed |
| `conflict` | A Claude Code managed settings file the agent did not write is present; the agent left it alone (section 7) |
| `error` | Applying the settings failed (with a short reason) |

The value is stored in `device_seen:{tenant}`, next to the existing
heartbeat fields.

**Hook decisions.**

- Same audit rows and runtime events as #460. The device id comes from the
  device record, not a header.
- The record gains `fleet` and, in monitor mode, `"monitor": true` with the
  decision that would have been made.
- `hook_seen:{tenant}` (#460) is keyed by device id and gains `fleet`.

**No new Redis keys** beyond the in-process device lookup cache. Tenant
scoping is unchanged: the tenant always comes from the device key's own
record, never from the request.

## 4. API / interface

### 4.1 Hook route accepts device keys (data plane)

- `("POST", "/v1/shield/hooks/claude-code")` joins `DEVICE_PATHS`. The
  middleware's 403 message is updated to list it.
- With a device key:
  - The tenant, device id and fleet come from the device record, as
    `/v1/shield/runtime/events` already does.
  - `X-Device-Id` is ignored.
  - The agent id is the fleet's `agent_hooks.agents.claude_code`.
- With a tenant key, the route behaves exactly as in #460.
- **Fleet mode `off`:** answer `{}`.
- **Fleet mode `monitor`:** decide as usual, record the decision with
  `monitor: true`, and answer `{}`.
- **Fleet mode `enforce`:** answer the decision.

### 4.2 Turn on, and fleet settings (both planes, tenant admin)

**`POST /v1/tenant/me/hooks/enable`**

Body: `{"coding_agent": "claude_code", "profile": "coding-agent-baseline", "agent": "claude-code", "replace_binding": false}`. It also adds the coding agent to `agent_hooks.agents`.

- **Profile:** if the profile does not exist, it is created from the
  template. If it does exist, it is used as it is and never overwritten.
- **Agent:** if the agent does not exist, it is created with
  `runtime_profile` set. If it exists without a profile, the profile is
  set. If it exists bound to a **different** profile, the route returns 409
  `{current_profile}` unless `replace_binding` is true.
- **Response:** `{profile, profile_created, agent, agent_created, bound}`.
- **Idempotent:** running it twice changes nothing.

**`GET` / `PUT /v1/tenant/me/hooks/fleets`**

- Reads or replaces the `agent_hooks` block of the device policy (section
  3), using the device policy's existing save path. That path includes its
  history and validation.
- `GET` adds, per fleet:
  - device counts from the device list;
  - counts by heartbeat `agent_hooks.<coding agent>.state`.

### 4.3 Agent Registry (portal)

The agent form gets a **Runtime profile** dropdown, filled from
`/v1/tenant/me/runtime-profiles`, with "None" as the first choice. It sends
`runtime_profile` on create and update. Both routes already accept and
validate it. This closes the gap where the Runtime Profiles page says
"bind an agent in the Agent Registry" but no form field exists.

### 4.4 Portal: the Claude Code card

The card on Runtime Profiles becomes:

1. **Status line:**
   - which profile and agent are in use;
   - when nothing is set up yet, a **Turn on for Claude Code** button that
     calls `/enable`.
2. **Fleets table:** one row per fleet, with:
   - a mode select (off, monitor, enforce);
   - an "if Shield can't be reached" select (allow, deny);
   - laptop counts by state (active, conflict, off, error).

   **Save** calls `PUT /fleets`.
3. **Laptops table** (#460): gains the device name and fleet from the
   device record, and the state. A `conflict` row shows the managed settings
   snippet to merge.
4. **Build files** (the #460 standalone path): moves into a collapsed
   section titled "Laptops without the Votal agent".
   - Its Shield URL default changes to `SHIELD_DEVICE_AGENT_SHIELD_URL`,
     then `SHIELD_PUBLIC_URL`, then the request URL.
   - The card says so when it falls back to the request URL.
   - This fixes the wrong URL seen after #460: the portal answered 404 for
     the hook route.

### 4.5 Device agent (`packages/votal-device-agent`, version 0.2.0)

**New module `agent_hooks.py`** (with one settings writer per coding agent; Claude Code's first). On every bundle sync it applies the
fleet's setting:

| Fleet mode | What the agent does |
|---|---|
| `monitor` or `enforce` | Writes the Claude Code managed settings file with a command hook. On macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`. On Windows: `C:\Program Files\ClaudeCode\managed-settings.json`. It also writes the hook script and `hook.conf` into its own install directory (root or SYSTEM owned, readable by users) and records a checksum of what it wrote. |
| `off`, after having been on | **Rewrites** its managed settings file to `{}` rather than deleting it, and records the new checksum. Task 0 showed that a running session follows changes to a settings file that already exists, but ignores a file that appears mid-session. Keeping the file in place lets later switches, on or off, reach running sessions. It never touches a file whose checksum does not match. |
| `off`, never on | Writes nothing. |

The managed settings content does not depend on the mode: monitor versus
enforce is decided by the server on each call, and `ON_UNREACHABLE` is read
from `hook.conf` on each call. A mode change therefore needs no new settings
file, and takes effect on the next tool call in running sessions.

**The command hook** is the #460 script (`claude_code_hook.sh`, and `.ps1`
on Windows) with two additions read from `hook.conf`:

- **`SHIELD_LOCAL_SECRET_FILE`:** the script sends the agent's existing
  local secret (`state/local_secret`, already user-readable) to the agent's
  local API instead of a tenant key.
- **`ON_UNREACHABLE=allow|deny`:**
  - `deny`: the script keeps #460's rule that every failure exits 2.
  - `allow`: a failure exits 0 and the hook prints a one-line warning.

**New local API route** `POST /v1/local/claude-code/hook` on
`127.0.0.1:47823`:

- It uses the same checks as the other local routes: the local secret, no
  web origin, and a loopback host only.
- It forwards the body to Shield's hook route with the device key, so the
  key never leaves root or SYSTEM.
- It returns Shield's answer unchanged.
- If Shield cannot be reached, it answers with the fleet's `on_unreachable`
  decision itself.

**Heartbeat:** reports `agent_hooks.claude_code.state` as in section 3.

**Why a command hook to the local agent, and not an HTTP hook to Shield:**

- The device key is in the System keychain or DPAPI and is readable only by
  root or SYSTEM. Claude Code's hook runs as the user. Going through the
  agent keeps the key where it is.
- Only a command hook can deny when nothing answers. #460 showed that an
  HTTP hook lets the call through when it times out or fails.

## 5. Security & backward compatibility

- **Opt-in per fleet; the default is off.** Existing tenants, fleets and
  agents see no change until an admin sets a mode. Agents older than 0.2.0
  ignore the new bundle field (verified in task 0) and install nothing.
- **No new secrets on laptops.**
  - The device key stays in root or SYSTEM storage.
  - The hook authenticates to the local agent with the existing local
    secret.
  - A local process that reads that secret can ask the agent for hook
    decisions. It gets the same allow or deny Claude Code would get, and
    nothing else.
- **The bundle is signed.** The agent writes Claude Code settings only from
  a bundle that verifies against the pinned key, so no one can push
  settings to laptops without Shield's signing key.
- **Settings someone else manages are never overwritten.** Section 7
  describes the conflict rule; it is the same rule as #460's install script.
- **Device lookup cache.** A revoked device key keeps working on the hook
  route only, for up to 30 seconds after revocation. Every other device
  route keeps checking the store on each call, as today. Recommended,
  because the alternative costs three store reads on every Claude Code
  tool call.
- **Escape hatches:**
  - `SHIELD_RUNTIME_POLICY=off` (as in #460) makes the hook route answer
    `{}`.
  - `SHIELD_DEVICE_AGENT_HOOKS=off` makes the bundle carry `off` for
    every fleet, so agents remove what they installed.
- **Unchanged:** the standalone path (#460) and tenant-key callers.

## 6. Packaging & deploy

- **Server:**
  - Changes in `core/dlp/device_policy.py`, `core/dlp/devices.py`
    (`DEVICE_PATHS`) and `api/routes_hooks.py`.
  - New routes in `api/routes_hooks_portal.py` (already in
    `Dockerfile.admin`).
  - Portal changes in `static/tenant.html`.
  - If a new module is imported by `admin_app.py`, it is added to
    `Dockerfile.admin`; the import guard test enforces this.
- **No new pip dependency.** The agent uses only the standard library for
  this feature.
- **Device agent 0.2.0:**
  - `agent_hooks.py`, the local API route and the bundled hook scripts.
  - Rebuilt and signed macOS `.pkg` and Windows `.msi`, published to the
    release location the rollout kit points at.
  - Existing kits pick up 0.2.0 through the agent's normal update path, or
    IT pushes the new installer once. The release note says which.
- **Docs:**
  - `docs/claude-code-runtime-guardrails.md` is rewritten around "turn on
    per fleet".
  - The standalone steps move into a "Without the Votal agent" section.
- **Deploy order:** server first, then the agent release. The new bundle
  field is ignored by older agents, and the hook route keeps accepting
  tenant keys.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| A Claude Code managed settings file exists that the agent did not write | Not touched. Heartbeat `conflict`; the portal shows the hooks block to merge. The agent rechecks on every sync and takes over only if the file is removed. |
| An admin edits the agent-written file by hand | The checksum no longer matches. Treated as `conflict` from then on; never overwritten. |
| The agent is stopped or crashed | The hook script cannot reach `127.0.0.1:47823`. `ON_UNREACHABLE=deny` denies; `allow` lets the call through with a warning. |
| The laptop is offline | The agent answers with the fleet's `on_unreachable`. |
| The fleet is switched from enforce to off | The hook route answers `{}` for that fleet straight away. At the next sync the agent rewrites its settings file to `{}`, and running sessions drop the hook (task 0: a removed hook stops applying within one call). |
| A fleet is turned on for the first time | Claude Code sessions started after the agent's next sync are checked. Sessions already running are not, until they restart, because they ignore a settings file that appears mid-session (task 0). The portal says so when a fleet is switched on. |
| The device key is revoked | Hook calls fail within 30 seconds (section 5). The agent then follows `on_unreachable` and reports the revocation, as it does today. |
| `/enable` meets an agent bound to another profile | 409 with the current profile; nothing changes unless `replace_binding`. |
| `/enable` meets an existing profile with the template's name | Used as it is, never overwritten. |
| An older agent (below 0.2.0) gets the new bundle field | Ignored (task 0 verifies this). The portal shows those laptops as "agent too old" from the heartbeat's agent version. |
| Monitor mode | Every call answers `{}`. The decisions are recorded as `monitor: true`, so the portal and SIEM show what enforce would have done. |
| Store down during the device lookup | As for other device routes: an error, so the agent follows `on_unreachable`. |

## 8. Test plan (Definition of Done)

**Server**
- Device policy:
  - `claude_code` validates strictly;
  - `for_fleet` resolves one fleet;
  - a missing field means off;
  - the escape hatch forces off.
- Hook route with a device key:
  - tenant, device and fleet come from the record;
  - off, monitor and enforce behave as specified;
  - monitor records the would-be decision;
  - a revoked key is refused, with a test that freezes time across the
    30-second cache;
  - a tenant key behaves exactly as in #460.
- `/enable` cases:
  - creates the profile and the agent;
  - keeps an existing profile;
  - binds an existing agent that has no profile;
  - 409 on another binding;
  - `replace_binding` true;
  - idempotent.
- `/fleets`: round trip, validation errors, and the per-fleet counts.

**Portal**
- A wiring test for the card and the Agent Registry dropdown (element ids
  match the routes).
- Escaping of everything laptops report.
- The URL default order.

**Device agent**
- Apply and remove the settings for each mode.
- The conflict rule: a foreign file, and a hand-edited file.
- Checksum bookkeeping.
- The local route: secret, origin and host checks; forwarding with the
  device key; `on_unreachable` both ways.
- Heartbeat states.
- The hook script's two new settings, run under `sh` and `dash` as in #460.

**End to end**
- On a real Mac with agent 0.2.0 enrolled into a test fleet: enforce denies
  `openssl enc` with the reason shown; monitor allows it and records it;
  `deny` on unreachable blocks when the agent is stopped.
- The same on a Windows machine. This is the first real run of the
  PowerShell hook.

**Suite:** full suite green in a clean venv; CI `pytest` passes; the device
agent's own tests pass.

## 9. Task 0 results (2026-10-04)

| Check | Result |
|---|---|
| Device agent 0.1.0 and a bundle carrying `claude_code` | **Ignored safely.** A bundle signed with the field verifies and loads, the field is carried unused, and prompts are screened as before. Checked with the agent tests' own signing helpers. |
| A running session and a hook **added** to a settings file that already exists | **Applied live.** In a 5-write session, a hook added after write 2 checked writes 3 to 5. |
| A running session and a hook **removed** | **Applied live.** With the hook removed after write 2, only writes 1 and 2 were checked. Deleting the file also took effect, about one call later. |
| A running session and a settings file that **appears** mid-session | **Ignored** until restart. None of the 5 writes was checked. Hence the agent keeps its file once written (section 4.5) and the first-time row in section 7. |
| The same three on the **managed** settings path | Pending: needs `sudo`. The owner runs `task0_managed.sh`, which also answers the `disableAllHooks` question from #460. The rows above were measured on project settings, which Claude Code watches with the same mechanism. |
| Windows: the shell that runs a command hook, and `\|\| exit 2` | Pending: needs a Windows machine. The owner runs `task0_windows.ps1`. |

Method: real Claude Code 2.1.104 with its model replaced by a local scripted
API (as in #460), harmless file writes only.

## Tasks

One branch per task, each a PR, in order.

0. **Verify, no code.**
   - Claude Code picks up a managed settings file written while it is
     running (new sessions).
   - On Windows, how Claude Code runs a command hook, and whether
     `|| exit 2` works there. Needs a Windows machine.
   - Whether a user setting can switch off a managed hook (`test_managed.sh`
     from #460). The owner runs it.
   - That device agent 0.1.0 ignores an unknown bundle field.
1. **Server:**
   - `claude_code` in the device policy and bundle;
   - device keys on the hook route, with the lookup cache;
   - fleet modes and monitor records;
   - the escape hatch;
   - tests.
2. **Portal and admin API:**
   - `/enable` and `/fleets`;
   - the card (status, fleets table, laptops with state, standalone section,
     URL default);
   - the Agent Registry runtime profile dropdown;
   - tests.
3. **Device agent 0.2.0:**
   - `agent_hooks.py`;
   - the local route;
   - the hook script settings;
   - heartbeat state;
   - tests.
4. **Release and docs:**
   - signed `.pkg` and `.msi` published;
   - the guide rewritten;
   - the end-to-end checks on a real Mac and a real Windows machine.
