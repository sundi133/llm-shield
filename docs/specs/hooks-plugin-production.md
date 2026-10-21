# Spec: Shield hooks for Claude Code and Cowork, production ready

Status: DRAFT, awaiting approval. Extends `agent-hook-adapter.md`,
`agent-hooks-tool-policies.md`, `agent-hooks-prompt-check.md` and
`claude-code-fleet-rollout.md`.

## 1. Problem and outcome

The `votal-shield-hooks` plugin (examples/agent-hooks/plugin, 1.1.0) applies a
customer's Shield policies to every Claude Code and Cowork tool call. The checks
themselves work (verified live in #470, #471). What is not ready is everything
around them: a developer can switch it off or point it somewhere harmless, the
laptop credential is too strong, there is no release to install from, and two
platforms were never run.

Findings, each checked in code or on production on 2026-10-21:

| # | Finding | Evidence |
|---|---|---|
| F1 | The plugin reads a **user-owned** config: `--config "$HOME/.votal/hook.conf"`. The user can set `ON_UNREACHABLE=allow`, or `SHIELD_URL=http://localhost:<port>` (the script accepts localhost "for testing") with a local responder that answers `{}`, and every call is allowed | `plugin/votal-shield-hooks/hooks/hooks.json`, `claude_code_hook.sh:137-180` |
| F2 | The user can set `SHIELD_AGENT` to an id with no runtime profile; Shield then allows everything ("agent has no runtime profile") | `core/runtime_policy/hooks.py:240`, `api/routes_hooks.py:101-107` |
| F3 | The hook route accepts any tenant key, and production does not enforce `SHIELD_CONFIG_WRITE_SCOPE`: a laptop key could change or switch off the tenant's policy | scenario run S11 (HTTP 200 on a policy write with a serving key) |
| F4 | One line in the user's settings, `"disableAllHooks": true`, switches the hooks off; this is the state of the author's own laptop today | `~/.claude/settings.json` |
| F5 | The plugin files and the script live under the user's home, so the user can edit the script itself | plugin install location |
| F6 | No release: `package_for_bucket.py` prints upload commands and uploads nothing; the device-agent install path (#461) has never published a release | `plugin/package_for_bucket.py` |
| F7 | macOS and Linux only: the plugin runs `/bin/sh`; `claude_code_hook.ps1` has never run on Windows and is not in the plugin | `hooks.json`, memory of #461 |
| F8 | Cowork never verified live; the README itself warns Cowork may not see `~/.votal/hook.conf` | `examples/agent-hooks/README.md` section 6 |
| F9 | When Shield is unreachable, results reach the model unredacted and prompts go through (`ON_UNREACHABLE_RESULT=allow`, `ON_UNREACHABLE_PROMPT=allow`) | `claude_code_hook.sh:74-76` |
| F10 | An admin cannot tell a laptop that stopped calling Shield from a compliant one: silence looks the same as nothing to block | no per-device last-seen record |

**Outcome.** A customer's security admin rolls Shield hooks out to a fleet
from a pinned, hosted release and an MDM kit, on macOS, Windows and Linux,
such that:

1. a developer without admin rights cannot switch the hooks off, edit the
   script, change the config, or pick an agent id that has no policy;
2. the laptop credential can only screen calls; it cannot read or change
   policy;
3. regulated customers get fail-closed defaults for calls, results and prompts;
4. the admin sees, per laptop, when Shield last heard from it, with which
   version and in which mode, and which laptops went quiet.

Two delivery modes, stated plainly in the customer guide:

| Mode | For | Tamper resistance |
|---|---|---|
| **Managed** (MDM): root-owned script and config, hooks in Claude Code managed settings | Fleets, regulated customers | Yes, subject to task 0 |
| **Plugin** (self-install, Cowork) | Trials, individual developers, Cowork | No: the user can remove it. Detected by F10 coverage, not prevented |

**Non-goals.** Claude.ai chat with connectors (runs no hooks). A Codex plugin
(Codex keeps its settings-file hooks). A deterministic rule for email
recipient domains (separate spec). Releasing the Votal device agent. Changing
what the policy checks decide.

## 2. Plane and latency contract

- **Data plane** (`core/app.py`): `/v1/shield/hooks/claude-code` and
  `/codex`, the coding-agent guard path. Changes there:
  - key binding and the no-profile refusal (section 5): one in-memory read of
    the key record, which the auth middleware already loads;
  - coverage labels: three more fields on the existing `hook_seen` record,
    written in the existing background task.
  - Latency budget: **under 1 ms added to the hook's answer.**
- **Admin plane** (`admin_app.py`): the coverage read endpoint and portal card,
  in `api/routes_hooks_portal.py`, which is already in `Dockerfile.admin`. Off
  the hot path, no guarded-traffic impact.
- **Laptop:** the hook script. No new process or dependency.

## 3. Data model

| Key | Shape | TTL | Notes |
|---|---|---|---|
| `hook_seen:{tenant_id}` (existing hash, `core/runtime_policy/hook_seen.py`) | field `{agent}\|{device or user}` -> the existing record plus `"hook_version": "1.2.0"`, `"hook_mode": "managed\|user\|unknown"`, `"hook_os": "darwin\|linux\|windows\|unknown"` | none (as today) | Built in task 2. Reused rather than a second hash: it already records each laptop's last call, written after the answer, at most once a minute per laptop unless the decision changes. Per-event counts dropped |
| tenant API key record (existing) | new optional field `"agent": "<agent id>"` | n/a | Set when the key is registered for a fleet; see section 5 |
| tenant config (existing) | new optional `"hooks": {"require_profile": bool, "stale_after_hours": int}` | n/a | `require_profile` defaults to false (section 5) |

- **Tenant scoping:** the tenant always comes from the credential, never from
  a header or body. Device and user come from the script's headers and are
  labels for the admin, not trust decisions.
- **Write cost:** unchanged: `hook_seen` already writes at most once a minute
  per laptop, in a background task.

## 4. API and interface

**Script to Shield (data plane), new request headers:**

- `X-Votal-Hook-Version: 1.2.0`
- `X-Votal-Hook-Mode: managed|user` (managed when the config read is owned by root and writable by no one else; `user` for a self-install, plugin or settings file)
- `X-Votal-Hook-OS: darwin|linux|windows`

Unknown or missing values are recorded as `unknown`, never refused.

**Admin plane:**

| Method and path | Auth | Answer |
|---|---|---|
| `GET /v1/tenant/me/hooks/coverage?stale_after_hours=24&limit=200&cursor=` (task 3) | portal session or tenant settings key | `{"devices":[{"agent","device","user","last_seen","version","mode","os","stale":bool}], "stale_count", "next_cursor", "truncated"}`, read from `hook_seen`. The existing `GET /v1/tenant/me/hooks/claude-code` already lists these rows |
| `POST /v1/tenant/me/hooks/claude-code/kit` (existing) | portal session or tenant settings key | gains `{"os": "macos\|windows\|linux", "tier": "standard\|regulated", "agent": "<id>"}`; returns `managed-settings.json`, `hook.conf` and an install script for that OS (section 6) |

**Portal:** a Coverage card on the coding-agent hooks page, listing laptops,
last seen, version and mode, with stale laptops first.

**Key registration:** `POST /v1/admin/tenants/{tenant_id}/api-keys` accepts an
optional `"agent"`, valid only with `"scope": "runtime"`. The tenant's own
`POST /v1/tenant/me/api-keys` accepts `"agent"` too and then mints a runtime
key bound to it: the one scope that route sets, since a bound runtime key is
strictly less than the unscoped key it mints otherwise.

## 5. Security and backward compatibility

| Change | Default | Escape hatch | Fixes |
|---|---|---|---|
| Managed mode in the script: if the OS path exists (`/Library/Application Support/Votal/hook.conf`, `/etc/votal/hook.conf`, `%ProgramData%\Votal\hook.conf`), use it and ignore `--config`; refuse it unless it is owned by root (Administrators on Windows) and not writable by group or others; refuse a localhost `SHIELD_URL` except the device-agent loopback with its secret | On whenever the OS file exists. Self-installs have no such file, so they are unchanged | none needed: an admin who installs the root file wants this | F1 |
| Plugin `hooks.json` drops `--config "$HOME/..."`, so the script picks the managed file first and falls back to the user file | User-file installs keep working | none | F1 |
| A key registered with `"agent"` is bound to it: the hook route uses that agent and refuses a different `X-Agent-Key` (403) | Only keys registered with `agent` | none (opt-in by registration) | F2 |
| `hooks.require_profile: true`: an agent with no runtime profile is denied, not allowed | **Off** (behaviour change); the kit turns it on for new fleets | set it false | F2 |
| The hook route refuses an **admin-scoped** tenant key (403, "use a runtime key on laptops") | **On**, behaviour change | `SHIELD_HOOKS_ALLOW_ADMIN_KEY=1` for one release; migration note in the guide | F3 |
| Unscoped legacy keys keep working on the hook route, with a `Warning` header and a portal notice | Warn only | n/a | F3 |
| Regulated tier in the kit: `ON_UNREACHABLE=deny`, `ON_UNREACHABLE_RESULT=withhold`, `ON_UNREACHABLE_PROMPT=block` | Kit option; the script's built-in defaults are unchanged | choose `standard` | F9 |
| Coverage labels on `hook_seen` | On, as `hook_seen` already is; labels only, never prompt or tool content | none needed (no new write) | F10 |

Ops actions, no code:

- set `SHIELD_CONFIG_WRITE_SCOPE=enforce`, `SHIELD_GUARD_REQUIRE_KEY=enforce`
  and `SHIELD_ENABLE_KILLSWITCH=true` on production (F3);
- rotate any laptop key that has admin scope.

**What a malicious user can and cannot do after this:**

- **Managed mode:** with no admin rights, the user cannot change the config,
  the script or the managed settings. They can still uninstall Claude Code and
  use another tool, which coverage then shows as a quiet laptop. Whether a
  user-level `disableAllHooks` or `allowManagedHooksOnly` affects managed and
  plugin hooks is **unverified**; task 0 decides it.
- **Plugin mode:** the user can remove or edit the plugin. That is documented
  as such, and visible in coverage as `mode: user`, stale or missing.
- **A stolen laptop key** can only screen calls for its bound agent. It cannot
  read or write policy, provided `SHIELD_CONFIG_WRITE_SCOPE=enforce` is set.

## 6. Packaging and deploy

- **No new Python dependencies.** The script still needs only `sh`, `curl`,
  `sed`, `tr`, `mktemp`; on Windows, PowerShell 5.1 or later with no modules.
- **Admin plane:** no new module; `api/routes_hooks_portal.py` is already in
  `Dockerfile.admin`. Any helper module it imports must be added there, and
  `tests/test_admin_dockerfile_imports.py` enforces that.
- **Release (task 5):** a GitHub Actions workflow on tag `hooks-plugin-v*`:
  - runs `package_for_bucket.py`, uploads the zip and `marketplace.json` to
    the bucket, pinned by sha256;
  - attaches the per-OS kit files to a GitHub release;
  - needs write access to the bucket, held only by the workflow's service
    account (the docstring's warning: whoever writes the zip runs code on every
    laptop).
- **MDM kit** (task 3), per OS:
  - the root-owned script and `hook.conf`;
  - `managed-settings.json` with the hooks pointing at the root-owned script
    and ending in `|| exit 2`;
  - an install script MDM runs as root (`install.sh`, `install.ps1`) that sets
    ownership and modes.
- **Images:** data plane and admin plane both rebuild (route changes on both).
- **Env flags:** `SHIELD_HOOKS_ALLOW_ADMIN_KEY`.

## 7. Failure modes and edge cases

| Case | Behaviour |
|---|---|
| Managed config present but owned by the user or group-writable | Treated as a broken setup: `fail()`, which denies before a call |
| Both managed and user config present | Managed wins; the user file is ignored |
| Redis down during coverage write | Write skipped, logged once a minute; the hook answer is unaffected |
| Coverage hash at the 5,000-field cap | Oldest pruned; `truncated: true` in the read |
| Bound key, header names another agent | 403 before any policy work; the script turns it into a denial |
| `require_profile` on, agent's profile deleted | Every call denied, with the reason "agent X has no runtime profile" (fail closed) |
| Old script (no version headers) | Recorded as `version: unknown`, `mode: unknown`; still served |
| Windows: PowerShell blocked by execution policy | The managed command uses `-ExecutionPolicy Bypass -File`; if PowerShell cannot start, the command's own fallback must exit 2 (task 0 confirms this exists on Windows) |
| Cowork cannot read the config | Fails closed with "hook config is missing"; the guide says to use the managed path Cowork can read, as found in task 0 |
| Clock skew on stale detection | Shield's clock only; laptops send no timestamps |

## 8. Test plan (definition of done)

**Task 0, verification gate.** No code; results written into this spec before
task 1 starts. Each item is a run on a real machine, recorded with the Claude
Code version.

- **V1:** managed-settings path and precedence on macOS, Windows, Linux.
- **V2:** with managed hooks installed, does a user `disableAllHooks: true`
  stop them? Does `allowManagedHooksOnly` stop plugin hooks, including a
  plugin enabled from managed settings?
- **V3:** can managed settings force-enable the plugin and its marketplace so
  the user cannot remove it, and is the plugin's install directory writable by
  the user?
- **V4:** Windows: which shell runs a command hook; does exit 2 block; does
  `|| exit 2` work; is `${CLAUDE_PLUGIN_ROOT}` expanded?
- **V5:** Cowork: does it run plugin hooks for all three events, and can the
  hook read `/Library/Application Support/Votal/hook.conf`?
- **V6:** a hook that times out, or exits non-zero other than 2: does the call
  run (it did on 2.1.104)?

Also needed for task 0: the Claude Code docs. They are currently blocked by the
author's own network allow-list (`code.claude.com` is not on it), so add it or
read them outside the profile.

**Results so far** (from the CI jobs that run the real Claude Code CLI,
`tests/test_claude_code_plugin_e2e.py`):

- **V4, answered for Claude Code 2.1.197 on Windows:** command hooks run in
  Git Bash (bash 5.3), and `${CLAUDE_PLUGIN_ROOT}` expands to a forward-slash
  path (`C:/Users/...`). The plugin's `/bin/sh` command runs there, and the
  script hands over to its PowerShell twin.
- **Also seen on the runner:** files an administrator creates in their own
  profile are owned by Administrators, so the hook judges that user's own
  `hook.conf` managed. That is consistent, since an administrator could change
  a managed file anyway, but it means a localhost Shield (testing only) is
  refused there.

**Tasks 1 to 5:**

- **Script:**
  - managed path chosen over `--config`;
  - an owner or mode violation fails;
  - localhost refused in managed mode;
  - headers sent;
  - every failure still exits 2 before a call.
  - The same cases for the `.ps1`, run in CI on `windows-latest` with `pwsh`
    and Windows PowerShell 5.1.
- **Route:**
  - a bound key with another agent gets 403;
  - `require_profile` denies an agent with no profile and allows one with a
    profile;
  - an admin-scoped key gets 403, and 200 with `SHIELD_HOOKS_ALLOW_ADMIN_KEY=1`;
  - an unscoped key gets the `Warning` header;
  - coverage is written in the background (the response does not wait);
  - coverage is skipped when Redis is down.
- **Coverage read:**
  - tenant isolation;
  - stale flag;
  - pagination;
  - 90-day prune;
  - 5,000-field cap.
- **Kit:**
  - each OS output parses;
  - the managed command ends in `|| exit 2`;
  - the regulated tier sets all three fail-closed values;
  - a drift test pins the kit's script to `core/runtime_policy/hook_scripts`.
- **Release:**
  - `package_for_bucket.py` output is reproducible (same sha256 twice);
  - `marketplace.json` pins it;
  - the workflow is dry-run on a fork tag.
- **Regression:**
  - `tests/test_agent_hooks_examples.py`, the hook script contract tests and
    `tests/test_portal_session_auth.py` stay green;
  - full suite green in a clean venv;
  - CI `pytest` passes.

## 9. Tasks (one PR each, in order)

| Task | Scope | Depends on |
|---|---|---|
| 0 | Verification gate V1 to V6; results recorded here; revise sections 5 to 7 if a result changes the design | Access to a Mac, a Windows VM, Cowork, and the Claude Code docs |
| 1 | Script hardening: managed path, owner and mode checks, no localhost in managed mode, version, mode and OS headers; plugin `hooks.json` without `--config $HOME`; `.ps1` parity; tests including Windows CI | 0 |
| 2 | Hook route: key binding (`agent` on runtime keys), `hooks.require_profile`, admin-key refusal with escape hatch, unscoped warning; coverage recording in the background | 1 |
| 3 | Admin plane: coverage endpoint and portal card; kit per OS and tier (managed settings with all three events, root config, install scripts including Windows); kit refuses keys the hook route would refuse; kit and device-agent timeouts raised to 25 s (script) and 30 s (hook) for model-judged rules; real-root installer runs in CI on Linux and Windows | 2 |
| 4 | Windows in the plugin and the kit: a Windows hook command (per V4), the `.ps1` shipped in the plugin, end to end on a Windows VM | 1, V4 |
| 5 | Release workflow to the bucket with sha256 pinning; plugin 1.2.0; customer guide `docs/claude-code-production-rollout.md` (managed vs plugin, migration note for admin keys, ops flags) | 3, 4 |

**Found while writing the guide (task 5), not yet built:** hooks installed
from a kit or the plugin always enforce. The tenant's monitor/enforce switch
(`policy_mode`) does not reach `/v1/shield/hooks/*` for a tenant key; only
Votal device agent fleets have a monitor mode. The guide says so and tells
admins to pilot with a small group. A follow-up could honour the tenant's
mode on the tenant-key path.

Ops, alongside task 2: the production flags and key rotation in section 5.
