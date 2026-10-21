---
title: Claude Code rollout for production
layout: default
nav_order: 32
permalink: /claude-code-production-rollout/
description: Roll Votal Shield checks out to every developer laptop running Claude Code or Cowork, so tool calls, tool results and prompts are checked by your policies, in a way developers cannot switch off, with coverage that shows which laptops went quiet.
---

# Claude Code rollout for production
{: .no_toc }

Votal Shield checks Claude Code and Cowork at three points: **before each tool
call** (a call your policy forbids never runs), **after it** (secrets and
personal data in the result are redacted before the model reads them) and **on
each prompt** (a request your policy forbids never reaches the model). This
guide is for the administrator rolling that out to a fleet.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Two ways to deploy

| | Managed (MDM) | Plugin |
|---|---|---|
| For | Fleets, regulated customers | Trials, single developers, Cowork |
| How | Your MDM runs the installer from the Votal portal | `claude plugin install`, or an upload in Cowork |
| Config | Root-owned (`/Library/Application Support/Votal/hook.conf`, `/etc/votal/hook.conf`, `C:\ProgramData\Votal\hook.conf`); developers cannot change it | `~/.votal/hook.conf`, which its owner can edit |
| Can a developer remove it | Not without administrator rights | Yes |
| Shows in the portal as | **managed** | **user install** |

Use managed for anything you rely on. A plugin install can be removed; the
coverage view shows when that happens, but it does not prevent it.

When a managed config is installed, the hook reads it whatever a plugin or
settings file passes, and it refuses every call if anyone but root
(Administrators on Windows) owns it or can write it.

Supported: macOS, Linux, and Windows with Git for Windows (Claude Code itself
needs it). On Windows, Claude Code runs the hook command in Git Bash and the
hook hands over to its PowerShell version, which checks Windows permissions.
This is tested on every change with the real Claude Code CLI on Linux and
Windows.

## Before you start

1. **Policies.** In the portal, **Runtime Profiles**, the **coding-agent-baseline**
   profile is a starting point. Turn on the checks you want in its
   `tool_policies` (before the call, after it, on the prompt) and write your
   Tool Registry rules and input policies.
2. **Agent.** In **Agent Registry**, the agent your laptops use (for example
   `claude-code`) must have that runtime profile.
3. **A laptop key.** The key is readable on every laptop, so mint a runtime
   key bound to the agent, with your settings key or a signed-in admin:

   ```bash
   curl -s -X POST https://shield.votal.ai/v1/tenant/me/api-keys -H "X-API-Key: $SETTINGS_KEY" -H "Content-Type: application/json" -d '{"label": "laptops", "agent": "claude-code"}'
   ```

   Whoever reads this key off a laptop can only screen calls, as that agent.
   Shield refuses an admin-scoped key on laptops.
4. **Optional, from Votal:** deny any agent that has no runtime profile, and set
   when a laptop counts as quiet:
   `PUT /v1/admin/tenants/{tenant_id}` with
   `{"hooks": {"require_profile": true, "stale_after_hours": 24}}`.

## Managed rollout

1. **Build the kit.** In the portal, **Runtime Profiles**, card **Coding agents
   on laptops**, open **Laptops without the Votal agent**:
   - **Hook:** Fail-closed (a script that denies when Shield cannot answer).
   - **Operating system:** one kit per OS.
   - **Tier:** **Regulated** also withholds tool results and blocks prompts
     when Shield cannot answer; **Standard** only denies tool calls then.
   - **Shield URL:** `https://api.guardrails.votal.ai` (not the portal's).
   - **Key:** the laptop key from step 3. Build files refuses a key Shield would
     refuse, and the key is not stored.
2. **Deploy** with your MDM:

   | OS | Run | As |
   |---|---|---|
   | macOS | `install-votal-claude-code.sh` (or the `.mobileconfig` plus the script) | root, for example a Jamf or Kandji policy script |
   | Linux | `install-votal-claude-code.sh` | root |
   | Windows | `install-votal-claude-code.ps1` | Administrator, for example an Intune script |

   The installer writes the hook, its config and Claude Code's managed settings,
   with the permissions the hook checks. It never overwrites Claude Code
   managed settings someone else wrote: it stops and says so, and you merge
   its `hooks` and `allowManagedHooksOnly` keys into yours.
3. **Check one laptop.** Restart Claude Code there and ask for something your
   policy forbids: it is refused with "Blocked by Votal Shield". In the portal
   the laptop shows as **managed**, with the hook's version.
4. **Pilot, then widen.** A kit install enforces from the start: the tenant's
   monitor switch does not apply to these hooks (only laptops running the
   Votal device agent have a per-fleet monitor mode). So deploy to a small
   pilot group first, review their decisions in the decision audit
   (guardrail `runtime_boundary`), tune the profile, then widen.

## Plugin install (trials and Cowork)

Put the config at `~/.votal/hook.conf` (Windows: `%USERPROFILE%\.votal\hook.conf`):

```
SHIELD_URL=https://api.guardrails.votal.ai
SHIELD_API_KEY=<the laptop key>
SHIELD_AGENT=claude-code
SHIELD_TIMEOUT=25
```

**Claude Code** (2.1.224 or later):

```bash
claude plugin marketplace add https://storage.googleapis.com/votal-ai/claude-plugins/marketplace.json
```

```bash
claude plugin install votal-shield-hooks@votal-shield
```

The catalog pins the plugin's zip by its sha256, so Claude Code refuses a zip
that does not match. Each release is also on GitHub (tag `hooks-plugin-v<version>`)
with a `SHA256SUMS` file.

**Cowork:** upload the release's `votal-shield-hooks-<version>.zip` in
Organization settings, Plugins & skills. Cowork's behaviour has not yet been verified
end to end: try one task your policy forbids first. If every call is refused
with "hook config ... is missing", Cowork cannot read the config where it runs
its hooks.

Use the plugin **or** a settings-file install, not both, or every call is
checked twice.

## Watch coverage

The portal's **Laptops** list (and `GET /v1/tenant/me/hooks/coverage` for your
own monitoring) shows each laptop's last call, whether it is **managed** or a
**user install**, and its hook version and OS. A laptop that stops calling
Shield looks the same as one with nothing to block, so laptops quiet for
longer than the window (24 hours unless you change it) come first, marked
**stale**. A stale laptop has lost its hook, its route to Shield, or simply
not used Claude Code: check which.

## What developers can and cannot do

- **Edit or remove a managed install:** no, without administrator rights.
- **Point the hook at another Shield, or a local stand-in:** no. A managed
  install refuses any URL but https, and the key is bound to its agent.
- **Use an agent with a weaker profile:** no, with a bound key; with
  `require_profile` on, an agent with no profile is denied, not allowed.
- **Turn hooks off in their own settings (`disableAllHooks`):** the managed
  settings set `allowManagedHooksOnly`, which stops developers adding their
  own hooks. Whether a developer's `disableAllHooks` can switch off managed
  hooks is still being verified. Until then, watch for **stale** laptops.
- **Work outside Claude Code:** the hooks govern Claude Code and Cowork, not
  commands a person runs themselves, and not Claude in a browser.

## If you deployed before version 1.2.0

- **Admin-scoped keys are refused** on laptops (`Shield answered HTTP 403`).
  Mint a bound runtime key, swap it into `hook.conf`, and revoke the old one.
  Until you have, Votal can set `SHIELD_HOOKS_ALLOW_ADMIN_KEY=1` on the
  guardrail server.
- **Rebuild older kits.** Kits built before 1.2.0 checked tool calls only, and
  gave Shield 4 seconds, too short for rules Shield's model judges (they now
  wait 25 seconds, Claude Code 30). New kits register all three checks.
- **The managed config wins.** A `hook.conf` at the managed path is read
  whatever `--config` a settings file or plugin passes.

## Troubleshooting

What a developer sees after "Blocked by Votal Shield:", and what to do:

| Message | Cause | Fix |
|---|---|---|
| `... must be owned by root and writable by no one else` (Windows: `owned by Administrators`) | The managed config's permissions were changed | Rerun the installer |
| `SHIELD_URL must be https in a managed install` | A managed config points at an http address | Use `https://api.guardrails.votal.ai` |
| `Shield answered HTTP 403` | An admin-scoped key, or a key bound to another agent | Use a runtime key bound to this agent |
| `agent '...' has no runtime profile, and this tenant requires one` | `require_profile` is on and the agent has no profile | Give the agent a runtime profile in Agent Registry |
| `hook config ... is missing or unreadable` | No config where the hook looks | Install the config (managed path, or `~/.votal/hook.conf`) |
| `Shield could not be reached at ...` | No route to Shield, or Shield took longer than `SHIELD_TIMEOUT` | Check the laptop's network or proxy; tool calls are refused until it is back (results and prompts too, in the regulated tier) |
| `the Windows hook claude_code_hook.ps1 is missing` | A damaged plugin install on Windows | Reinstall the plugin |
