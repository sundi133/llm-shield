---
title: Device DLP runbook
layout: default
nav_order: 72
permalink: /device-dlp-runbook/
description: Day-to-day operation of the Votal device agent after rollout, with step-by-step procedures for leaked tokens, lost laptops, false positives, emergency rollback, outages, key rotation and upgrades.
---

# Device DLP runbook

For the admins who run the Votal device agent once it is rolled out. Setting
it up is in the [admin guide](/device-dlp-agent/). Every procedure here says
what to do, how long it takes to take effect, and what to check afterwards.

In the portal, everything is under **Enterprise Controls, then Device DLP**
unless stated.

## How fast changes reach laptops

| Change | Reaches a laptop |
|---|---|
| DLP policy (mode, rules, categories, thresholds) | At its next policy check, within about 5 minutes when online |
| Revoking a device | At once, on every Shield server |
| Revoking a kit or token | At once: no further enrollments |
| A new MDM profile or installer | When the MDM delivers it (minutes to hours; laptops must be online and checked in) |
| A new pinned signing key in the profile | After the agent restarts on that laptop |
| An offline laptop | Keeps its last policy: fully for 24 hours, then for 7 days of grace (reported as a stale policy), then only redacts known secrets |

## Routine checks

| How often | Check | Where | Act when |
|---|---|---|---|
| Daily | Stale devices | Devices (the count at the top) | A laptop is stale that should be online: see "A laptop stopped reporting" |
| Daily | Refused enrollments | The decision audit (see Reference) or your SIEM: events "device enrollment refused" | Any: see "Alert: enrollment refused" |
| Weekly | Kits running out | Rollout kits: laptops left and expiry | Under 10 % left, or expiring within 30 days: download a new kit |
| Weekly | Out-of-date kits | Rollout kits: the warning under the status | Any: follow the warning |
| Weekly | Model health | Devices: the Model column and states | Laptops in `model_unavailable` or `model_mismatch`: see "Many laptops cannot use the model" |
| Weekly | Blocks and reasons requested | The decision audit | A rule or category blocking good work: see "Users report a false block" |
| After adding laptops | Company inventory | Company inventory | Upload the MDM's latest export |

## Alert: enrollment refused

Shield refuses an enrollment, and raises a high-severity event, when:

| The event says | Meaning | Do |
|---|---|---|
| "a device ... with this serial is still reporting" | Someone enrolled with the serial of a laptop that reported in the last 24 hours | If you reinstalled that laptop: revoke its old device; it enrolls within an hour. If not: treat as an attempt to take over a colleague's laptop, and see "An enrollment token leaked" |
| "... is not in the company inventory" | A laptop outside your inventory tried to enroll | A new laptop: upload the latest MDM export. Unknown host name: see "An enrollment token leaked" |

The event names the claimed host name, the fleet, and the kit token it used.

## An enrollment token leaked

A rollout kit, its profile, or the Windows install arguments were exposed, or
you see enrollments you cannot explain.

1. **Stop the token.** Rollout kits (or Enrollment tokens), **Revoke**. Effect:
   at once. Laptops it already enrolled keep working.
2. **Find what it enrolled.** `GET /v1/tenant/me/devices` lists every device
   with `enrollment_token_id` and `enrolled_at`. The kit list shows the kit's
   `token_id`. Revoke any device you do not recognise.
3. **Close the gap.** Upload your MDM's serial export to Company inventory, if
   you have not, so only your laptops can enroll.
4. **Replace the kit.** Download a new kit for the fleet with **Revoke this
   fleet's earlier kits** ticked, and upload its profile (Mac) or install
   arguments (Windows) over the old ones.

Check afterwards: no new unexpected devices over the next days, and
refused-enrollment alerts for anything still using the old token.

## A laptop is lost or stolen, or an employee leaves

1. **Revoke the device** under Devices. Its key stops working at once: it can no
   longer fetch policy, renew its certificate or report.
2. **Remove it from the inventory:** upload the MDM export without it.
3. **Wipe or retire it in your MDM,** as for any company laptop.

What remains: a Mac keeps its own AI-only certificate until it expires, at most
7 days after its last renewal. Someone holding the laptop and able to intercept
a colleague's network traffic could use it against AI services only, within
that window. It cannot be used for any other site.

## A laptop stopped reporting

A device shows as stale after an hour without a heartbeat.

1. **Is it on?** Asleep, shut down or offline laptops go stale. They report again
   when back online.
2. **On the laptop, run `verify`** (see Reference) and follow the admin guide's
   troubleshooting table.
3. **Logs:**
   - macOS: `/Library/Logs/Votal/agent.log` and `ollama.log`.
   - Windows: `C:\ProgramData\Votal\DeviceAgent\logs\`, and the Votal Device
     Agent service in Services.
4. **Reinstall if needed.** If it reported in the last 24 hours, revoke the old
   device first, then reinstall through the MDM.

A laptop whose agent was stopped or removed by a local administrator shows the
same way. The heartbeat is how you see it: this is detection, not prevention.

## Users report a false block

1. **Find the decision** in the decision audit: the reason names the rule, or
   the category the local model found.
2. **Fix the cause, from narrowest to widest:**
   - **A rule** (the reason names it): adjust it in Data Policies.
   - **A model category:** in the DLP policy, set that category's
     `enforcement` to `monitor`; it is then recorded, never enforced.
     Categories: credentials, personal data, customer data, health, source
     code, financial, exfiltration intent.
   - **Blocking too eagerly:** raise `block_p`, or remove the category from
     `block_categories` so it asks for a reason instead of blocking.
   - **Too many reasons asked for:** raise `justify_p`.
3. **Meanwhile,** users can give a reason when asked, and the prompt is sent
   once. A block from a rule cannot be overridden this way, by design.

The policy editor validates every change before saving.

## Turn enforcement off now

When blocking is disrupting work and you need it off before you understand
why:

1. **In the DLP policy,** set `mode` to `monitor`. If a fleet has its own entry
   in `fleet_modes`, set that to `monitor` too, or remove it.
2. **Save.** Online laptops switch within about 5 minutes; everything is still
   recorded.

To stop inspecting AI traffic altogether, the last resort:

- Remove the proxy setting: on Mac, remove the kit's profile, or use a kit
  generated without the proxy setting; on Windows, delete the machine's
  `AutoConfigURL`.
- Or set `SHIELD_DEVICE_AGENT=off` on Shield to stop new enrollments.

## Shield is unreachable

Laptops keep enforcing without Shield:

- They keep their last policy for 24 hours, then 7 days of grace, then only
  redact known secrets.
- Decisions queue in the laptop's local log and upload when Shield is back.
- Enrollment and certificate renewal wait.

After an outage, devices may show as stale until their next heartbeat, a few
minutes after Shield returns. No action is needed.

## Many laptops cannot use the model

`model_unavailable` or `model_mismatch` on many devices.

- **The rules still apply:** known secrets are still redacted and rule blocks
  still block. If `fail_mode` is `block`, AI services are blocked instead while
  the model is unavailable.
- **`model_unavailable`:** usually the laptop could not download the model
  (812 MB, on first start). Check `ollama.log`, disk space, and whether the
  network allows the download.
- **`model_mismatch`:** a laptop has a model that is not the one your policy
  pins. The agent deletes it at once and downloads the pinned one when the
  service next starts. Restart the service (see Reference) to do it now.

## An AI service is added to the policy

1. **Add the host** to `ai_hosts` in the DLP policy. Windows laptops and the
   proxy pick it up within minutes.
2. **For Macs, download a new kit.** It reissues the root certificate to cover
   the host. Upload its profile. Until the new profile arrives, that host is
   not inspected on Macs.

## Upgrade the agent

1. **Read the release notes** for the new version (Votal device agent releases on
   GitHub). A signed release is required for Intune on Mac.
2. **Download a kit, then the installer.** Once your Shield offers the new
   version, download a new kit; its `get-installer` script fetches and checks
   the new installer. Your Shield administrator can pin a version with
   `SHIELD_DEVICE_AGENT_VERSION`.
3. **Upload the installer to your MDM** as an update to the existing package or
   app, scoped as before. Profiles do not need to change.
4. **Check** the Agent column under Devices as laptops update.

## Rotate the enrollment token

Kits last up to 365 days. Before a kit expires or runs out:

1. Download a new kit with **Revoke this fleet's earlier kits** ticked.
2. Upload its profile (Mac) or install arguments (Windows).

Enrolled laptops are not affected. Only laptops that have not enrolled yet
need the new token.

## Rotate Shield's keys

These are Shield administrator operations. They are rare, and each has an
effect on laptops; plan them.

**The policy signing key** (`SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY`) is pinned on
every laptop.

1. Change it on Shield.
2. Download a new kit for every fleet, and upload the profiles and install
   arguments.
3. Restart the agent on laptops with an MDM script (see Reference). The pinned
   key is read when the agent starts.

Until a laptop has the new profile and has restarted, it refuses the new
policy and keeps the last one it verified: fully for 24 hours, then 7 days of
grace. No protection is lost if you finish within about a week. The same key
signs robot and runtime-profile bundles; coordinate with their owners.

**The device CA master key** (`SHIELD_DEVICE_CA_MASTER_KEY`) is Macs only.

1. Change it on Shield.
2. Reissue the root (the Reissue root button under MDM settings, or
   `POST /v1/tenant/me/devices/root-ca/reissue`).
3. Download new kits and upload the profiles.

Until a Mac has both the new root profile and a renewed certificate (renewal
is daily), apps on it may refuse the agent's certificate for AI services. They
are then passed through uninspected for an hour at a time, and each one is
recorded. Expect up to a day of reduced inspection on Macs.

## Remove the agent from a fleet

1. **Uninstall through the MDM:**
   - Mac: run `packaging/macos/uninstall.sh` as a script, then remove the
     profile.
   - Windows: uninstall the app in Intune and remove the proxy and extension
     settings.
2. **Revoke the fleet's kits and devices** in the portal.
3. **Clear the company inventory** if no fleet uses it.

## Reference

**On a laptop**

| | macOS | Windows |
|---|---|---|
| Check everything | `sudo "/Library/Application Support/Votal/DeviceAgent/bin/votal-device-agent" verify` | `"C:\Program Files\Votal\DeviceAgent\votal-device-agent.exe" verify` (as administrator) |
| Agent's own view | same, with `status` | same, with `status` |
| Restart the agent | `sudo launchctl kickstart -k system/ai.votal.device-agent` | `Restart-Service VotalDeviceAgent` |
| Logs | `/Library/Logs/Votal/` | `C:\ProgramData\Votal\DeviceAgent\logs\` |
| Settings from MDM | `/Library/Managed Preferences/ai.votal.device-agent.plist` | `HKLM\SOFTWARE\Policies\Votal\DeviceAgent` |
| Local ports | 47823 (local API and PAC), 47824 (proxy), 11535 (the agent's own Ollama) | same |

**Shield APIs** (tenant key; writes need an admin key when the registry write
gate is enforced)

| Purpose | API |
|---|---|
| Devices, with enrollment token and times | `GET /v1/tenant/me/devices` |
| Revoke a device | `DELETE /v1/tenant/me/devices/{device_id}` |
| Kits | `GET`, `POST /v1/tenant/me/devices/rollout-kits`; `DELETE .../{kit_id}` |
| Company inventory | `GET`, `PUT`, `DELETE /v1/tenant/me/devices/inventory` |
| Mac root certificate | `GET /v1/tenant/me/devices/root-ca`; `POST .../root-ca/reissue` |
| DLP policy | `GET`, `PUT /v1/tenant/me/dlp-policy` |
| Decision audit (blocks, refusals) | `GET /v1/shield/decisions/{tenant_id}?guardrail=runtime_boundary&tool_name=runtime:dlp` |
