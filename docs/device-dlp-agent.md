---
title: Device DLP agent
layout: default
nav_order: 71
permalink: /device-dlp-agent/
description: Check prompts to AI tools on Mac and Windows laptops before they leave the device, with your DLP rules and a small local model. Rolled out with Jamf, Kandji or Intune from one kit.
---

# Votal device agent: admin guide

The Votal device agent checks what employees send to AI tools (ChatGPT, Claude,
Gemini, Copilot, API clients and CLIs) on their Mac or Windows laptop, before it
leaves the laptop. It applies your DLP rules first, then a small AI model that
runs on the laptop (Tev1 0.8B), then your policy: allow, redact, ask for a
reason, or block.

Prompts are never sent to Votal for inspection. Laptops report the decision,
the category, the destination, the app, a hash and a length. Short excerpts
with sensitive values masked are opt-in.

## What you need

- **An MDM:** Jamf Pro or Kandji for Macs, Intune for Windows (and Macs).
- **Laptops:** macOS 13 or later, or Windows 10 or 11 (x64), with about 1.5 GB
  free disk and 1 GB free memory for the local model.
- **Shield set up for devices.** Your Shield administrator (Votal, if Votal
  hosts your Shield) sets these on Shield:

  | Setting | What it is for |
  |---|---|
  | `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` | Signs the policy laptops enforce. Without it laptops do not enroll. |
  | `SHIELD_DEVICE_CA_MASTER_KEY` | 64 hex characters (for example from `openssl rand -hex 32`). Each company's Mac root certificate is derived from it; no two companies share one. |
  | `SHIELD_DEVICE_AGENT_SHIELD_URL` | The https address laptops use to reach Shield. Rollout kits carry it. |
  | `SHIELD_BROWSER_EXTENSION_IDS` | Optional: the Votal browser extension, included in every kit. |

- **The browser extension is optional.** Without it, browser prompts are still
  checked by the agent's local proxy.

## Roll it out

### 1. Start in monitor mode

In the portal, open **Enterprise Controls, then Device DLP**. The DLP policy
starts in `monitor`: laptops record what they would have done and change
nothing. Leave it there until you have looked at the results. Rules come from
your Data Policies.

### 2. Restrict enrollment to your laptops (recommended)

A rollout kit contains an enrollment token, and once deployed it can be read on
the laptops it was deployed to. To make sure only your own laptops can enroll:

1. Export the computer or device list from your MDM as CSV. Any column whose
   header contains "Serial" is used.
2. Under **Company inventory**, upload the file.

A laptop whose serial number is not in the list is then refused, even with a
valid token, and the attempt raises an alert. Serial numbers are hashed on
arrival; Votal does not keep them as uploaded. Upload again when you add
laptops: each upload replaces the list. **Clear** turns the restriction off.

### 3. Download a rollout kit

Under **Rollout kits**, enter the fleet (for example `sales`) and choose the
MDM. For Intune, choose Windows, Mac or both. Then:

- **Include the proxy setting:** leave it on unless your laptops already have a
  proxy (PAC) configuration. The kit then gives you the lines to add to yours.
- **Laptops and days:** how many laptops the kit's token may enroll, and for
  how long (up to 365 days).

Click **Download rollout kit**. The zip contains a new enrollment token and is
its only copy: keep it like a password and delete it once uploaded.

### 4. Upload it to your MDM

The kit's `README.md` has the exact steps for your MDM. In short:

| MDM | Upload | Health check |
|---|---|---|
| Jamf Pro | the `.pkg` (a policy, once per computer) and `Votal-Device-Agent.mobileconfig` (a configuration profile) | extension attribute |
| Kandji | the `.pkg` (a Custom App) and `Votal-Device-Agent.mobileconfig` (a Custom Profile) | audit script |
| Intune, Windows | the `.msi` (a line-of-business app, with the arguments from `install-command.txt`) and the kit's platform scripts | remediation detection script |
| Intune, Mac | the `.pkg` (a macOS app) and `Votal-Device-Agent.mobileconfig` (a custom profile) | custom attribute |

The kit's `get-installer` script downloads the installer and checks that it is
the release's and signed by Votal before you upload it. The Mac profile holds
everything a Mac needs: the agent's settings, the root certificate, the proxy
setting, the browser extension, and a managed login item so employees cannot
turn the agent off. Order does not matter: the agent waits for its settings.

### 5. Watch laptops arrive

Laptops appear under **Devices** as they enroll, usually within minutes of the
installer and profile arriving, with their state, mode, agent version and last
heartbeat. A laptop that stops reporting (uninstalled, offline for a long time,
or tampered with) is marked stale after an hour. The kit's health check shows
the same in your MDM.

### 6. Turn on enforcement

When the monitor-mode results look right for a fleet, set it to `enforce` in
the DLP policy (`fleet_modes`, for example `{"sales": "enforce"}`). Laptops pick
it up at their next policy check, within about five minutes.

By default, even in enforce mode:

- Known secrets that match your rules are redacted before sending.
- Credentials and customer data the model finds with high confidence are
  blocked.
- Personal and health data ask the user for a reason, then allow the prompt
  once.
- Source code, financial data and data-exfiltration intent are recorded only.
  The local model does not catch them reliably enough to act on them.

## What employees see

| Situation | What happens |
|---|---|
| Nothing sensitive | Nothing. The prompt is sent as typed. |
| A secret your rules redact | The value is replaced (for example with `[AWS_KEY]`) and the prompt is sent. |
| Blocked | The AI tool shows an error: "Blocked by your company's AI data policy", with the reason. |
| Reason needed | The browser extension asks for a reason. Other apps show a link to a page on the laptop where the user gives one. The same prompt is then allowed once, within a minute. |

## Keeping it current

- **A new kit:** download one whenever you need it, for example when the token
  is running out. Tick **Revoke this fleet's earlier kits** to retire the old
  token. Upload the new profile over the old one (it has the same identifier).
  Laptops already enrolled are unaffected either way.
- **Kits marked out of date:** the list says why.
  - The root certificate was reissued: upload the profile from a new kit.
  - The policy has an AI service the root does not cover: download a new kit;
    it reissues the root for you.
  - A newer agent version exists: upload the new installer.
- **Revoking a kit** stops its token enrolling more laptops. Laptops it
  enrolled keep working; revoke any of them under **Devices**.
- **Reinstalling a laptop:** if its previous install reported in the last 24
  hours, revoke the old device first. Otherwise Shield refuses the new
  enrollment and raises an alert. This stops anyone who has read the token from
  taking over a colleague's laptop by claiming its serial number. After 24
  silent hours the old device is replaced automatically. To go back to
  replacing immediately, set `SHIELD_DEVICE_REENROLL_LIVE=replace` on Shield.

For day-to-day operation (leaked tokens, lost laptops, false blocks, emergency
rollback, outages, key rotation, upgrades), see the
[Device DLP runbook](/device-dlp-runbook/).

## Certificate trust on macOS

To inspect AI traffic, the agent needs a certificate that apps trust. Since
macOS 11, only an MDM profile can make a certificate trusted without the user
approving it. So Macs work like this:

- **Your company has one root certificate,** in the kit's profile. It is
  limited to the AI services in your policy: macOS refuses it for any other
  site.
- **Each Mac has its own certificate under that root.** It is valid for 7 days
  and renewed daily. The Mac creates its key and never sends it anywhere. A
  device you revoke gets no renewal, so its certificate stops working within a
  week.
- **If a Mac cannot renew for more than 7 days** (for example, long offline),
  AI traffic passes uninspected and this is recorded. If your policy's
  `fail_mode` is `block`, AI services are unreachable instead, until it
  renews.

Windows needs none of this: the agent trusts its own certificate on the laptop.

Apps that refuse the certificate are handled by the policy's
`pinned_host_action`: logged and passed through (the default), or blocked.

## Command-line tools and SDKs

CLIs and SDKs honour `HTTPS_PROXY` rather than the PAC file, and many use their
own certificate list. To cover them:

- Set `HTTPS_PROXY=http://127.0.0.1:47824`.
- Point `NODE_EXTRA_CA_CERTS` (Node, including Claude Code) or `SSL_CERT_FILE`
  (Python) at a bundle that includes the agent's certificate.

Traffic to other sites goes through the agent untouched and is never
decrypted.

## Uninstall

- **macOS:** run `packaging/macos/uninstall.sh` as root (Jamf and Kandji can
  run it as a script), then remove the profile.
- **Windows:** uninstall the app in Intune, and remove the proxy and extension
  settings the kit's scripts made.

Uninstalling removes the device key and the agent's certificate. Revoke the
device in the portal so its key stops working immediately.

## Troubleshooting

On a laptop, as an administrator, `verify` prints one line per check with the
reason for any failure:

- macOS: `sudo "/Library/Application Support/Votal/DeviceAgent/bin/votal-device-agent" verify`
- Windows: `"C:\Program Files\Votal\DeviceAgent\votal-device-agent.exe" verify`

| Check | If it fails |
|---|---|
| MDM settings | The profile (Mac) or install arguments (Windows) have not arrived, or a value is wrong; the line says which. Check the kit's scope in the MDM. |
| agent.json | The settings have not been written yet. It appears once the MDM settings arrive. |
| enrolled | The line gives the reason. "Invalid or expired enrollment token" or "no uses left": download a new kit. "Still reporting": the laptop's previous install is enrolled; revoke it and the agent enrolls within an hour. "Not in the company inventory": add the laptop's serial number to the inventory. |
| agent running | The agent service is not running. Check `/Library/Logs/Votal/agent.log` (Mac) or the service in Windows. |
| policy bundle | "fallback": the laptop cannot reach Shield, or the pinned key does not match this Shield. The laptop still redacts known secrets. |
| decision model | "model_unavailable": the local model is still downloading, or failed to; see `ollama.log` in the log folder. "model_mismatch": the model was not the one your policy pins; the agent removed it and downloads the right one when the service next starts. |
| local proxy | On a Mac it starts once the Mac has its certificate, so check "enrolled" first. |
| device CA trusted | On a Mac, the profile with the root certificate is missing or out of date: upload the one from a current kit. |
| browser extension host | The extension ids in the kit do not match the installed extension. |
| audit chain | The local decision log was altered. Report it: this is a tamper signal. |

## Privacy

- The agent reads prompts only for AI services in your policy.
- It sends Votal a verdict, category, destination, app, device, time, and the
  prompt's hash and length.
- It never sends the prompt text. Excerpts (the first 200 characters, with
  every rule match masked) are off unless you turn on `capture_excerpt`.
- Decisions are kept on the laptop in a tamper-evident log until they are
  uploaded.

## Setting up without a kit

For another MDM, or to build the configuration yourself, the pieces a kit
contains are in `packages/votal-device-agent/packaging/`:

- **macOS:** profile templates in `macos/mdm/` for settings, proxy and
  extension. The root certificate profile is under **MDM settings** in the
  portal. The values (Shield URL, tenant, pinned key) are shown there too.
- **Windows:** the MSI takes the settings as properties
  (`SHIELDURL`, `TENANTID`, `FLEET`, `PINNEDPUBLICKEY`, `ENROLLMENTTOKEN`,
  `EXTENSIONIDS`), written to `HKLM\SOFTWARE\Policies\Votal\DeviceAgent`, and
  `windows/intune/set-pac.ps1` sets the proxy.
- **Tokens:** create them under **Enrollment tokens** (up to 90 days; kits allow
  365).
