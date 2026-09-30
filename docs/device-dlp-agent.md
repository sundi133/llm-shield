---
title: Device DLP agent
layout: default
nav_order: 71
permalink: /device-dlp-agent/
description: Check prompts to AI tools on Mac and Windows laptops before they leave the device, with your DLP rules and a small local model. Deployed with Jamf, Kandji or Intune.
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

- A Shield deployment with policy-bundle signing configured
  (`SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY`). Without it laptops do not enroll,
  because they only accept signed policy.
- For Macs, a device CA secret: `SHIELD_DEVICE_CA_MASTER_KEY` (64 hex
  characters, for example from `openssl rand -hex 32`). Keep it with your other
  Shield secrets. Each tenant's root certificate is derived from it, so tenants
  never share one.
- An MDM: Jamf Pro, Kandji or Intune.
- Laptops:
  - macOS 13 or later, or Windows 10 or 11 (x64).
  - About 1.5 GB free disk and 1 GB free memory for the local model.
- The Votal browser extension, optional. Without it, browser prompts are still
  checked by the agent's local proxy.

## 1. Prepare in the Votal portal

Open **Enterprise Controls, then Device DLP**.

1. **MDM settings.** Copy `ShieldURL`, `TenantID` and `PinnedPublicKey`. The
   pinned key is how laptops tell your policy from anyone else's. Copy it from
   the portal into MDM and nowhere else.
2. **Enrollment token.** Create one per fleet (for example `sales`), with
   enough uses for the fleet and a short expiry. The token is shown once. You
   can revoke it early.
3. **DLP policy.** Start in `monitor`: laptops record what they would have done
   and change nothing. Rules come from your Data Policies.

## 2. Deploy on Mac (Jamf Pro or Kandji)

Files are in `packages/votal-device-agent/packaging/macos/`.

1. **Package.** Upload `votal-device-agent-<version>.pkg` and scope it to the
   fleet.
2. **Settings profile.** Edit `mdm/votal-device-agent-settings.mobileconfig`.
   Replace every `__PLACEHOLDER__` with the values from step 1, then upload it:
   - Jamf: Configuration Profiles, then Upload.
   - Kandji: Library, then Custom Profile.
3. **Proxy profile.** Upload `mdm/votal-device-agent-proxy.mobileconfig`. It
   sends only AI services to the agent (`http://127.0.0.1:47823/proxy.pac`);
   all other traffic goes direct. A Mac accepts only one proxy profile. If you
   already have one, add the PAC URL to it instead.
4. **Browser extension (optional).** Edit
   `mdm/votal-device-agent-chrome.mobileconfig` with your extension id, and add
   the same id to `ExtensionIDs` in the settings profile.
5. **Root certificate profile.** In the portal's MDM settings, click
   **Download macOS profile**, then upload it the same way. It lets the agent
   inspect AI services only. See "Certificate trust on macOS" below.

Order does not matter. The agent waits for its settings and enrolls when they
arrive.

## 3. Deploy on Windows (Intune)

Files are in `packages/votal-device-agent/packaging/windows/`.

1. **App.** Add `votal-device-agent-<version>.msi` as a line-of-business app.
   Its install command carries the settings:

   ```
   msiexec /i votal-device-agent-<version>.msi /qn SHIELDURL=https://api.guardrails.votal.ai TENANTID=acme FLEET=sales PINNEDPUBLICKEY=<64 hex> ENROLLMENTTOKEN=vde.acme.<secret> EXTENSIONIDS=<extension id>
   ```

   The settings are written to `HKLM\SOFTWARE\Policies\Votal\DeviceAgent`. You
   can instead set that key with an Intune configuration profile (custom
   OMA-URI) and install the MSI with no properties.
2. **Proxy.** Run `intune/set-pac.ps1` as a platform script (system context).
   It points the machine's proxy auto-configuration at the agent, for AI
   services only.
3. **Browser extension (optional).** Force-install it with the Chrome or Edge
   settings catalog.

On Windows, the agent adds its certificate to the machine's trusted roots
itself. Nothing more is needed.

## 4. Check a laptop

On the laptop, as an administrator:

- macOS: `sudo "/Library/Application Support/Votal/DeviceAgent/bin/votal-device-agent" verify`
- Windows: `"C:\Program Files\Votal\DeviceAgent\votal-device-agent.exe" verify`

It prints one line per check: settings, enrollment, agent running, signed policy,
local model, local proxy, certificate trust, browser host and audit log. The
exit code is 0 when every required check passes.

In the portal, **Devices** lists every laptop with its last heartbeat. A laptop
that stops reporting (uninstalled, offline for a long time, or tampered with)
is marked stale after an hour.

## 5. Turn on enforcement

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

## Certificate trust on macOS

To inspect AI traffic, the agent needs a certificate that apps trust. Since
macOS 11, only an MDM profile can make a certificate trusted without the user
approving it. So Macs work like this:

- **Your tenant has one root certificate.** You upload it once, as the
  profile from the portal. It is limited to the AI services in your policy:
  macOS refuses it for any other site.
- **Each Mac has its own certificate under that root.** It is valid for 7 days
  and renewed daily. The Mac creates its key and never sends it anywhere. A
  device you revoke gets no renewal, so its certificate stops working within
  a week.
- **If a Mac cannot renew for more than 7 days** (for example, long offline),
  AI traffic passes uninspected and this is recorded. If your policy's
  `fail_mode` is `block`, AI services are unreachable instead, until it
  renews.

If you add an AI service to the policy that the root does not cover, the portal
says so. Click **Reissue root** and upload the new profile. Until you do, that
service is not inspected on Macs.

Windows needs none of this. The agent trusts its own certificate on the laptop
itself.

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

## Company inventory (optional)

An enrollment token deployed through MDM can be read on the laptops it was
deployed to. To make sure only your own laptops can enroll, upload your MDM's
serial number export:

1. Export the computer or device list from Jamf, Kandji or Intune as CSV. Any
   column whose header contains "Serial" is used.
2. In the portal, open Device DLP, then Company inventory, and upload the file.

From then on, a laptop whose serial number is not in the list is refused, even
with a valid token, and the attempt raises an alert. Serial numbers are hashed
on arrival; Votal does not keep them as uploaded. Upload again whenever you add
laptops: each upload replaces the list. **Clear** turns the restriction off.

## Reinstalling a laptop

A laptop can be reinstalled or reimaged at any time. If its previous install
reported to Shield in the last 24 hours, revoke the old device in the portal
first. Otherwise Shield refuses the new enrollment and raises an alert. This
stops anyone who has read the enrollment token from taking over a colleague's
laptop by claiming its serial number.

Silent for more than 24 hours, the old device is replaced automatically. To go
back to replacing immediately, set `SHIELD_DEVICE_REENROLL_LIVE=replace` on
Shield.

## Uninstall

- macOS: run `packaging/macos/uninstall.sh` as root, then remove the profiles.
- Windows: uninstall the app in Intune, and remove the PAC setting.

Uninstalling removes the device key and the agent's certificate. Revoke the
device in the portal so its key stops working immediately.

## Troubleshooting

| `verify` says | Do this |
|---|---|
| MDM settings: none found | The settings profile or registry key has not arrived. Check its scope in the MDM. |
| enrolled: FAIL | The enrollment token is missing, expired or used up. Create a new one and update the profile. |
| enrolled: "a device with this serial is still reporting" | This laptop's previous install is still enrolled and reported in the last 24 hours. Revoke the old device in the portal; the agent enrolls again within an hour. |
| policy bundle: fallback | The laptop cannot reach Shield, or the pinned key is wrong. The laptop still redacts known secrets. |
| decision model: model_unavailable | The local model is still downloading, or failed to. Check `/Library/Logs/Votal/ollama.log` (Mac) or `C:\ProgramData\Votal\DeviceAgent\logs\ollama.log` (Windows). |
| decision model: model_mismatch | The model on the laptop is not the one your policy pins. The agent removes it and downloads it again. |
| local proxy: FAIL | The agent could not start its proxy. On a Mac, it starts once the Mac has its certificate; check that the device is enrolled and can reach Shield. Otherwise check the agent log. |
| device CA trusted: FAIL | On a Mac, the root certificate profile is missing, or was replaced: upload the current one from the portal. |

## Privacy

- The agent reads prompts only for AI services in your policy.
- It sends Votal a verdict, category, destination, app, device, time, and the
  prompt's hash and length.
- It never sends the prompt text. Excerpts (the first 200 characters, with
  every rule match masked) are off unless you turn on `capture_excerpt`.
- Decisions are kept on the laptop in a tamper-evident log until they are
  uploaded.
