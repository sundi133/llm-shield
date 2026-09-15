---
title: "Endpoint Enforcement: Extension and Proxy"
layout: default
nav_order: 26
permalink: /endpoint-enforcement/
description: "Two ways to stop sensitive prompts leaving a managed device: a browser extension pushed by MDM with policy-enforced settings, or prompt inspection at your web gateway over ICAP with Squid or any cloud proxy. How to set up each, and which one your threat model needs."
---

# Endpoint enforcement
{: .no_toc }

Your users reach AI tools through a browser. There are exactly two places to
stop a sensitive prompt before it leaves: **in the browser**, with a managed
extension, or **on the network**, at the web gateway the traffic already
crosses.

This page covers both, how to deploy each under MDM, and, more usefully, which
one your threat model actually calls for.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Which one do you need

| | **Browser extension** | **Gateway (ICAP)** |
|---|---|---|
| Installed on the device | Yes, an extension | No, configuration only |
| Sees prompt text | Before it is sent, in the page | After TLS interception at the proxy |
| Screens attachments before upload | **Yes**, file picker, drag-and-drop, paste | Request body only |
| Covers non-browser traffic | No | **Yes**, any client through the proxy |
| Covers unmanaged devices | No | Only if they use the proxy |
| Needs TLS interception | No | **Yes**, plus a CA on every device |
| If Shield is unreachable | `failOpen` decides: block (default) or send unscreened | Fails per your configured posture |
| Typical time to deploy | Hours | Weeks, mostly legal and works council |

**The short version.** The extension is the better user experience. It is the
only path that stops a prompt inside the page before it is sent, and the only
one that screens attachments before the site receives them. The gateway is the broader net and the
only one that sees traffic outside the browser. Most enterprises that are
serious about this run **both**: the extension for the everyday accidental
paste, the gateway so that turning the extension off does not turn enforcement
off.

{: .warning }
> **Neither is a control against a determined insider.** MDM makes your path the
> default, not the only one. A user can install a personal browser, run a VM, or
> tether to a phone. If the traffic must not escape, the enforcement has to be
> egress control: deny outbound 443 to AI destinations from anything except the
> proxy's source address. Everything on this page makes the control convenient.
> Only egress policy makes it mandatory. Be straight with buyers about this.

---

## 2. Path A: browser extension by MDM

### What it enforces

When the user submits a prompt or attaches a file, the extension sends it to
Shield from its background service worker before the site receives it. In
`enforce` mode a block verdict stops the send and the text stays in the
composer. In `warn` mode the prompt is flagged with a banner and still sent.
The extension does not run rules locally and does not rewrite the prompt.

Supported sites today: Claude (claude.ai), ChatGPT (chatgpt.com,
chat.openai.com), Gemini (gemini.google.com) and Microsoft Copilot
(copilot.microsoft.com). Adding a site is a few lines in the content script.
Coverage is browser tabs only, not desktop apps, mobile, or direct API use.

{: .note }
> **A second build exists.** `extension/` is an edge build that runs tenant
> rules locally first and can redact in place before escalating to Shield. It
> does not yet support managed configuration, so it is not the build MDM
> deploys. This page describes the managed build in
> `examples/browser-extension/` only.

### Step 1: package and host

Pack the extension and host two files on any static HTTPS origin: the `.crx`
and an `update.xml` that points at it.

```xml
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='EXTENSION_ID'>
    <updatecheck codebase='https://downloads.example.com/shield-prompt-guard.crx'
                 version='1.0.0'/>
  </app>
</gupdate>
```

To ship an update, bump `version` in `manifest.json`, repack with the same
`.pem`, and replace both files. Enrolled fleets update automatically within
hours with no customer action.

### Step 2: force-install policy

One policy line, delivered through whatever already manages the browser:

```
ExtensionInstallForcelist = ["EXTENSION_ID;https://downloads.example.com/update.xml"]
```

| Platform | Where it goes |
|---|---|
| **Windows, GPO or Intune** | `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`, string value `1`. Google publishes ADMX templates for Group Policy. |
| **macOS, Jamf / Kandji / Intune** | Configuration profile targeting `com.google.Chrome`, key `ExtensionInstallForcelist`, array of the same string. |
| **Linux** | JSON file in `/etc/opt/chrome/policies/managed/`. |
| **Chrome Browser Cloud Management** | Google Admin console, Devices > Chrome > Apps and extensions. Add by ID with a custom update URL. One console, all desktop platforms. |
| **Microsoft Edge** | Identical policy name under `HKLM\Software\Policies\Microsoft\Edge` or `com.microsoft.Edge`. |

**On Edge.** The extension is standard Chromium MV3 and runs on Edge with no
code changes. Two things differ, and both belong to the admin rather than the
extension: policy lives under the Edge namespace, and to force-install by ID you
either publish to Microsoft Edge Add-ons or self-host the `.crx` and point the
Edge forcelist at your update URL. Edge can install from the Chrome Web Store,
but only if the user enables "Allow extensions from other stores", which is not
suitable for a managed control.

### Step 3: configuration by policy, not by user

The extension reads its settings from managed storage. Push them under the
`3rdparty` namespace. Managed values override anything a user sets locally, and
`mode` set to `enforce` cannot be turned off by the user.

```json
{
  "3rdparty": {
    "extensions": {
      "EXTENSION_ID": {
        "policy": {
          "shieldUrl":  "https://api.guardrails.example.com",
          "tenantKey":  "your-tenant-key",
          "deviceId":   "${machine_name}",
          "userId":     "jane.doe@example.com",
          "mode":       "enforce",
          "failOpen":   false
        }
      }
    }
  }
}
```

| Key | Meaning |
|---|---|
| `shieldUrl` | Shield data-plane base URL. A self-hosted endpoint also requires adding that host to `host_permissions` in `manifest.json` and repacking. |
| `tenantKey` | Tenant API key, which selects the policy bundle applied |
| `proxyToken` | Optional bearer if a proxy fronts the data plane |
| `deviceId` | Asset identifier for attribution. MDM expands variables such as `${machine_name}` |
| `userId` | User identifier for attribution. Employee id, directory account or email, your choice |
| `mode` | `off`, `warn` or `enforce` |
| `timeoutMs` | Screening deadline, default 45000, clamped to 1000 to 120000 |
| `failOpen` | On an unreachable Shield in enforce mode: `false` (default) blocks, `true` sends unscreened |

{: .note }
> **`failOpen` is the security decision on this page.** The default is `false`,
> because a timeout is not an approval. Set it to `true` only where availability
> genuinely outranks the data being protected, and record that decision, because
> an auditor will ask which way it is set.

**The extension collects no identity on its own.** `userId` and `deviceId` are
whatever you inject. That is deliberate, and it is the answer to the works
council question about what the extension knows about the user.

### Step 4: verify on a device, not in the console

1. Open `chrome://extensions`. The extension shows an "Installed by your administrator" badge and no Remove button.
2. Open `chrome://policy` and confirm `ExtensionInstallForcelist` and the `3rdparty` block are present with status OK.
3. Click the extension icon, then Test connection. Expect the policy-pushed user and device identifiers echoed back.
4. In enforce mode, paste a known-blocked string into a supported AI site. The block banner should appear, and the event should reach Shield telemetry with the expected user and device columns.

### Honest limits

- **Per-site DOM interception is fragile.** Submission is intercepted on the focused editable plus a generic send-button fallback. Site UI changes may need adapter updates.
- **Browser tabs only.** Desktop apps, mobile and direct API calls are not covered. That gap is exactly what Path B closes.

{: .note }
> **Controls evidenced:** SP 800-53 AC-3 access enforcement, SC-28 protection of
> information at rest, SI-10 information input validation. NIST AI RMF
> MEASURE 2.10 privacy-enhanced. EU AI Act Art. 10 data governance.

---

## 3. Path B: web gateway over ICAP

### What it enforces

`shield-icap` screens prompts on their way out of the network. It speaks **ICAP
(RFC 3507)** in REQMOD, so it plugs into the gateway you already run rather than
asking you to install a second one. A prompt that violates policy is blocked
before it reaches the provider, and the user sees a readable reason rather than
a broken page.

Traffic outside your inspected destination list is never read. That scoping is
the single most important thing to bring to a legal or works council review.

### Mode B: behind the gateway you already have

If you run Zscaler, Netskope, Blue Coat, Cisco WSA, Forcepoint or Palo Alto, the
traffic is **already being decrypted**, and no new interception point is needed.
This is the cheap path and the one to check for first.

1. Run the adapter where the gateway can reach it with low latency.
2. Point the gateway's ICAP service at it.
3. Scope it to the AI destinations agreed in your authorisation phase.

Endpoints receive nothing at all in this mode. The gateway you already run is
doing the interception.

### Mode A: bundled Squid

For sites with no existing decrypting gateway, a Squid deployment is included.
The ICAP service registration looks like this:

```
icap_enable on
icap_service shield_req reqmod_precache icaps://icap.example.com:1344/screen bypass=off
adaptation_access shield_req allow ai_destinations
```

`bypass=off` is the security-relevant setting: if the adapter is unreachable,
the request fails rather than sliding past uninspected. Use ICAPS rather than
plaintext ICAP whenever the adapter is not on the same trusted segment as the
proxy, because REQMOD carries the full prompt body.

### What lands on each device

Nothing is installed. Endpoints receive configuration, pushed by MDM.

| Item | Why it is needed | Consequence of skipping it |
|---|---|---|
| Root CA in the system trust store | Squid presents a forged certificate for inspected hosts | Every AI site shows a certificate error |
| Proxy configuration, the PAC URL | Routes AI hosts to the proxy | Traffic goes direct and nothing is inspected |
| `QuicAllowed=false` | Chrome prefers HTTP/3, which ignores an HTTP proxy | Silent bypass, no error, no traffic |
| Firefox `security.enterprise_roots.enabled` | Firefox ignores the OS trust store | Certificate errors in Firefox only |
| `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` | Python and Node ship their own CA bundles | Every script on the fleet fails TLS |

The last row is the one that generates the support tickets. Push it with
everything else, not after the complaints start.

### macOS, by configuration profile

One profile, three payloads, marked non-removable:

```
Certificate payload      ca-cert.pem, System keychain
Proxies payload          com.apple.SystemConfiguration
                           ProxyAutoConfigEnable = 1
                           ProxyAutoConfigURLString = http://<host>:8081/proxy.pac
Managed preferences      com.google.Chrome
                           QuicAllowed = false
                           ProxyMode = pac_script
                           ProxyPacUrl = http://<host>:8081/proxy.pac
```

Environment variables for CLI tools go in a separate launchd plist, because
macOS has no per-machine environment file that both GUI and shell sessions read.

### Windows, by Intune or GPO

```
Trusted Certificate profile   ca-cert.cer -> Local Machine / Trusted Root
Chrome ADMX policy            ProxySettings = {"ProxyMode":"pac_script",
                                               "ProxyPacUrl":"http://<host>:8081/proxy.pac"}
                              QuicAllowed = false
Environment variables         REQUESTS_CA_BUNDLE, SSL_CERT_FILE, NODE_EXTRA_CA_CERTS
```

### Verify on a device

```
chrome://policy                          proxy and QUIC policies show as applied
curl -s http://<host>:8081/healthz       rules > 0, policy_error null
```

`rules: 0` means policy did not load, and an adapter with no rules blocks
nothing. Check this before believing a green deployment.

Then send a canary prompt containing a planted fake credential while still in
monitor mode, and confirm it appears as `would_block`.

{: .note }
> **Controls evidenced:** SP 800-53 AC-4 information flow enforcement, SC-7
> boundary protection, SC-8 transmission confidentiality, AU-2 event logging.
> NIST AI RMF MANAGE 4.1 post-deployment monitoring. EU AI Act Art. 12
> record-keeping.

---

## 4. Roll out in monitor mode first

This applies to both paths and it is not optional advice.

Set the extension to `warn`, or the adapter to `SHIELD_ICAP_MODE=monitor`.
Everything is inspected, decisions are recorded as `would_block`, and nothing is
blocked. Let the data write the policy rather than guessing it, then tune, then
enforce.

Two reasons this matters beyond user experience. First, the block list you would
have written on day one is almost always wrong, and a single bad block during an
executive demo can end the programme. Second, the recorded `would_block` volume
is the evidence that satisfies a change-management review that the control was
tuned before it was enforced.

The phased runbook, with owners and exit criteria per phase, is in the
[AI DLP rollout runbook](/swg-rollout-runbook/). Typical elapsed time is six to
ten weeks, and almost none of that is engineering.

---

## 5. Running both

The two paths are complementary, not alternatives, and they compose cleanly
because they enforce at different points against the same tenant policy.

| Scenario | What catches it |
|---|---|
| Employee pastes a customer list into ChatGPT in a managed browser | Extension blocks before send; in warn mode it flags and allows |
| Same employee uses a desktop AI app | Gateway, the extension never sees it |
| A script on a build agent calls an AI API directly | Gateway, if the agent egresses through the proxy |
| Extension disabled or removed | Gateway still inspects |
| User tethers to a phone to avoid the proxy | Neither. Egress control is the answer |

Run the extension in `enforce` with `failOpen: false` for the everyday case, and
the gateway in enforce for everything the browser does not cover. Point both at
the same tenant so one policy change moves both.

---

## Related

- [Deploy Shield at your web gateway](/swg-deployment/) for the full ICAP path, including Squid setup, CA generation, PAC files, Firefox, command-line runtimes and hosted deployment.
- [AI DLP rollout runbook](/swg-rollout-runbook/) for the phased programme with owners and exit criteria.
- [Edge fast path](/edge-fast-path/) for the extension's design and the policy bundle endpoint it consumes.
