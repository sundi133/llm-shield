---
title: "Spec: Device DLP rollout kit"
layout: default
nav_exclude: true
permalink: /specs/device-rollout-kit/
description: One download per fleet and MDM (Jamf, Kandji, Intune) that rolls the Votal device agent out to employee laptops with nothing typed by hand.
---

# Spec: Device DLP rollout kit

> Status: **APPROVED 2026-09-30** (user: "approved"). The live-device serial fix (§5, point 1) went into PR #447 first, at the user's request.
> Builds on: `docs/specs/device-dlp-agent.md` (PR #447).
> Planes: admin and data (kit generation, the same tenant routes as `/v1/tenant/me/devices/*`); CI (release pipeline); the laptop (agent fixes).
> Guard path: untouched.

## 1. Problem & outcome

**Today** an admin assembles six pieces by hand and pastes the same values into
several of them:

| Piece | By hand today |
|---|---|
| Installer | A CI artifact: unsigned, no Ollama, expires in 90 days |
| Settings | Edit a profile template: Shield URL, tenant, fleet, pinned key, token |
| Root certificate (macOS) | A separate download from the portal |
| Proxy (PAC) | A second profile (macOS) or a script (Windows) |
| Browser extension | A third profile, edited with the extension id |
| Health check | Run `verify` on a laptop |

**Outcome.** In the portal, under Device DLP, an admin chooses a fleet and an MDM
and clicks **Download rollout kit**. The zip holds everything with every value
filled in. The observable success conditions:

1. **Jamf or Kandji (macOS):** upload one profile and one `.pkg`, scope both to
   a group. Laptops enroll with no user action and appear in the fleet view.
2. **Intune (Windows):** add one MSI with the install command from the kit, and
   one platform script. Laptops enroll and appear in the fleet view.
3. **Intune (macOS):** the same two uploads as Jamf.
4. **Nothing typed by hand.** No placeholder is left in any kit file (a test
   checks this). Following the kit's README takes at most 3 steps per MDM, then
   "watch the fleet view".
5. **Fleet health in the MDM itself.** Jamf gets an extension attribute, Kandji
   an audit script and Intune a detection script, each reporting `verify`.
6. **Installers come from a signed, versioned release** that includes Ollama. A
   helper in the kit fetches the release and checks its signature.

**Non-goals**
- **Pushing into MDM APIs.** Shield will not hold Jamf, Kandji or Intune
  credentials. The admin uploads the kit's files.
- **Hardware attestation** (Apple Managed Device Attestation, Intune compliance
  checks at enrollment). Recorded as the future fix in §5.
- **Automatic agent updates.** The admin ships a new version by uploading the
  new `.pkg` / `.msi`, as with any MDM-managed app.
- **Linux, unmanaged or personal devices.**
- **The signing identities themselves.** The Apple Developer ID and the Windows
  code-signing certificate belong to Votal; this spec only uses them.

## 2. Plane & latency contract

| Component | Runs | On a guard path? |
|---|---|---|
| Kit generation `POST /v1/tenant/me/devices/rollout-kits` | admin and data plane (CPU) | **No.** Off hot path, no guarded-traffic impact. Pure templating plus one token write. |
| Kit list, inventory API | admin and data plane | No. |
| Release pipeline | GitHub Actions | No. |
| Agent fixes (wait for settings, serial rule) | laptop, and `/v1/devices/enroll` on the data plane | No. Enrollment is not a guard path. |

## 3. Data model

**Kit tokens reuse the enrollment token store** (`core/dlp/devices.py`):

| Key | Change |
|---|---|
| `device_enroll:{tenant_id}:{sha256(secret)}` | Adds `kind: "kit"`, `kit_id`, `mdm` |
| `device_enroll_used:{tenant_id}:{sha}` | Unchanged (atomic INCR) |

Kit tokens get their own limits, because they sit in MDM for the life of the
rollout (new hires join months later):

| Limit | Kit tokens | Other tokens (unchanged) |
|---|---|---|
| Expiry | default 180 days, max 365 | max 90 days |
| Uses | default 5,000, max 100,000 | max 10,000 |

**A new kit record** (never holds the token):

| Key | Shape | TTL |
|---|---|---|
| `device_kit:{tenant_id}:{kit_id}` | `{kit_id, fleet, mdm, platforms, include_proxy, extension_ids, agent_version, root_fingerprint, token_id, created_by, created_at, expires_at}` | the token's expiry + 30 days |

**A new, opt-in serial allow list:**

| Key | Shape | TTL |
|---|---|---|
| `device_inventory:{tenant_id}` | SET of `sha256(serial)`, from an admin-uploaded MDM export. Serials are hashed on upload; plain serials are never stored. | none |

When the set is non-empty, enrollment requires the laptop's `serial_hash` to be
in it.

**Tenant scoping.** Every key carries `tenant_id`, which comes from the
authenticated key. The kit's token names its tenant (`vde.<tenant>.<secret>`)
and is checked against that tenant's store only, as today.

## 4. API / interface

All tenant routes are on both planes, behind the registry write gate for
writes, with an admin audit record. Kit generation needs
`SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY`, plus `SHIELD_DEVICE_CA_MASTER_KEY` when the
kit includes macOS.

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/tenant/me/devices/rollout-kits` | Mint a kit token and return the kit as `application/zip` (`X-Votal-Kit-Id` header) |
| GET | `/v1/tenant/me/devices/rollout-kits` | Kits so far (never the token): fleet, MDM, uses left, expiry, and whether stale |
| DELETE | `/v1/tenant/me/devices/rollout-kits/{kit_id}` | Revoke the kit's token. Enrolled laptops keep working. |
| PUT | `/v1/tenant/me/devices/inventory` | Body: CSV or a JSON list of serials; replaces the allow list; returns the count |
| GET | `/v1/tenant/me/devices/inventory` | The count and when it was uploaded (never the serials) |
| DELETE | `/v1/tenant/me/devices/inventory` | Clear it: enrollment is no longer restricted |

**Kit request body:**

```json
{"fleet": "sales", "mdm": "jamf", "platforms": ["macos"],
 "include_proxy": true, "extension_ids": ["<32 letters>"],
 "expires_in_days": 180, "uses": 5000, "revoke_previous": false}
```

- `mdm` is one of `jamf`, `kandji`, `intune`.
- `platforms` defaults to `["macos"]` for Jamf and Kandji, and to
  `["windows", "macos"]` for Intune.
- `extension_ids` defaults to the published Votal extension
  (`SHIELD_BROWSER_EXTENSION_IDS`).
- `revoke_previous` revokes the previous kit tokens for the same fleet and MDM.

A kit is **stale** when the tenant root has been reissued since the kit was
made, or the policy has an AI host its root does not cover. The kit list shows
it, and the portal says "download a new kit".

**Kit contents.** The token appears only in the files marked (token).

*macOS, for Jamf, Kandji and Intune:*
- `Votal-Device-Agent.mobileconfig` (token): **one profile** with every payload:

  | Payload | Purpose |
  |---|---|
  | `ai.votal.device-agent` | Settings: Shield URL, tenant, fleet, pinned key, token, extension ids, `CAMode` tenant |
  | `com.apple.security.root` | The tenant root |
  | `com.apple.SystemConfiguration` | PAC `http://127.0.0.1:47823/proxy.pac`, fallback allowed. Only when `include_proxy`. |
  | `com.google.Chrome`, `com.microsoft.Edge` | `ExtensionInstallForcelist` |
  | `com.apple.servicemanagement` | Managed Login Items (macOS 13+): a rule for the Label `ai.votal.device-agent` and Votal's Team ID, so users cannot turn the agent off and see no "background item added" prompt |

- `get-installer.sh`: downloads the pinned version's `.pkg` from the release,
  then checks `pkgutil --check-signature` (Votal's Team ID) and
  `spctl -a -t install` (notarized). Prints the file to upload.
- A health check:
  - Jamf: `jamf-extension-attribute.sh`, which runs `verify` and prints
    `<result>ok</result>` or the failing checks.
  - Kandji: `kandji-audit.sh`, with the same output.
  - Intune on macOS: a custom attribute shell script.
- `README.md`: three steps for this MDM, then what to watch in the portal.

*Windows (Intune):*
- `install-command.txt` (token): the `msiexec /i ... /qn SHIELDURL=...` line for
  the Intune app's install command.
- `set-pac.ps1`: only when `include_proxy`.
- `browser-extensions.ps1`: `ExtensionInstallForcelist` for Chrome and Edge.
  The README also shows the settings-catalog alternative.
- `detect.ps1`: an Intune detection and remediation script that runs `verify`.
- `get-installer.ps1`: downloads the `.msi`, then checks the Authenticode
  signer and the SHA-256 from the release's `SHA256SUMS`.
- `README.md`.

*All kits:*
- `SECURITY.txt`: the kit contains an enrollment token, where it appears, and
  how to revoke it.
- `kit.json`: kit id, fleet, MDM, agent version, root fingerprint. No token.

**Release (CI).** A tag `device-agent-v<version>` produces a GitHub Release
(the repo is public) with:
- `votal-device-agent-<v>.pkg`: signed with Developer ID Installer, binaries
  with Developer ID Application, notarized and stapled.
- `votal-device-agent-<v>.msi`: Authenticode-signed.
- `SHA256SUMS`.

Both installers bundle Ollama at the version and SHA-256 pinned in
`packages/votal-device-agent/packaging/ollama.lock`.

Kits pin the agent version: `SHIELD_DEVICE_AGENT_VERSION`, defaulting to the
version in the package.

## 5. Security & backward compatibility

**The token is visible once it is deployed.** A kit embeds an enrollment token
in MDM configuration. MDM admins can see it, and so can local users on each
laptop: Windows `HKLM\SOFTWARE\Policies` is readable by Users, and the macOS
managed-preferences files are assumed readable (to confirm on an enrolled Mac).
So **an employee can enroll a software "device"**. That gets them:

| Obtained | Impact |
|---|---|
| The DLP bundle | Low: the same policy already on their laptop |
| A device key | Events attributed to a new device id: noise, visible in the fleet view |
| A 7-day intermediate CA, name-constrained to AI hosts | **The real risk:** from an on-path position (same network, ARP spoofing), intercepting a colleague's AI traffic. Never any other site; macOS and curl enforce the constraints (verified in PR #447). |

Mitigations in this spec:
1. **No takeover of a live device (changes today's behavior).** Today an
   enrollment with the same `serial_hash` and fleet replaces the old identity.
   Because serial numbers are visible (About This Mac), an employee could then
   knock a colleague's laptop off by claiming its serial.
   - Now, if that device sent a heartbeat in the last 24 h, the enrollment is
     refused (409) and recorded as a `dlp` event with severity high.
   - A genuine reinstall on a silent device still replaces it, as today.
   - Escape hatch: `SHIELD_DEVICE_REENROLL_LIVE=replace` restores the old
     behavior. Migration note in the admin guide: to reinstall a laptop within
     24 h, revoke it in the portal first.
2. **Opt-in inventory allow list.** Upload the MDM's serial export; only those
   serials enroll. A software "device" then needs a real, currently unenrolled
   company serial, not any string.
3. **Visibility.** The fleet view shows enrollments per kit per day, and kits
   with unusual enrollment counts. Revoking a kit is one click.
4. **Short, rotatable tokens.** 180 days by default. Regenerating a kit mints a
   new token; `revoke_previous` retires the old one.
5. **No automatic re-enrollment after revoke.** A revoked laptop keeps
   enforcing its last policy and reports `revoked`; it does not use the MDM
   token to come back. This is today's behavior, now written down and tested.

**Residual risk,** documented in the admin guide: without hardware attestation,
an employee who controls a valid, unenrolled company serial can enroll a
software device. The future fix is Apple Managed Device Attestation and the
Intune compliance state at enrollment.

**Other protections**
- The kit zip is built in memory and never stored. Its token is shown by
  nothing else.
- Kit generation needs the registry write gate. It is audited
  (`tenant_create_rollout_kit`: kit id, fleet, MDM, token id; never the token).
- Kit generation reissues the tenant root if the policy's AI hosts are not
  covered (audited), because the kit is about to replace the profile anyway.

**Backward compatibility.** Existing tokens, devices, APIs and the manual
profiles in `packaging/` are unchanged. The only default that changes is
live-device replacement (point 1), with its escape hatch.

## 6. Packaging & deploy

- **New modules:** `core/dlp/rollout_kit.py` (stdlib only: zipfile, plistlib,
  json) and its templates in `core/dlp/kit_templates/`. Both ship to the admin
  image through the existing `COPY core/dlp/ core/dlp/`. A guard test checks
  that the templates load in the admin image layout.
- **New routes:** in `api/routes_devices.py`, already copied to the admin
  image.
- **No new pip dependencies.**
- **New env:**

  | Variable | Default |
  |---|---|
  | `SHIELD_DEVICE_AGENT_VERSION` | the package version |
  | `SHIELD_BROWSER_EXTENSION_IDS` | empty |
  | `SHIELD_DEVICE_REENROLL_LIVE` | `reject` |

- **Existing env, now needed on the admin plane for kits:**
  `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` and `SHIELD_DEVICE_CA_MASTER_KEY`.
- **Release workflow** `.github/workflows/device-agent-release.yml`, on tag
  `device-agent-v*`. Repository secrets:
  - `APPLE_APP_CERT_P12`, `APPLE_INSTALLER_CERT_P12`, `APPLE_CERT_PASSWORD`
  - `NOTARY_KEY_ID`, `NOTARY_ISSUER`, `NOTARY_KEY_P8`
  - `WINDOWS_SIGN_CERT_PFX`, `WINDOWS_SIGN_PASSWORD` (or Azure Trusted Signing)

  Without the secrets it publishes an **unsigned pre-release**, clearly
  labelled, so the pipeline can be tested before the certificates exist.
- **Version source:** one constant, `votal_device_agent/__init__.py
  __version__`, replacing the two copies (`__main__.VERSION`,
  `sync.AGENT_VERSION`).
- **Images:** rebuild the admin and data plane images (new routes and
  templates). Agent: a new release.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| macOS in the kit, but `SHIELD_DEVICE_CA_MASTER_KEY` unset | 503, naming the variable |
| `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` unset | 503 (laptops could not verify anything) |
| The policy has AI hosts the root does not cover | The root is reissued (audited) and the kit carries the new one; header `X-Votal-Root-Reissued: 1` |
| No extension id | The extension payloads and script are left out; the README says the browser is still covered by the proxy |
| `include_proxy` false (the customer already has a proxy profile; Apple allows one per Mac) | The README gives the PAC lines to add to their PAC, and the kit leaves the proxy payload out |
| Token uses exhausted | Enrollment returns 401 "no uses left"; the kit list shows "exhausted, download a new kit" |
| Redis down while generating | 503; nothing is returned half-made (the token is written before the zip is built) |
| The release version is not published | `get-installer` fails, naming the version; the README links the release page |
| Unsigned release (no certificates yet) | The kit README says so. Intune for Mac rejects unsigned `.pkg`; Jamf and Kandji take it. `get-installer.sh --allow-unsigned` exists for pilots only. |
| Agent installed before the profile arrives | The service **waits** (checks every 30 s, logs once) instead of exiting and restarting every 10 s, as it does today |
| Reinstall within 24 h of the old agent's last heartbeat | 409 until then, or the admin revokes the old device. The agent retries hourly and `verify` says why. |
| Profile removed from a laptop | The agent keeps its last settings and policy, and reports `stale_bundle` if it can no longer sync. Removal is visible in the MDM. |
| Huge inventory upload | Capped at 200,000 serials (about 13 MB of hashes in Redis); larger returns 413 |
| Two admins generate kits at once | Independent tokens; `revoke_previous` revokes only kits created before this one |

## 8. Test plan (Definition of Done)

**Kit contents** (per MDM and platform combination):
- Every expected file is present, and no `__PLACEHOLDER__` remains anywhere.
- The profile parses with plistlib. Payload types and UUIDs are unique. The
  root DER equals the current root. The PAC URL and the Login Items label are
  correct.
- The token appears only in the files marked (token) and nowhere in `kit.json`,
  `SECURITY.txt` or the README.
- Shell scripts pass `bash -n`; PowerShell scripts are checked for syntax with
  `pwsh` when available.
- The customer READMEs have no em dashes.

**API:**
- Registry write gate; audit record without the token; the zip is not stored.
- The kit list never shows the token; stale detection; revoke and
  `revoke_previous`.
- Root auto-reissue; 503 without either key; uses and expiry limits for kit
  tokens against other tokens.

**Serial rule:**
- A live duplicate returns 409 and records a high-severity event.
- A duplicate silent for 24 h or more is replaced.
- The escape hatch restores the old behavior.

**Inventory:**
- Hashed on upload; allow and deny at enrollment; cleared means unrestricted;
  the 413 cap.

**Agent:**
- It waits for settings instead of exiting.
- It does not re-enroll after revoke.
- It retries after a 409.

**Release workflow:**
- The workflow YAML parses and names the secrets above.
- Without secrets, the path is unsigned and labelled pre-release.
- `ollama.lock` is used and its checksum enforced.

**Suite and CI:**
- Guards: `Dockerfile.admin` and the template files; the full suite green in a
  clean venv; the CI `pytest` gate.

**Acceptance on real MDMs (manual, recorded in the PR):**
- One Mac through Jamf or Kandji and one Windows laptop through Intune,
  following only the kit README.
- Each shows in the fleet view, `verify` is ok, and a password prompt to
  ChatGPT is blocked.

## Tasks (one branch, `feat/device-rollout-kit`, after PR #447 merges; one commit per task)

| # | Task | Size |
|---|---|---|
| 1 | Unattended rollout fixes: the agent waits for settings; kit token kind and limits; a single version constant. (The live-device serial rule and its escape hatch shipped in PR #447 before merge.) | S |
| 2 | Kit generator (`core/dlp/rollout_kit.py` and templates): the macOS profile with all payloads, scripts and READMEs for Jamf, Kandji and Intune, and the Windows Intune kit; pure, tested without the API | M |
| 3 | Kit API and portal: generate, list, revoke; stale detection; root auto-reissue; the "Roll out" card on the Device DLP page; tests and a browser check | M |
| 4 | Opt-in inventory allow list: API, enrollment check, portal upload | S |
| 5 | Release pipeline: `ollama.lock`, the tagged release workflow (signed when secrets exist, unsigned pre-release otherwise), `SHA256SUMS`, and the signature checks in the `get-installer` scripts | M |
| 6 | Admin guide rewritten around the kit, plus the acceptance checklist | S |

**As built, task 1:**
- **Waiting for settings.** `installed.wait_for_settings` polls every 30 s and
  logs once per change of reason. SIGTERM ends the wait cleanly.
- **Invalid settings.** Invalid MDM settings with no earlier `agent.json`: the
  service waits and says why. Invalid settings pushed later: it keeps the last
  good `agent.json` and logs it, so DLP stays on.
- **Kit tokens.** `create_enrollment_token(kind="kit", kit_id=, mdm=)` allows
  up to 365 days and 100,000 uses; hand-made tokens keep 90 days and 10,000.
  The existing token endpoint cannot make kit tokens.
- **One version.** It is written in `votal_device_agent/_version.py` and read by
  the CLI, the heartbeat and enrollment, `build_pkg.sh` and `build_msi.ps1`.
  CI checks that the built binary reports it.

**As built, task 2** (`core/dlp/rollout_kit.py`, templates in
`core/dlp/kit_templates/`):
- **Pure:** a `KitRequest` goes in, a zip comes out. Minting the token and
  reading the root and policy is task 3.
- **Strict validation.** Every value that reaches a script or command line is
  checked against a pattern (tenant, fleet, URLs, version, Team ID, signer,
  extension ids, hosts, token). A kit runs as root or SYSTEM on every laptop,
  so none of them can carry shell or PowerShell syntax.
- **Templates:**
  - They are `*.tmpl`, because `.dockerignore` drops `*.md`.
  - Rendering fails on any unknown or leftover placeholder.
  - Every template is used; a test checks it.
- **One stable profile identifier per tenant and fleet**
  (`ai.votal.device-agent.<tenant>.<fleet>`): a newer kit's profile replaces
  the older one instead of adding a second proxy payload.
- **Managed Login Items** carry the Team ID once the release is signed
  (`apple_team_id`).
- **The token appears in exactly two files:** the Mac profile and the Windows
  `install-command.txt`. `SECURITY.txt` lists them.
- **Generated sentences.** The README's profile description and Windows script
  step are built from what the kit actually contains.
- **Admin guide link:** the kit links `https://docs.shield.votal.ai/device-dlp-agent/`.

**As built, task 3** (`core/dlp/kits.py`, routes in `api/routes_devices.py`,
the Rollout kits card on the Device DLP page):
- **Order inside `create_kit`:**
  1. Parse the body.
  2. Validate the whole kit with a placeholder token.
  3. Reissue the root if the policy outgrew it (audited as
     `tenant_reissue_device_root_ca`, reason "rollout kit").
  4. Mint the kit token.
  5. Build the zip.
  6. Record the kit.

  A bad request returns 400 without minting a token. A failed build revokes
  the token it minted.
- **The kit record** is `device_kit:{tenant}:{kit_id}`. It never holds the
  token, and has a millisecond timestamp so the list stays newest first.
- **Kit status:** active, exhausted, revoked or expired. Laptops left shows
  only while the token can still enroll.
- **Stale reasons:**
  - the root was reissued since the kit was made;
  - the policy has hosts no root covers;
  - an older agent version.
- **Revoking** a kit (or `revoke_previous`) revokes its token only; laptops it
  enrolled keep working.
- **The Shield URL in a kit:**
  - `SHIELD_DEVICE_AGENT_SHIELD_URL` when set.
  - Otherwise the request's own https URL, but only in the app that mounts
    `/v1/devices/enroll` (the data plane).
  - A kit made through the admin plane without the variable gets 503: it
    would otherwise point laptops at a host that cannot enroll them.
- **More env:** `SHIELD_DEVICE_AGENT_RELEASE_BASE`, `SHIELD_APPLE_TEAM_ID`,
  `SHIELD_WINDOWS_SIGNER`, `SHIELD_BROWSER_EXTENSION_IDS`,
  `SHIELD_DEVICE_AGENT_VERSION`. Default agent version:
  `kits.DEFAULT_AGENT_VERSION`, held equal to the agent's `_version.py`.
- **Checked in the portal** (admin plane, local demo):
  - generate Jamf, Kandji and Intune kits, all 200;
  - list them and revoke one;
  - "revoke earlier kits" keeps the new one active;
  - console errors are only the pre-existing sign-in and `aibom/drift` loads.
- **End to end in the tests:** the token taken out of a downloaded kit enrolls
  a laptop.

## What is needed from Votal (not code)

1. **An Apple Developer ID** (Application and Installer certificates) and a
   notarization API key: for task 5 and for Intune on Mac.
2. **A Windows code-signing certificate,** or an Azure Trusted Signing account.
3. **The published Chrome Web Store id** of the extension, for
   `SHIELD_BROWSER_EXTENSION_IDS`.
4. **Production keys:** `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` and
   `SHIELD_DEVICE_CA_MASTER_KEY` set on production (both planes).
5. **For acceptance:** one test Mac in Jamf or Kandji, and one Windows laptop
   in Intune.

Tasks 1 to 4 and 6 need none of these. Task 5 runs unsigned until items 1 and 2
exist.
