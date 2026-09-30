---
title: "Acceptance: device DLP rollout kit on real MDMs"
layout: default
nav_exclude: true
permalink: /specs/device-rollout-acceptance/
description: The manual acceptance run for the device DLP rollout kit on Jamf or Kandji (Mac) and Intune (Windows), following only the kit README. Fill in and attach to the release PR.
---

# Acceptance: device DLP rollout kit on real MDMs

Spec: `docs/specs/device-rollout-kit.md` §8 ("Acceptance on real MDMs"). The
automated suite checks every file a kit contains. This run checks what it
cannot: the MDM consoles, real enrollment over the network, and real apps.

Rules for the run:
- Follow **only the kit's README.md**. Anything you had to work out that the
  README did not say is a finding.
- Use a test fleet (for example `acceptance`) and a test tenant, not a
  customer's.
- Record each result as pass, fail or n/a, with a note. Screenshots of the MDM
  console for steps 2 and 3 go in the PR.

## Before the run

| # | Check | Result |
|---|---|---|
| 0.1 | Shield has `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY`, `SHIELD_DEVICE_CA_MASTER_KEY` and `SHIELD_DEVICE_AGENT_SHIELD_URL` (https) on the planes that serve the portal and devices | |
| 0.2 | A release `device-agent-v<version>` exists. Note whether it is signed; Intune for Mac needs signed | |
| 0.3 | One test Mac enrolled in Jamf or Kandji; one test Windows laptop in Intune; both with Chrome | |
| 0.4 | The test fleet is in `monitor` in the DLP policy | |

## A. Mac, with Jamf Pro or Kandji

| # | Step | Expected | Result |
|---|---|---|---|
| A.1 | Portal: Rollout kits, fleet `acceptance`, MDM Jamf (or Kandji), download | A zip `votal-rollout-kit-acceptance-jamf.zip`; the kit is listed as active | |
| A.2 | Run `macos/get-installer.sh` (add `--allow-unsigned` only for an unsigned release) | Prints the `.pkg`. On a signed release it refuses nothing; change one byte of the `.pkg` and run again: it refuses | |
| A.3 | Upload the `.pkg` and the profile as the README says; scope to the test Mac | The MDM accepts both files without editing them | |
| A.4 | Wait for the Mac to install both | The Mac appears under Devices within 15 minutes; state ok; mode monitor | |
| A.5 | The profile shows in System Settings (Device Management) with the Votal payloads | Settings, root certificate, proxy, extension (if an id was set), login item | |
| A.6 | System Settings, General, Login Items | The agent is listed as managed; the user cannot switch it off | |
| A.7 | The health check (extension attribute or audit) | "ok" in the MDM console | |
| A.8 | On the Mac: `sudo .../votal-device-agent verify` | Every line ok | |
| A.9 | In Chrome, paste a real-looking password into ChatGPT | Recorded under Devices and in the decision audit (monitor: not blocked) | |
| A.10 | Set the fleet to `enforce`; wait 5 minutes; repeat A.9 | ChatGPT shows "Blocked by your company's AI data policy" | |
| A.11 | Paste a patient record into Claude | A reason is asked for; after giving one the prompt is sent once | |
| A.12 | Open a non-AI site | Loads normally; its certificate is the site's own, not Votal's | |

## B. Windows, with Intune

| # | Step | Expected | Result |
|---|---|---|---|
| B.1 | Portal: Rollout kits, fleet `acceptance`, MDM Intune, Windows only, download | Zip with `windows/`; the kit is listed as active | |
| B.2 | Run `windows/get-installer.ps1` | Prints the `.msi`; checksum and signature checked | |
| B.3 | Add the MSI as a line-of-business app with the arguments line from `install-command.txt`; add the platform scripts; assign to the test laptop | Intune accepts all of them without edits | |
| B.4 | Wait for the install | The laptop appears under Devices within 15 minutes; state ok | |
| B.5 | The remediation detection script | "Without issues" in Intune | |
| B.6 | On the laptop, as administrator: `votal-device-agent.exe verify` | Every line ok | |
| B.7 | `certlm.msc`, Trusted Root Certification Authorities | The Votal device CA is there, and its name constraints list the AI hosts | |
| B.8 | Repeat A.9 and A.10 in Chrome and Edge | As on the Mac | |
| B.9 | `C:\ProgramData\Votal\DeviceAgent\state`: try to open `ca\mitmproxy-ca.pem` as a standard user | Access denied | |

## C. Security behaviours

| # | Step | Expected | Result |
|---|---|---|---|
| C.1 | Revoke the kit in the portal; enroll another laptop with it | Refused ("invalid or expired enrollment token"); already-enrolled laptops keep working | |
| C.2 | Upload a company inventory without the test Mac's serial; reinstall the agent on it after revoking its device | Refused, "not in the company inventory"; a high-severity alert in the decision audit | |
| C.3 | With the Mac enrolled and reporting, install on a second machine using the Mac's serial hash (or reinstall without revoking) | Refused, "still reporting"; alert raised; the first Mac unaffected | |
| C.4 | Add an AI host to the policy; download a new kit | The root is reissued; the old kit is marked out of date; the new profile covers the host | |
| C.5 | Uninstall on the Mac (`uninstall.sh`) and Windows (Intune uninstall) | Agent gone; its certificate and key removed; the device goes stale in the portal after an hour | |

## Record

| Field | Value |
|---|---|
| Date | |
| Shield build | |
| Agent release (signed or unsigned) | |
| MDMs and versions | |
| macOS and Windows versions | |
| Run by | |
| Findings (README gaps, console path changes, failures) | |

Findings about console paths go straight into the kit's README templates
(`core/dlp/kit_templates/`), with the date checked.
