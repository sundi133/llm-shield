#!/usr/bin/env python3
"""Write the MDM files that force-install the self-hosted browser extension.

One set per release location, for every MDM a customer might use: a macOS
configuration profile (Jamf, Kandji, Intune for Mac), an Intune or GPO script
and a .reg file for Windows, a Linux policy file, and the JSON for Google's
Admin console. Each installs VotalAI Guardrails in Chrome and Edge from the
self-hosted update URL and pushes its settings (tenant key, mode, user, device).
See docs/enterprise-install.md.

    python scripts/build_extension_mdm.py \\
        --id gcbcablddjeicimnfipalnckffoiihnb \\
        --update-url https://storage.googleapis.com/votal-public/extension/update.xml \\
        --out dist/extension/mdm

The files hold placeholders, never a real key: REPLACE_WITH_TENANT_KEY is
replaced by the customer, in their MDM, with their own tenant key.
"""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TENANT_KEY = "REPLACE_WITH_TENANT_KEY"
USER_ID = "REPLACE_WITH_USER_ID"
DEVICE_ID = "REPLACE_WITH_DEVICE_ID"
SHIELD_URL = "https://api.guardrails.votal.ai"
_NS = uuid.UUID("6f1c9a52-6d8e-4f0a-9a57-3c1f2b7e9d10")   # stable UUIDs across releases


def _uuid(name: str) -> str:
    return str(uuid.uuid5(_NS, name)).upper()


def settings(user_id: str = USER_ID, device_id: str = DEVICE_ID) -> dict:
    """The managed settings every platform pushes (managed_schema.json)."""
    return {"shieldUrl": SHIELD_URL, "tenantKey": TENANT_KEY, "mode": "enforce",
            "userId": user_id, "deviceId": device_id}


def mobileconfig(ext_id: str, update_url: str) -> bytes:
    """One profile, four payloads: force-install and settings, for Chrome and Edge."""
    force = f"{ext_id};{update_url}"
    payloads = []
    for browser, domain in (("Chrome", "com.google.Chrome"), ("Edge", "com.microsoft.Edge")):
        payloads.append({
            "PayloadType": domain, "PayloadVersion": 1,
            "PayloadIdentifier": f"ai.votal.guardrails.extension.{browser.lower()}.install",
            "PayloadUUID": _uuid(f"{browser}-install"),
            "PayloadDisplayName": f"{browser}: install VotalAI Guardrails",
            "ExtensionInstallForcelist": [force],
        })
        payloads.append({
            "PayloadType": f"{domain}.extensions.{ext_id}", "PayloadVersion": 1,
            "PayloadIdentifier": f"ai.votal.guardrails.extension.{browser.lower()}.settings",
            "PayloadUUID": _uuid(f"{browser}-settings"),
            "PayloadDisplayName": f"{browser}: VotalAI Guardrails settings",
            **settings(),
        })
    profile = {
        "PayloadType": "Configuration", "PayloadVersion": 1,
        "PayloadIdentifier": "ai.votal.guardrails.extension",
        "PayloadUUID": _uuid("profile"),
        "PayloadDisplayName": "VotalAI Guardrails browser extension",
        "PayloadDescription": "Installs VotalAI Guardrails in Chrome and Edge and sets your "
                              "organisation's Shield settings. Prompts to AI tools are checked "
                              "against your company's AI data policy.",
        "PayloadOrganization": "Votal AI",
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": True,
        "PayloadContent": payloads,
    }
    return plistlib.dumps(profile, sort_keys=False)


def powershell(ext_id: str, update_url: str) -> str:
    s = settings()
    return f'''# VotalAI Guardrails: force-install in Chrome and Edge, and set its settings.
# Intune: Devices > Scripts and remediations > Platform scripts, run as system,
# 64-bit. Group Policy: a computer startup script.
# Set $TenantKey to your Shield tenant key before uploading.
param(
  [string]$TenantKey = "{s["tenantKey"]}",
  [string]$Mode = "{s["mode"]}",
  # Who is using the laptop. Scripts run as SYSTEM, so the signed-in user is
  # not known here; leave it empty and the extension reports the device, or
  # set it per user from your own inventory.
  [string]$UserId = "",
  [string]$DeviceId = $env:COMPUTERNAME,
  [string]$ShieldUrl = "{s["shieldUrl"]}"
)
$ErrorActionPreference = "Stop"
if ($TenantKey -eq "{TENANT_KEY}") {{ throw "Set `$TenantKey to your Shield tenant key first." }}
$Id = "{ext_id}"
$Force = "{ext_id};{update_url}"
foreach ($Browser in @("Google\\Chrome", "Microsoft\\Edge")) {{
  # Force-install, keeping any other forced extensions.
  $Key = "HKLM:\\SOFTWARE\\Policies\\$Browser\\ExtensionInstallForcelist"
  New-Item -Path $Key -Force | Out-Null
  $Current = (Get-ItemProperty -Path $Key).PSObject.Properties | Where-Object {{ $_.Name -match '^\\d+$' }}
  $Mine = $Current | Where-Object {{ $_.Value -like "$Id;*" }}
  if ($Mine) {{
    Set-ItemProperty -Path $Key -Name $Mine[0].Name -Value $Force
  }} else {{
    $N = 1
    while ($Current.Name -contains "$N") {{ $N++ }}
    New-ItemProperty -Path $Key -Name "$N" -Value $Force -PropertyType String -Force | Out-Null
  }}
  # The extension's settings (managed storage).
  $Cfg = "HKLM:\\SOFTWARE\\Policies\\$Browser\\3rdparty\\extensions\\$Id\\policy"
  New-Item -Path $Cfg -Force | Out-Null
  $Values = @{{ shieldUrl = $ShieldUrl; tenantKey = $TenantKey; mode = $Mode; deviceId = $DeviceId }}
  if ($UserId) {{ $Values.userId = $UserId }}
  foreach ($Name in $Values.Keys) {{
    New-ItemProperty -Path $Cfg -Name $Name -Value $Values[$Name] -PropertyType String -Force | Out-Null
  }}
}}
Write-Output "VotalAI Guardrails set for Chrome and Edge"
'''


def reg(ext_id: str, update_url: str) -> str:
    s = settings(device_id=DEVICE_ID)
    lines = ["Windows Registry Editor Version 5.00", "",
             "; VotalAI Guardrails for Chrome and Edge. Replace the REPLACE_WITH_ values,",
             "; then import or deploy with Group Policy Preferences. Value \"1\" in",
             "; ExtensionInstallForcelist must not clash with another forced extension.", ""]
    for browser in ("Google\\Chrome", "Microsoft\\Edge"):
        base = f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\{browser}"
        lines += [f"[{base}\\ExtensionInstallForcelist]", f'"1"="{ext_id};{update_url}"', "",
                  f"[{base}\\3rdparty\\extensions\\{ext_id}\\policy]"]
        lines += [f'"{k}"="{v}"' for k, v in s.items()] + [""]
    return "\r\n".join(lines)


def linux(ext_id: str, update_url: str) -> str:
    return json.dumps({
        "ExtensionInstallForcelist": [f"{ext_id};{update_url}"],
        "3rdparty": {"extensions": {ext_id: settings()}},
    }, indent=2) + "\n"


def google_admin(ext_id: str, update_url: str) -> str:
    """The "Policy for extensions" box takes each value wrapped in {"Value": ...}."""
    return json.dumps({k: {"Value": v} for k, v in settings().items()}, indent=2) + "\n"


def readme(ext_id: str, update_url: str, version: str) -> str:
    base = update_url.rsplit("/", 1)[0] + "/mdm"
    return f"""VotalAI Guardrails {version}: files for your MDM
========================================================

Extension id:  {ext_id}
Update URL:    {update_url}
Force-install: {ext_id};{update_url}
Package:       {update_url.rsplit("/", 1)[0]}/votalai-guardrails-{version}.crx
MDM files:     {base}/

Chrome and Edge fetch the package themselves from the update URL, and update
it when a new version is published there: upload these files once.

Every file installs the extension in Chrome and Edge and sets its settings.
Before uploading, replace:

  REPLACE_WITH_TENANT_KEY   your Shield tenant key (use one made for this,
                            not an admin key: a local administrator can read it)
  REPLACE_WITH_USER_ID      who uses the laptop, usually your MDM's email
                            variable; or delete the line to report the device
  REPLACE_WITH_DEVICE_ID    the laptop, usually your MDM's device-name or
                            serial-number variable

Variable names differ by MDM (Jamf: $EMAIL and $COMPUTERNAME; Kandji and
Intune have their own). Use the ones your MDM documents for custom profiles.

macOS: Jamf Pro, Kandji, Intune for Mac
  votalai-guardrails.mobileconfig
  Jamf: Computers > Configuration Profiles > Upload.
  Kandji: Library > Add new > Custom Profile.
  Intune: Devices > macOS > Configuration > Templates > Custom.
  One profile, four payloads: Chrome and Edge, install and settings.

Windows: Intune or Group Policy
  install-votalai-guardrails.ps1   Intune platform script (system, 64-bit),
                                   or a GPO computer startup script. Set
                                   $TenantKey at the top first.
  votalai-guardrails.reg           the same settings as a registry file.

Linux
  votalai-guardrails-linux.json   copy to /etc/opt/chrome/policies/managed/

Google Admin console (Chrome Browser Cloud Management)
  Apps & extensions > add by ID {ext_id} with custom URL {update_url},
  Installation policy "Force install", then paste
  google-admin-policy.json into "Policy for extensions".

Check on a test laptop
  chrome://policy        shows ExtensionInstallForcelist and the settings
  chrome://extensions    VotalAI Guardrails {version}, installed by your organisation
  Off-store force-install works only on managed machines (MDM, domain-joined,
  or Chrome Browser Cloud Management).

Files: {base}/
Guide: https://github.com/sundi133/llm-shield/blob/main/docs/enterprise-install.md
"""


FILES = {
    "votalai-guardrails.mobileconfig": mobileconfig,
    "install-votalai-guardrails.ps1": powershell,
    "votalai-guardrails.reg": reg,
    "votalai-guardrails-linux.json": linux,
    "google-admin-policy.json": google_admin,
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--id", required=True, help="the extension id")
    ap.add_argument("--update-url", required=True, help="https URL of update.xml")
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / "extension" / "mdm")
    args = ap.parse_args(argv)
    if not re.match(r"^[a-p]{32}$", args.id):
        raise SystemExit("--id: 32 letters a-p (a Chrome extension id)")
    if not args.update_url.startswith("https://"):
        raise SystemExit("--update-url must be https")
    version = json.loads((ROOT / "examples" / "browser-extension" / "manifest.json")
                         .read_text())["version"]
    args.out.mkdir(parents=True, exist_ok=True)
    for name, build in FILES.items():
        data = build(args.id, args.update_url)
        (args.out / name).write_bytes(data if isinstance(data, bytes) else data.encode())
    (args.out / "README.txt").write_text(readme(args.id, args.update_url, version))
    for name in sorted(list(FILES) + ["README.txt"]):
        print(args.out / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
