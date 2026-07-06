# VotalAI Guardrails: Enterprise Install (without the Chrome Web Store)

Managed Chrome and Edge fleets can force-install VotalAI Guardrails directly
from a Votal-hosted package. No Chrome Web Store listing is involved, the
extension appears in every managed browser pre-configured, and end users
cannot disable or remove it.

There are two roles below: **Votal** (packs, signs, and hosts the extension)
and **Customer IT** (pushes two browser policies through their existing
management tooling).

## 1. Votal: pack and sign the extension (once per release)

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --pack-extension=examples/browser-extension \
  --pack-extension-key=shield-prompt-guard.pem   # omit on the very first pack
```

- The first pack (without `--pack-extension-key`) generates
  `shield-prompt-guard.pem`. **Guard this key.** It determines the extension
  ID, and every future update must be signed with the same key. Store it in a
  secret manager, never in git.
- Output is `browser-extension.crx`. Rename it
  `shield-prompt-guard-<version>.crx`.
- The extension ID (a 32-char string like `abcdefghijklmnopabcdefghijklmnop`)
  is stable across versions. Read it by dragging the `.crx` onto
  `chrome://extensions` on any machine, or from the packing output.

## 2. Votal: host two files over HTTPS

Host on any static HTTPS endpoint (for example `https://downloads.votal.ai`):

| File | Purpose |
|---|---|
| `shield-prompt-guard.crx` | the signed extension package |
| `update.xml` | update manifest Chrome polls (roughly every 5 hours) |

`update.xml`:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='EXTENSION_ID'>
    <updatecheck codebase='https://downloads.votal.ai/shield-prompt-guard.crx'
                 version='1.0.0'/>
  </app>
</gupdate>
```

Shipping an update: bump `version` in `manifest.json`, repack with the same
`.pem`, replace both files. Every enrolled fleet updates automatically within
hours; no customer action is needed.

## 3. Customer IT: force-install policy

One policy line, delivered through whatever already manages Chrome:

```
ExtensionInstallForcelist = ["EXTENSION_ID;https://downloads.votal.ai/update.xml"]
```

Per platform:

- **Windows (GPO / Intune)**: registry value under
  `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`
  (string value `1` = `EXTENSION_ID;https://downloads.votal.ai/update.xml`).
  Google publishes ADMX templates for Group Policy.
- **macOS (Jamf / Intune / other MDM)**: configuration profile targeting
  `com.google.Chrome`, key `ExtensionInstallForcelist`, array of the same
  string.
- **Linux**: JSON file in `/etc/opt/chrome/policies/managed/`, e.g.
  `{"ExtensionInstallForcelist": ["EXTENSION_ID;https://downloads.votal.ai/update.xml"]}`.
- **Chrome Browser Cloud Management** (Google Admin console, free): Devices >
  Chrome > Apps & extensions, add by ID with a custom update URL. Works across
  all desktop platforms from one console.
- **Microsoft Edge**: identical policy name under
  `HKLM\Software\Policies\Microsoft\Edge` (Windows) or `com.microsoft.Edge`
  (macOS). The same `.crx` and `update.xml` serve both browsers.

## 4. Customer IT: configuration policy (managed storage)

The extension reads its config from Chrome managed storage (schema:
`examples/browser-extension/managed_schema.json`). Push values under the
`3rdparty` policy namespace:

```json
{
  "3rdparty": {
    "extensions": {
      "EXTENSION_ID": {
        "policy": {
          "shieldUrl":  "https://api.guardrails.votal.ai",
          "tenantKey":  "acme-tenant-key",
          "deviceId":   "${machine_name}",
          "userId":     "jane.doe@acme.com",
          "mode":       "enforce"
        }
      }
    }
  }
}
```

Notes:

- `shieldUrl` is optional; it defaults to `https://api.guardrails.votal.ai`.
  A self-hosted Shield endpoint also requires adding that host to
  `host_permissions` in `manifest.json` and repacking.
- `userId` and `deviceId` are the attribution fields shown in Shield
  Telemetry. The extension collects no identity on its own; what to inject
  (employee id, AD account, email, asset tag) is the customer's decision.
  Policy variables such as `${machine_name}` are expanded by the OS/MDM.
- Managed values override anything a user enters locally, and `mode` set to
  `enforce` cannot be turned off by the user.

## 5. Verify a rollout

1. On a managed machine, open `chrome://extensions`. VotalAI Guardrails
   shows an "Installed by your administrator" badge and no Remove button.
2. Open `chrome://policy` and confirm `ExtensionInstallForcelist` and the
   `3rdparty` block are present with status OK.
3. Click the extension icon, then Test connection. Expect a green check with
   the policy-pushed user and device identifiers echoed back.
4. In enforce mode, paste a known-blocked prompt into claude.ai. The red
   Shield banner should appear and the event should show in Shield Telemetry
   with the expected agent (userId) and device columns.

## Constraints

- Force-installing an off-store `.crx` only works on genuinely managed
  browsers: Windows machines must be AD domain-joined or CBCM-enrolled
  (Chrome ignores the policy on unmanaged home machines), and macOS/Linux
  need the policy delivered via MDM or managed policy files. For enterprise
  fleets this is a given.
- Unmanaged users cannot install a `.crx` by double-clicking (Chrome blocks
  off-store installs). For POCs and small teams, use the Chrome Web Store
  listing or Load unpacked instead.
- The middle path is the store's private/organization publishing: Google
  hosts the package, only approved Workspace domains see it, and IT
  force-installs by ID with no self-hosted `update.xml`. Offering both
  channels is common; self-hosting suits customers who do not want a
  dependency on Google infrastructure.
