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
python scripts/pack_extension.py \
  --key ~/.votal/extension-signing/votalai-guardrails.pem \
  --base-url https://storage.googleapis.com/votal-public/extension \
  --out dist/extension
```

It writes `votalai-guardrails-<version>.crx` and `update.xml`, and prints the
extension ID and the force-install line. It needs no browser, so it also runs
in CI.

- **Guard the key.** It determines the extension ID, and every future update
  must be signed with the same key. Keep it in a secret manager, never in git
  (the script refuses a key inside the repository). Add `--new-key` on the very
  first pack only: a new key is a new ID, and every customer's policy would
  point at one you can no longer publish.
- The extension ID is stable across versions:
  `gcbcablddjeicimnfipalnckffoiihnb`.

## 2. Votal: host two files over HTTPS

Any static HTTPS host works. Votal's are in a public storage bucket:

| File | URL |
|---|---|
| the signed package | `https://storage.googleapis.com/votal-public/extension/votalai-guardrails-<version>.crx` |
| the update manifest Chrome polls (roughly every 5 hours) | `https://storage.googleapis.com/votal-public/extension/update.xml` |

```bash
gsutil -h "Content-Type:application/x-chrome-extension" \
  cp dist/extension/votalai-guardrails-*.crx gs://votal-public/extension/
gsutil -h "Content-Type:application/xml" -h "Cache-Control:no-cache, max-age=0" \
  cp dist/extension/update.xml gs://votal-public/extension/
```

Shipping an update: bump `version` in `manifest.json`, pack with the same key,
upload both files. Upload the package first, then `update.xml`, so the
manifest never names a file that is not there yet. Every enrolled fleet updates
within hours; no customer action is needed.

## 3. Customer IT: force-install policy

One policy line, delivered through whatever already manages Chrome:

```
ExtensionInstallForcelist = ["gcbcablddjeicimnfipalnckffoiihnb;https://storage.googleapis.com/votal-public/extension/update.xml"]
```

Per platform:

- **Windows (GPO / Intune)**: registry value under
  `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`
  (string value `1` = `gcbcablddjeicimnfipalnckffoiihnb;https://storage.googleapis.com/votal-public/extension/update.xml`).
  Google publishes ADMX templates for Group Policy.
- **macOS (Jamf / Intune / other MDM)**: configuration profile targeting
  `com.google.Chrome`, key `ExtensionInstallForcelist`, array of the same
  string.
- **Linux**: JSON file in `/etc/opt/chrome/policies/managed/`, e.g.
  `{"ExtensionInstallForcelist": ["gcbcablddjeicimnfipalnckffoiihnb;https://storage.googleapis.com/votal-public/extension/update.xml"]}`.
- **Chrome Browser Cloud Management** (Google Admin console, free): Devices >
  Chrome > Apps & extensions, add by ID with a custom update URL. Works across
  all desktop platforms from one console.
- **Microsoft Edge**: identical policy name under
  `HKLM\Software\Policies\Microsoft\Edge` (Windows) or `com.microsoft.Edge`
  (macOS). The same `.crx` and `update.xml` serve both browsers. See the
  Edge note below.

### Microsoft Edge (same extension, no rebuild)

The extension is standard Chromium MV3 and runs on Edge with **no code
changes**: the `chrome.*` APIs and every manifest key it uses are supported
identically. Only two things differ, and both are the admin's, not the
extension's:

- **Policy location**: force-install (`ExtensionInstallForcelist`) and the
  `3rdparty` managed-storage config live under the Edge policy namespace
  (`.../Policies/Microsoft/Edge`), not Google Chrome's. Same key names, same
  values.
- **Distribution**: to force-install by ID, either publish to the
  **Microsoft Edge Add-ons** store (a separate Partner Center submission from
  the Chrome Web Store) or self-host the `.crx` + `update.xml` and point the
  Edge forcelist at the update URL, the same self-host path described above.
  Edge can also install from the Chrome Web Store, but only if the user
  enables "Allow extensions from other stores," which is not suitable for a
  managed control.

## 4. Customer IT: configuration policy (managed storage)

The extension reads its config from Chrome managed storage (schema:
`examples/browser-extension/managed_schema.json`). Push values under the
`3rdparty` policy namespace:

```json
{
  "3rdparty": {
    "extensions": {
      "gcbcablddjeicimnfipalnckffoiihnb": {
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
