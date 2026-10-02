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

## Ready-made MDM files

Votal publishes the files for every MDM next to the package, already filled in
with the extension ID and update URL. Each installs the extension in Chrome and
Edge and sets its configuration (section 4). Replace `REPLACE_WITH_TENANT_KEY`,
`REPLACE_WITH_USER_ID` and `REPLACE_WITH_DEVICE_ID` before uploading.

| MDM | File |
|---|---|
| Jamf Pro, Kandji, Intune for Mac | [`votalai-guardrails.mobileconfig`](https://storage.googleapis.com/votal-public/extension/mdm/votalai-guardrails.mobileconfig) |
| Intune (Windows), Group Policy | [`install-votalai-guardrails.ps1`](https://storage.googleapis.com/votal-public/extension/mdm/install-votalai-guardrails.ps1) or [`votalai-guardrails.reg`](https://storage.googleapis.com/votal-public/extension/mdm/votalai-guardrails.reg) |
| Linux | [`votalai-guardrails-linux.json`](https://storage.googleapis.com/votal-public/extension/mdm/votalai-guardrails-linux.json) |
| Google Admin console | [`google-admin-policy.json`](https://storage.googleapis.com/votal-public/extension/mdm/google-admin-policy.json) |
| All of the above, with a README | [`votalai-guardrails-mdm.zip`](https://storage.googleapis.com/votal-public/extension/mdm/votalai-guardrails-mdm.zip) |

Votal regenerates them with `scripts/build_extension_mdm.py` when the ID or
update URL changes; a new extension version needs no new MDM files.

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

Every setting, including the tenant key, is pushed by MDM. Nothing is typed on
the laptop, and a value set by policy overrides anything entered locally.

| Setting | Required | What it is |
|---|---|---|
| `tenantKey` | yes | Your Shield tenant API key. It selects your tenant and its policy |
| `mode` | yes | `enforce` blocks, `warn` shows a warning and lets the user continue, `off` disables screening |
| `userId` | recommended | Who the user is, shown in Shield Telemetry (employee id, AD account or email: your choice) |
| `deviceId` | recommended | The machine, for example `${machine_name}` or an asset tag |
| `shieldUrl` | no | Defaults to `https://api.guardrails.votal.ai` |
| `proxyToken` | no | Bearer token for a proxy in front of Shield (RunPod deployments) |
| `timeoutMs` | no | How long to wait for a verdict, in milliseconds (default 45000) |
| `failOpen` | no | If Shield cannot be reached in enforce mode: `false` (default) blocks the prompt, `true` sends it unscreened |

The schema is `examples/browser-extension/managed_schema.json`. The values go
under the extension's ID in the `3rdparty` policy namespace:

```json
{
  "3rdparty": {
    "extensions": {
      "gcbcablddjeicimnfipalnckffoiihnb": {
        "policy": {
          "tenantKey":  "acme-tenant-key",
          "mode":       "enforce",
          "userId":     "jane.doe@acme.com",
          "deviceId":   "${machine_name}"
        }
      }
    }
  }
}
```

Per platform:

- **Windows (GPO / Intune)**: string values under
  `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\gcbcablddjeicimnfipalnckffoiihnb\policy`,
  one per setting (`tenantKey`, `mode`, `userId`, `deviceId`). In Intune, push
  them with a PowerShell script or a custom OMA-URI registry policy.
- **macOS (Jamf / Kandji / Intune)**: a configuration profile whose preference
  domain is `com.google.Chrome.extensions.gcbcablddjeicimnfipalnckffoiihnb`, with the settings as keys.
  In Jamf this is "Application & Custom Settings"; in Kandji and Intune, a
  custom profile.
- **Linux**: the JSON above as a file in `/etc/opt/chrome/policies/managed/`.
- **Chrome Browser Cloud Management** (Google Admin console): on the
  extension's page under Apps & extensions, paste the inner `policy` object
  into "Policy for extensions". Each setting is wrapped as
  `{"tenantKey": {"Value": "acme-tenant-key"}, "mode": {"Value": "enforce"}}`.
- **Microsoft Edge**: the same settings under
  `HKLM\Software\Policies\Microsoft\Edge\3rdparty\extensions\gcbcablddjeicimnfipalnckffoiihnb\policy`
  (Windows) or the domain `com.microsoft.Edge.extensions.gcbcablddjeicimnfipalnckffoiihnb` (macOS).

### About the tenant key

- **Use a key made for this.** Create a separate tenant key for the extension
  with the `runtime` scope, not an admin key. A managed setting can be read by
  anyone with administrator rights on the laptop, and in `chrome://policy`.
- **One key per fleet, or one for the company.** The key identifies the
  tenant, not the person: `userId` and `deviceId` say who and where. Separate
  keys per fleet let you rotate one group without touching the others.
- **To rotate:** create the new key, push it by MDM, wait until laptops have
  picked it up (`chrome://policy` shows the new value), then revoke the old
  key in the Shield portal. Chrome applies a changed policy without a restart.
- **A missing or wrong key** does not stop the browser. The extension's Test
  connection reports it, and Shield applies its default policy or refuses the
  call, depending on how your Shield is configured.

Other notes:

- A self-hosted Shield endpoint needs more than `shieldUrl`: that host must
  also be in `host_permissions` in `manifest.json`, and the extension repacked.
- The extension collects no identity on its own. What to put in `userId` and
  `deviceId` is your decision. Variables such as `${machine_name}` are
  expanded by the OS or MDM where it supports them; otherwise your MDM's own
  variables (for example Jamf's `$COMPUTERNAME`) do the same job.
- `mode` set to `enforce` by policy cannot be turned off by the user.

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
