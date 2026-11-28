# Spec: Firefox support for the VotalAI Guardrails browser extension

Status: **draft, awaiting approval** (2026-11-28). Branch `spec/firefox-extension`.

Builds on `examples/browser-extension` (MV3, version 1.4.1), its packager
`scripts/pack_extension.py` (signed CRX3 + `update.xml` for Chrome and Edge),
`docs/enterprise-install.md`, and the fail-closed rule in
`examples/browser-extension/fail_policy.js` (#569). Complements
`docs/specs/device-kit-firefox-terminal.md`, which sends Firefox *traffic* to
the device agent through the PAC; this spec covers the *extension* in Firefox,
for laptops without the agent or with the agent's proxy off.

## 1. Problem & outcome

**Problem.** The extension runs in Chrome and Edge only. A Firefox user's
prompts and file uploads on claude.ai, ChatGPT, Gemini and Copilot are not
screened unless the laptop has the device agent with its proxy on. Customers
with Firefox users (POC "Test Cases G" AG-03) have no browser-level coverage.

What stops the current package from running in Firefox (checked against main
at `81ac68e`):

1. `manifest.json` declares `"background": {"service_worker": "background.js"}`.
   Firefox does not run MV3 background service workers; it runs background
   scripts (an event page) listed in `background.scripts`.
2. `background.js` loads its modules with `importScripts("agent_client.js")`,
   `verdict_text.js`, `fail_policy.js` and `exception_client.js`.
   `importScripts` exists only in a worker, so an event page throws on the
   first line.
3. No `browser_specific_settings.gecko.id`. Firefox needs a fixed add-on ID for
   `storage.managed` (policy-pushed `userId`, `deviceId`, `tenantKey`, `mode`,
   `failOpen`) and for `nativeMessaging`. Firefox also only installs
   permanently a package Mozilla has signed, and signing needs that ID.
4. In Firefox MV3 the user can withdraw the extension's access to a site
   (Extensions, Permissions). The content script then stops running on that
   site, so screening is off for it with nothing to say so. Chrome has a
   similar per-site setting, but it is less exposed; we handle both.
5. Policy for Firefox lives elsewhere: `HKLM\SOFTWARE\Policies\Mozilla\Firefox`
   on Windows, the `org.mozilla.firefox` preference domain on macOS, or
   `policies.json`. The NDML kit's policy scripts and `docs/enterprise-install.md`
   cover Chrome and Edge only.

The rest of the code already uses APIs Firefox supports under the `chrome.*`
namespace with callbacks: `runtime.sendMessage`, `onMessage`,
`openOptionsPage`, `sendNativeMessage`, `lastError`, `storage.local`,
`storage.managed`, `storage.onChanged`.

**Outcome.**
- One source tree, two builds: the Chrome/Edge build is unchanged (same
  manifest, same CRX, same ID); `scripts/pack_extension.py --target firefox`
  writes a Firefox build (unpacked folder and `.xpi`) with a fixed ID.
- In current Firefox release and ESR, the Firefox build blocks and flags
  exactly as the Chrome build does for prompts and file uploads on the four
  sites, in monitor and enforce mode, including the fail-closed rule.
- If the user withdraws site access, the popup says which sites are not
  screened, and Test connection reports it.
- Admins can force-install it and push `userId`, `deviceId`, `tenantKey` and
  `mode` by Firefox policy, documented with working examples.
- Success is observable: in Firefox, a card number typed into chatgpt.com in
  enforce mode is not sent and the red banner names the policy; the prompt
  shows in Telemetry with the policy-pushed user in the Agent column.

**Non-goals.**
- Firefox for Android, Safari.
- The device agent's native messaging host for Firefox (the extension falls
  back to cloud screening when the host is absent: `agentHello` resolves
  `null` on `lastError`). Follow-up: `platform/native_messaging.py` writes
  Mozilla's manifest locations with `allowed_extensions`.
- Publishing a listed add-on on addons.mozilla.org. Distribution is a signed,
  unlisted `.xpi` (section 6).
- Preventing a user from withdrawing site access. Firefox has no policy that
  locks per-site host permissions; we detect and report, as with disabling
  the extension today ("Bypassable" in the README).

## 2. Plane & latency contract

- **Client only.** No server, admin-plane or data-plane change. No change to
  `/guardrails/*`, `cap/mint` or `tools/call` and no server-side work per
  request: the Firefox build calls the same `/guardrails/input` and
  `/guardrails/file` with the same headers.
- **Off the hot path.** Screening latency in Firefox is the same network call
  as in Chrome. The site-access check runs at startup, when permissions change,
  and when the popup opens, never per prompt.

## 3. Data model

- No Redis keys, no server state.
- Extension storage keys are unchanged (`chrome.storage.local`: `shieldUrl`,
  `tenantKey`, `proxyToken`, `mode`, `timeoutMs`, `installId`, exception
  records; `chrome.storage.managed`: the `managed_schema.json` keys).
- New manifest fields in the Firefox build only:
  `browser_specific_settings.gecko.id = "guardrails@votal.ai"` and
  `strict_min_version` (set in task 1 to the oldest ESR the build passes on;
  expected `128.0`), plus `gecko.update_url` when packed with `--base-url`.
- Tenant scoping unchanged: the tenant comes from the key, as today.

## 4. API / interface

**Packager.** `scripts/pack_extension.py` gains `--target chrome|firefox`
(default `chrome`, so every existing invocation is unchanged).

- `--target firefox` reads `examples/browser-extension/manifest.json` and
  writes a derived manifest:
  - `background`: `{"scripts": ["agent_client.js", "verdict_text.js",
    "fail_policy.js", "exception_client.js", "background.js"]}` (the
    `importScripts` order) instead of `service_worker`.
  - `browser_specific_settings.gecko`: `id`, `strict_min_version`, and
    `update_url` when `--base-url` is given.
  - `options_ui: {"page": "options.html", "open_in_tab": true}` in place of
    `options_page`.
  - `storage.managed_schema` dropped (Firefox ignores it; the schema stays
    the source of truth for Chrome and for docs).
- It writes `dist/extension-firefox/votalai-guardrails-<version>/` (unpacked)
  and `votalai-guardrails-<version>.xpi` (unsigned zip, same file exclusions as
  the CRX), and `updates.json` when `--base-url` is given.
- Signing is a separate, documented operator step (section 6). The packager
  never holds Mozilla credentials.

**`background.js`.** Module loading becomes
`if (typeof importScripts === "function") importScripts(...)`. In Firefox the
same modules arrive first through `background.scripts`. No other change.

**Site access.** New in `background.js`, pure logic in a new
`site_access.js` (loaded like `fail_policy.js`):

- `siteAccess()` returns `{covered: [...], missing: [...]}` for the four sites
  and the Shield host, from `chrome.permissions.contains`.
- Checked on startup and on `chrome.permissions.onRemoved` / `onAdded`. When
  something is missing, the toolbar badge shows `!`.
- The popup lists the missing sites with a button that calls
  `chrome.permissions.request` (a user gesture, so allowed in both browsers).
- Test connection adds a line per missing site.
- Missing access to the Shield host means no verdict, which in enforce mode
  now holds the prompt (#569); the popup says so.

**Policy (docs and NDML kit scripts).** Same keys as Chrome, Firefox's
locations:

- Windows: `HKLM\SOFTWARE\Policies\Mozilla\Firefox\3rdparty\Extensions\guardrails@votal.ai`
  with string values `userId`, `deviceId`, and so on.
- macOS: a profile payload for the `org.mozilla.firefox` domain with
  `EnterprisePoliciesEnabled = true` and
  `3rdparty.Extensions["guardrails@votal.ai"]`.
- `policies.json`: the same under `policies.3rdparty.Extensions`.
- Force install: `ExtensionSettings["guardrails@votal.ai"]` with
  `installation_mode: "force_installed"` and `install_url` pointing at the
  hosted signed `.xpi`.

## 5. Security & backward compatibility

- **Chrome and Edge unchanged.** Their manifest, CRX, extension ID and
  `update.xml` are byte-for-byte what they are today. The only shared code
  change is the `importScripts` guard, which is a no-op in a worker. A
  regression test asserts the Chrome manifest is untouched.
- **No default changes.** The Firefox build applies the same modes, the same
  `failOpen` rule (enforce holds when there is no verdict) and the same
  45-second timeout.
- **Fixed Firefox ID.** `guardrails@votal.ai` is public by design, as Chrome
  extension IDs are. Only a Mozilla-signed package with that ID installs
  permanently, and signing needs our AMO account. Anyone can load a
  *temporary* add-on with the same ID in their own browser, but that gives
  them nothing beyond what they can already do: the tenant key is still
  needed to screen, and policy cannot be pushed to it from outside.
- **Withdrawn site access** is detected and shown (section 4). It cannot be
  prevented, and the README's "Known limits" says so for Firefox.
- **Keys.** As today, `tenantKey` should come from policy, not be typed into
  options, for fleets. `storage.local` is per-profile.

## 6. Packaging & deploy

- **No Python or admin-plane change.** No `admin_app.py` import, so
  `Dockerfile.admin` is untouched. No new runtime pip dependency.
- **Lint in CI:** a new step in the existing `extension (node)` job runs
  `npx --yes web-ext@<pinned> lint --source-dir dist/extension-firefox/...`
  on the Firefox build. Node tooling only, version pinned in the workflow.
- **End-to-end test dependency:** the Firefox test (task 4) needs Selenium
  and geckodriver.
  - Selenium is a test-only pip dependency, added to `requirements-test.txt`
    with the test guarded by `pytest.importorskip("selenium")` and an opt-in
    env flag (`VOTAL_FIREFOX_E2E=1`), as the Claude Code e2e does.
  - The CI job installs Firefox and geckodriver with pinned setup actions.
  - **Invariant check:** new pip import -> `requirements-test.txt` only, since
    nothing at runtime imports it. `requirements.txt` and
    `requirements-admin.txt` are unchanged. Validated in a clean venv.
- **Signing and hosting** (operator runbook in `docs/enterprise-install.md`):
  - `npx web-ext sign --channel=unlisted` with Votal's AMO API key and secret,
    which live in the operator's vault, never in the repo or CI.
  - Host the signed `.xpi` and `updates.json` next to the CRX.
  - Customers point `ExtensionSettings.install_url` at it.
  - For a POC without signing, Firefox Developer Edition or ESR can load it
    with `xpinstall.signatures.required=false`, or anyone can use
    `about:debugging` (temporary, until restart).
- **NDML-style kits:** add a `votal-shield-extension-firefox/` folder (the
  unpacked Firefox build) and Firefox branches in
  `policy/windows/set-extension-policy.ps1` and
  `policy/macos/make-extension-profile.sh`. Neither needs an ID argument for
  Firefox, since the ID is fixed.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Firefox older than `strict_min_version` | Firefox refuses the install with its own message; documented. |
| Background event page unloaded when idle | Messages from the content script wake it (as the Chrome worker does); no state kept in memory except the agent connection cache, which is rebuilt. |
| `importScripts` absent (Firefox) | Guarded; modules already loaded through `background.scripts`. Test asserts the guard and the script order match. |
| Site access withdrawn for chatgpt.com | No content script there: nothing is screened on that site. Badge `!`, popup lists it, Test connection reports it. |
| Shield host access withdrawn | Fetch fails, so there is no verdict: enforce holds ("Not sent"), monitor sends with "Shield unreachable" (#569 rule). Popup says why. |
| Native messaging host absent (no agent, or agent without Firefox host) | `agentHello` gets `lastError` and returns `null`; cloud screening, as on unmanaged Chrome. |
| Replay of an approved send in Firefox's content-script sandbox (synthetic `KeyboardEvent`, `btn.click()`, a rebuilt `DataTransfer` for drop/paste) | Must still reach the site's handlers. Verified in task 4 for Enter, the send button, the file picker, drop and paste. If drop or paste replay fails under Firefox's content-script wrappers, task 1 adds `cloneInto` / `window.wrappedJSObject` handling for Firefox only, behind a feature check. |
| `document.execCommand("insertText")` (redaction rewrite) | Supported in Firefox; covered by the e2e redact case. |
| Policy pushed but user opens options | Managed values override local ones, as in Chrome (`getConfig`). |
| Unsigned `.xpi` in release Firefox | Firefox refuses it; the docs give the signed path and the POC options. |
| Huge file / over 10 MB | Same caps and notes as Chrome (shared code). |

## 8. Test plan (Definition of Done)

- **Unit (node, CI `extension (node)` job):**
  - `site_access.test.js`: covered and missing lists, and the badge and
    popup messages, with `chrome.permissions` stubbed.
  - Background loading: `importScripts` is guarded and the Firefox build's
    `background.scripts` list matches the `importScripts` order in
    `background.js`. This is the drift guard: a new module added to one
    must be added to the other.
- **Packager (pytest, `tests/test_pack_extension.py`):**
  - `--target firefox` writes a manifest with `gecko.id`,
    `background.scripts` and no `service_worker`; an `.xpi` that excludes
    `test/` and `README.md`; and `updates.json` when `--base-url` is given.
  - `--target chrome` (and no flag) output is unchanged: the same file
    list, and a manifest identical to the source.
- **Lint:** `web-ext lint` on the Firefox build has zero errors (CI step).
- **End to end (task 4, `VOTAL_FIREFOX_E2E=1`, CI job with Firefox ESR and
  release):**
  - Selenium + geckodriver loads the build as a temporary add-on.
  - Configuration goes into `storage.local` from the background page, never
    typed into a page.
  - A stand-in chat page is served on localhost from a test-only manifest
    variant that adds `http://localhost/*` to the content-script matches. The
    variant is built only by the test. A fake Shield answers block, pass,
    flag or error.
  - Asserted, as in the Chromium run of 2026-11-28:
    - enforce blocks with the policy banner, and pass sends;
    - monitor flags and sends;
    - no verdict holds in enforce and sends in monitor;
    - a file picker upload is blocked, and drop and paste replays reach the
      page;
    - withdrawing site access shows the badge.
- **Manual, once per release:**
  - The signed `.xpi` force-installed by `policies.json` on macOS and
    Windows.
  - The policy-pushed `userId` appears in Telemetry.
  - One real prompt on each of the four real sites, in a test account.
- **Suite:** full suite green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each, in order)

1. **Firefox build.**
   - The `importScripts` guard and `pack_extension.py --target firefox`
     (manifest transform, unpacked folder, `.xpi`, `updates.json`).
   - Packager tests and the script-order drift guard.
   - The `web-ext lint` CI step.
   - A one-time manual load in Firefox release and ESR (`web-ext run`) to
     pin `strict_min_version`, and to check the replay cases that the e2e
     will then automate. Fixes go in this PR if needed.
2. **Site-access check.**
   - `site_access.js`, the badge, popup lines with the re-grant button, and
     Test connection lines. For both browsers.
   - Node tests, and README "Known limits".
3. **Firefox policy and docs.**
   - Firefox sections in `docs/enterprise-install.md`: signing, hosting,
     `ExtensionSettings`, the `3rdparty` policy for Windows, macOS and
     `policies.json`.
   - README install steps.
   - The Firefox branches of the kit policy scripts.
4. **Firefox end-to-end test.**
   - The opt-in e2e test, the test-only manifest variant and a fake Shield.
   - A CI job with Firefox ESR and release, and the Selenium test dependency.

## Open questions (defaults in brackets)

1. Add-on ID: [`guardrails@votal.ai`]. It can never change once customers
   force-install it.
2. Distribution: [signed unlisted `.xpi`, self-hosted next to the CRX], rather
   than a listed AMO add-on.
3. Minimum Firefox: [the oldest supported ESR, expected 128], pinned in task 1.
