# Shield Prompt Guard (POC)

A minimal Chrome MV3 extension that screens prompts on **public AI tools**
through Votal Shield's `/guardrails/input` **before** they are sent. Best-effort
client-side shadow-AI DLP / visibility — **not** a security boundary (a user can
disable it).

## Supported sites
| Site | Host |
|---|---|
| Claude | `claude.ai` |
| ChatGPT | `chatgpt.com`, `chat.openai.com` |
| Gemini | `gemini.google.com` |
| Microsoft Copilot | `copilot.microsoft.com` |

Selectors are per-site (see `SITES` in `content.js`); adding another site is a
few lines. Generic fallbacks are appended so a minor markup change still has a
chance of working.

## What it does
- Intercepts the send action on each site (Enter key + send button).
- Sends the composer text to Shield from the **background service worker**
  (so it bypasses the page CSP and can attach the RunPod `Authorization`
  bearer + tenant `X-API-Key` headers).
- **monitor** mode: flags (yellow banner) but always sends. **enforce** mode:
  blocks on a Shield block verdict (red banner). **off**: does nothing.
- **Fail-open**: if Shield is unreachable/slow (12s timeout) the prompt sends
  unscreened with a "Shield unreachable" banner — it never traps your chat.

## Install (Load unpacked)
1. Chrome → `chrome://extensions` → toggle **Developer mode** (top right).
2. **Load unpacked** → select this `shield-prompt-guard/` folder.
3. Click the extension icon → **Settings**, fill in:
   - **Shield URL** — e.g. `https://kebrpqdbp1log1.api.runpod.ai`
   - **Tenant API key** — e.g. `bank-co-key`
   - **RunPod proxy token** — `rpa_…` (only if behind RunPod's gateway)
   - **Mode** — start on `monitor`.
4. Extension popup → **Test connection** → expect `✓ Reached Shield`.
5. Open claude.ai, type a prompt, hit Enter — watch for the banner. Try a
   jailbreak-style prompt in `enforce` mode to see a block.

## Verify it reached Shield
The screened prompts appear in your Shield **Telemetry**, endpoint
`/guardrails/input` — same pipe as the Claude Code hook. With attribution
configured (below) the **agent column shows the user's email** instead of
`unknown-agent`.

## Attribution (who + which device)
The background worker attaches identity to every screened prompt:
- **`X-Agent-Key`** = corporate email from `chrome.identity.getProfileUserInfo()`
  (reliable on managed Chrome where the user is signed into the corp account),
  falling back to the device id.
- **`X-Device-Id`** = a device/asset id from **managed policy** (`storage.managed`
  → `deviceId`), falling back to a stable per-install UUID.
- The email + device id are also included in the request body (`user_email`,
  `device_id`) for audit.

A true hardware serial is **not** available to a normal extension (browser
sandbox). On **ChromeOS managed devices** only, `chrome.enterprise.deviceAttributes`
can provide the real serial/asset id — not available on Windows/macOS.

> Attribution is employee monitoring — deploy via corporate policy with notice.

## Known limits (by design — this is a POC)
- **Brittle**: depends on each site's DOM. If a site's composer/send markup
  changes, update that site's entry in the `SITES` map in `content.js`.
- **Bypassable**: disabling the extension or using the API directly evades it.
  It's a nudge/visibility layer, not enforcement.
- **Output is post-hoc**: only prompts are screened here; model responses stream
  into the DOM and would need separate (after-the-fact) redaction.
- **Token storage**: keys live in `chrome.storage.local` (plaintext-ish). Fine
  for a POC/demo; for fleet rollout use managed policy + a short-lived token.

## Fleet rollout (Chrome Enterprise)
Force-install and configure via **managed policy** — no per-user setup. The
schema is in `managed_schema.json`; admins push values under
`3rdparty.extensions.<extension-id>.policy`, e.g.:

```json
{
  "shieldUrl":  "https://shield.yourco.internal",
  "tenantKey":  "altayer-retail-key",
  "proxyToken": "rpa_...",
  "deviceId":   "${machine_name}",
  "mode":       "enforce"
}
```

Managed values **override** local config, so users can't change the endpoint or
disable enforcement. `${machine_name}` (and other policy variables) let the OS
inject the device identifier. Cross-platform: same code on Chrome/Edge for
**Windows, macOS, Linux, ChromeOS**.

## Files
| File | Role |
|---|---|
| `manifest.json` | MV3 manifest, permissions, content-script + background wiring |
| `background.js` | calls Shield `/guardrails/input` with headers; verdict logic |
| `content.js` | intercepts send on claude.ai; banner UI; approved-replay |
| `options.html/js` | config (URL, keys, mode) |
| `popup.html/js` | mode toggle + Test connection |
