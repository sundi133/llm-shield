# Shield Prompt Guard (POC)

A minimal Chrome MV3 extension that screens **claude.ai** prompts through Votal
Shield's `/guardrails/input` **before** they are sent. Best-effort client-side
DLP / shadow-AI visibility — **not** a security boundary (a user can disable it).

## What it does
- Intercepts the send action on claude.ai (Enter key + send button).
- Sends the composer text to Shield from the **background service worker**
  (so it bypasses claude.ai's page CSP and can attach the RunPod `Authorization`
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
The screened prompts appear in your Shield **Telemetry** (as `unknown-agent`,
endpoint `/guardrails/input`) — same pipe as the Claude Code hook.

## Known limits (by design — this is a POC)
- **Brittle**: depends on claude.ai's DOM. If the composer/send markup changes,
  update the selectors in `content.js` (`getComposer`, `isSendButton`).
- **Bypassable**: disabling the extension or using the API directly evades it.
  It's a nudge/visibility layer, not enforcement.
- **Output is post-hoc**: only prompts are screened here; model responses stream
  into the DOM and would need separate (after-the-fact) redaction.
- **Token storage**: keys live in `chrome.storage.local` (plaintext-ish). Fine
  for a POC/demo; for fleet rollout use managed policy + a short-lived token.

## Fleet rollout (later)
Package + push via Chrome Enterprise **managed policy** to all users; pre-seed
config via `storage.managed`. That turns this into a real shadow-AI DLP control
across the org (covers claude.ai, and the same pattern extends to ChatGPT/Gemini).

## Files
| File | Role |
|---|---|
| `manifest.json` | MV3 manifest, permissions, content-script + background wiring |
| `background.js` | calls Shield `/guardrails/input` with headers; verdict logic |
| `content.js` | intercepts send on claude.ai; banner UI; approved-replay |
| `options.html/js` | config (URL, keys, mode) |
| `popup.html/js` | mode toggle + Test connection |
