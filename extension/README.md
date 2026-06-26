# Votal Shield — browser extension (edge fast-path, MVP)

Blocks or redacts sensitive prompts **before they leave the browser** for web AI
tools (ChatGPT, Gemini, Claude, M365 Copilot, Perplexity), and escalates
ambiguous prompts to Shield. This is the **edge fast-path** client (Task 2 of the
edge spec); it consumes the `/v1/edge/policy-bundle` endpoint.

## How it works (tiers)
- **T0 (local, offline):** `rules.js` runs your tenant's regex rules + blocklists
  on the typed prompt at submit time. A clear hit **blocks** (critical/block) or
  **redacts** (replaces the match) — before anything is sent.
- **T2 (server, source of truth):** locally-clean prompts are escalated to
  `POST /guardrails/input`; if the server blocks, the send is stopped.

Edge blocks the obvious; the server stays authoritative.

## Install (developer / unmanaged)
1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
2. Open the extension's **Options** and set:
   - **Shield data-plane URL** (e.g. your RunPod host)
   - **Tenant API key**
   - **Proxy bearer** (only if behind a proxy)
   - escalate / enabled toggles
3. Visit a supported AI site and try typing an SSN-like string → it should block/redact on Enter.

## Deploy (enterprise / managed)
Package and **force-install** via Chrome/Edge enterprise policy (`ExtensionInstallForcelist`),
and pre-seed settings via managed storage. Configure the same Shield URL + tenant
key centrally. (Managed-storage schema is a follow-up.)

## Tests
`node --test extension/test/rules.test.mjs` — covers the T0 engine (block/redact/
allow, blocklist, malformed-regex safety, empty inputs).

## Honest limitations (MVP)
- **Per-site DOM is fragile.** Interception hooks Enter on the focused editable +
  a generic Send-button fallback; site UI changes may need adapter tweaks.
- **Coverage = browser tabs only** — not desktop apps, mobile, or direct API use.
- **Escalation re-send is best-effort** (the *blocking* path doesn't depend on it).
- Requires the `/v1/edge/policy-bundle` endpoint deployed (see `api/routes_edge.py`).

## Files
- `manifest.json` — MV3, supported AI hosts, content scripts, background worker
- `rules.js` — T0 rules engine (shared with Node tests)
- `content.js` — submit interception + block/redact/escalate + overlay
- `background.js` — config + authenticated bundle fetch (ETag) + escalation
- `options.html` / `options.js` — settings
- `test/rules.test.mjs` — engine tests
