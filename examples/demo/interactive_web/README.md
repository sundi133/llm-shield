# Interactive demo UI — chat with a Shield-guarded agent

A small local web app for the stage: the audience types (or you take shouts), and
a **real Shield** blocks or answers live on the big screen. Unlike a static page,
this app runs locally and proxies to Shield server-side, so the tenant key never
reaches the browser and there's no CORS/CSP problem.

## Run

```bash
pip install fastapi uvicorn httpx
export SHIELD_URL=https://api.guardrails.votal.ai   # or your Shield
export TENANT_KEY=<tenant-key>
python examples/demo/interactive_web/app.py         # → http://localhost:8800
```

Open `http://localhost:8800`, put it fullscreen on the projector.

## What you can do

- **Type any message** → the guarded agent replies, or a jailbreak gets 🛡 Blocked.
- **Quick chips** (top): Jailbreak · Read AWS creds · Exfil PII · Normal question · Allowed tool.
- **Commands** in the box: `/tool <name> [role]` (RBAC), `/screen <text>` (raw input-guard verdict).

Every prompt carries one `run_id`, so the session is one trace.

## Notes

- Verified live: jailbreak blocked (prompt-injection), forbidden tool blocked (RBAC),
  allowed tool passes, normal question answered.
- **All blocks come from your tenant's configured policies.** Chat enforcement
  screens the message through `/guardrails/input` and the reply through
  `/guardrails/output` (both apply the tenant's custom policies, resolved from
  `TENANT_KEY`); the guarded chat proxy is used only to generate the reply text.
  This demo does NOT create any policies — configure them in your portal.
- Requires the Shield LLM backend reachable for replies — test once before the
  talk. `/tool` and `/screen` are pure guard checks (no model) and always work.
- RBAC (`/tool`) uses the tenant's agent registry — register your agents +
  role permissions in the portal.
