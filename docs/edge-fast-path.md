---
title: Edge Fast-Path (Browser DLP for AI)
layout: default
nav_order: 24
permalink: /edge-fast-path/
description: Block or redact sensitive prompts before they leave the browser for web AI tools (ChatGPT, Gemini, Claude, Copilot) — a tiered edge check (local rules + heuristic classifier) that escalates ambiguous cases to the Shield server.
---

# Edge fast-path — browser DLP for AI
{: .no_toc }

Stop sensitive data from reaching web AI tools (ChatGPT, Gemini, Claude, M365
Copilot, Perplexity) by checking the prompt **on the device, before it's sent**.
A browser extension runs cheap local checks instantly and offline, and escalates
only ambiguous prompts to the Shield server.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The tiers
| Tier | Where | What | Latency |
|---|---|---|---|
| **T0 — rules** | browser (offline) | tenant regex rules + keyword blocklists → block / redact the obvious | µs |
| **T1 — classifier** | browser (offline) | heuristic prompt-injection / secret detection (pluggable for an ONNX/WASM model) | ms |
| **T2 — server** | data plane | full guardrail model (`/guardrails/input`) — **source of truth** | network |

**Edge blocks the obvious; the server stays authoritative.** A clear PII/secret
hit is blocked or redacted locally before anything leaves the device; only
locally-clean (or "suspicious") prompts are escalated to T2.

## How it works
1. The extension fetches a **policy bundle** for the tenant from
   `GET /v1/edge/policy-bundle` (regex rules + blocklists, ETag-cached).
2. On submit, **T0** runs the rules locally → block / redact / pass.
3. On pass, **T1** runs the heuristic classifier → `malicious` blocks locally,
   `suspicious` forces escalation.
4. On escalation, the worker calls **`POST /guardrails/input`**; a server block
   stops the send.

## Set up
**Server (once):** define the policy in the Shield portal — **Data Policies**
(regex DLP rules) + **I/O Guardrails** + input-guardrail blocklists. The bundle
endpoint serves these to the edge automatically. (`/v1/edge/policy-bundle` is
read-only and off the guard path.)

**Extension (developer):**
1. `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/`.
2. Options → set the **Shield data-plane URL** + **tenant API key** (+ proxy bearer if behind one).
3. Try typing an SSN-like string into a supported site → it blocks/redacts on Enter.

**Extension (enterprise):** package and **force-install** via Chrome/Edge policy
(`ExtensionInstallForcelist`) and pre-seed settings via managed storage.

## What it covers — and doesn't
| | |
|---|---|
| ✅ Inline block/redact of prompts in **web AI tabs** | ❌ Desktop apps (ChatGPT/Claude desktop), mobile |
| ✅ Offline (T0/T1) — works without a network hop | ❌ Direct API usage (use the gateway) |
| ✅ Vendor-agnostic (any web AI) | ⚠️ Per-site DOM changes may need adapter tweaks |
| ✅ Same tenant policy as the rest of Shield | ⚠️ T1 is a heuristic baseline (swap in a model later) |

For desktop/network coverage, integrate Shield as a callout in your SWG/CASB; for
agent tool calls, use the [MCP proxy / gateway](/ai-gateway-interoperability/).

## See also
- [AI Gateway & Proxy Interoperability](/ai-gateway-interoperability/) — server-side PEPs.
- [Enterprise Integration Architecture](/enterprise-integration-architecture/) — where the edge fits (PDP/PEP).
- Spec: `docs/specs/usage-retention.md` and the edge fast-path spec; code in `extension/` + `api/routes_edge.py`.
