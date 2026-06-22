---
title: AI Gateway & Proxy Interoperability
layout: default
nav_order: 21
permalink: /ai-gateway-interoperability/
description: Put Votal Shield guardrails in front of any model by integrating with your AI gateway/proxy — LiteLLM (native plugin), Portkey, Kong AI Gateway, Cloudflare AI Gateway, or any OpenAI-compatible gateway via the stateless guardrail HTTP API.
---

# AI gateway & proxy interoperability
{: .no_toc }

If your traffic already flows through an AI gateway or proxy (LiteLLM, Portkey,
Kong, Cloudflare, …), you can add Shield guardrails **at that layer** — no app
code changes. The gateway calls Shield's stateless guardrail HTTP API on each
request/response and blocks, sanitizes, or allows based on the verdict.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. How it works

A gateway sits between your app and the model. Shield plugs into the gateway's
**pre-call** (input) and **post-call** (output/tool) hooks:

```
┌──────────┐   request    ┌─────────────────┐   pre_call    ┌──────────────────────┐
│ Your app │ ───────────▶ │  AI gateway     │ ────────────▶ │ Shield /guardrails/* │
│ / agent  │              │ (LiteLLM,       │ ◀──────────── │  (input safety,      │
└──────────┘ ◀─────────── │  Portkey, Kong) │   verdict     │   output validation, │
              response     │                 │               │   tool RBAC)         │
                          │       │ allowed  └──────────────────────┘
                          │       ▼
                          │  ┌──────────┐
                          └─▶│  Model   │  (OpenAI, Anthropic, self-hosted, agent)
                             └──────────┘
```

Two integration shapes, depending on the gateway:

| Shape | When to use | Gateways |
|---|---|---|
| **Native plugin / guardrail hook** | The gateway has a guardrail/plugin extension point. | LiteLLM (Python `CustomGuardrail`), Kong (plugin) |
| **Webhook / sidecar** | The gateway can call an external HTTP guardrail, or you front it with a thin proxy. | Portkey (webhook), Cloudflare, any OpenAI-compatible gateway |

## 2. Maturity tiers

Same honest tiering as our [IdP interop](/idp-interoperability/) — we don't
over-claim:

| Gateway | Integration | Status |
|---|---|---|
| **LiteLLM** | Native `CustomGuardrail` plugin (`votal_guardrail.py`) + example config + one-shot script | **Validated** — shipped in this repo, runnable |
| **Portkey** | Custom guardrail **webhook** → thin Shield adapter | Integration pattern — validate in your env |
| **Kong AI Gateway** | Pre/post-function or custom plugin → Shield HTTP API | Integration pattern — validate in your env |
| **Cloudflare AI Gateway** | Front with LiteLLM/sidecar (no general-purpose guard webhook today) | Integration pattern — validate in your env |
| **Any OpenAI-compatible gateway** | Drop the LiteLLM proxy in front, or use the framework-free sidecar | Integration pattern (LiteLLM path is Validated) |

{: .note }
> **Validated** = code shipped here that we run. **Integration pattern** = works
> via the gateway's documented extension point against Shield's stable HTTP API;
> confirm it against your deployment. The Shield API contract (section 3) is the
> same for all of them.

## 3. The building block — Shield's guardrail HTTP API

Every integration below is just a gateway calling these **stateless** endpoints
on the Shield **data plane**. No SDK required.

| Endpoint | Purpose | Body |
|---|---|---|
| `POST {SHIELD_URL}/guardrails/input` | Input safety (pre-call) | `{"message": "<user text>"}` |
| `POST {SHIELD_URL}/guardrails/output` | Output validation / sanitization, and tool-arg checks | `{"output": "<text>"}` or `{"output": "...", "context": {"tool_name": "...", "tool_input": {...}, "agent_id": "...", "user_role": "...", "stage": "input"}}` |
| `POST {SHIELD_URL}/v1/shield/tool/check` | Tool RBAC (per tool call) | `{"agent_key": "...", "tool_name": "...", "user_role": "...", "tool_params": {...}}` |

**Headers** (per request):

| Header | Meaning |
|---|---|
| `x-api-key` | Tenant API key (which tenant's policies to apply) |
| `Authorization: Bearer <token>` | Proxy bearer if the data plane sits behind RunPod (`RUNPOD_TOKEN`) |
| `x-agent-key` | _(optional)_ Agent identity for RBAC / tool checks |
| `x-user-role` | _(optional)_ Caller role for RBAC |

**Response** (shared shape):

```json
{
  "safe": true,
  "action": "pass",                
  "guardrail_results": [
    {"guardrail": "prompt_injection", "passed": true, "message": ""}
  ]
}
```

When `safe` is `false`, the gateway should block (or sanitize, if the response
carries sanitized content) and surface the triggered `guardrail_results`.

## 4. LiteLLM (Validated)

Shield ships a native LiteLLM guardrail: **`VotalGuardrail(CustomGuardrail)`** in
[`votal_guardrail.py`](https://github.com/sundi133/llm-shield/blob/main/votal_guardrail.py).
It implements:

- `async_pre_call_hook` → `POST /guardrails/input`
- `async_post_call_success_hook` → `POST /guardrails/output` (text + per-tool context)
- `async_post_call_streaming_iterator_hook` → streaming output + `POST /v1/shield/tool/check`

### Config

`config/litellm_guardrails.example.yaml`:

```yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: gpt-4o
      api_key: os.environ/OPENAI_API_KEY
  - model_name: claude-sonnet
    litellm_params:
      model: anthropic/claude-3-5-sonnet-20241022
      api_key: os.environ/ANTHROPIC_API_KEY

guardrails:
  - guardrail_name: votal-input-guard
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: pre_call
      default_on: true
  - guardrail_name: votal-output-guard
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: post_call
      default_on: true

votal_guardrail:
  api_base: "https://<your-shield-data-plane-host>"
  api_token: ""          # blank → reads RUNPOD_TOKEN / SHIELD_API_TOKEN from env
  last_k_messages: 3

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```

Notes:
- Register the class **twice** — once `pre_call`, once `post_call` — so both
  input and output hooks run.
- `default_on: true` makes the guard transparent: external clients don't have to
  know it exists.
- Supported `mode` values: `pre_call`, `post_call`, `during_call`,
  `logging_only`.

### Per-tenant routing

LiteLLM intercepts `X-API-Key` as its own virtual key, so the **tenant** key is
passed in metadata (forwarded to Shield as `x-api-key`). Mint a virtual key that
carries the tenant:

```bash
curl -X POST "$PROXY/key/generate" \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{"metadata": {"tenant_api_key": "<TENANT_API_KEY>"}}'
```

Hand the returned `sk-...` key to the agent. Optionally include `agent_key` and
`user_role` in the same metadata to enable tool RBAC.

### One-shot setup

[`scripts/guard_external_agent.sh`](https://github.com/sundi133/llm-shield/blob/main/scripts/guard_external_agent.sh)
starts the proxy, confirms `VotalGuardrail initialized`, mints a tenant virtual
key, runs a benign/injection gate test, and prints the **Base URL + key + model**
to paste into a hosted agent:

```bash
SHIELD_URL=$RUNPOD_HOST RUNPOD_TOKEN=$RUNPOD_TOKEN TENANT_API_KEY=$TENANT_API_KEY \
  OPENAI_API_KEY=... ./scripts/guard_external_agent.sh
```

See [Guard an External Agent](/guard-external-agent/) for the full walkthrough.

## 5. Portkey (webhook pattern)

Portkey Guardrails support a **custom webhook** check: Portkey POSTs the request
(or response) to your endpoint and acts on the returned verdict. Point that
webhook at a thin adapter that translates Portkey's payload to Shield's
`/guardrails/input` (before-request hook) and `/guardrails/output`
(after-request hook), forwarding the tenant `x-api-key` and the
`Authorization` bearer.

Adapter contract (illustrative — match your Portkey webhook version):

```
Portkey  --POST webhook-->  Shield adapter  --POST /guardrails/input-->  Shield
                            (map fields,                  verdict
                             add x-api-key) <--{safe,...}--
         <--{verdict:bool}--
```

Attach the **before-request** hook for input safety and the **after-request**
hook for output validation. Mark the webhook **deny-on-failure** if you want
fail-closed behavior.

## 6. Kong AI Gateway (plugin pattern)

Kong's AI plugins run on the request/response lifecycle. Call Shield from either
a small **custom plugin** or a **pre-function/post-function** snippet:

- **access phase** → `POST {SHIELD_URL}/guardrails/input` with the prompt; on a
  non-`safe` verdict, short-circuit with `kong.response.exit(403, …)`.
- **response phase** → `POST {SHIELD_URL}/guardrails/output` with the model
  output; block or replace with sanitized content.

Inject the tenant `x-api-key` and proxy `Authorization` header from Kong
consumer/credentials config so each route maps to the right Shield tenant.

## 7. Cloudflare AI Gateway & other proxies

Cloudflare AI Gateway focuses on caching, rate-limiting, and observability and
does not expose a general-purpose external guardrail webhook for arbitrary
request/response mutation today. The reliable pattern is to **front it with the
LiteLLM proxy** (section 4) or the framework-free sidecar (section 8), which then
calls Shield. The same applies to any gateway without a guard extension point.

## 8. Any OpenAI-compatible gateway (sidecar pattern)

If you can't (or don't want to) modify the gateway, wrap it with a guard:

- **LiteLLM proxy in front** — the universal shim. Point LiteLLM at the
  gateway's OpenAI-compatible base URL as a model, enable `VotalGuardrail`
  (section 4), and send traffic to LiteLLM instead. Works for any
  OpenAI-compatible upstream.
- **Framework-free sidecar** —
  [`examples/guarded_chat.py`](https://github.com/sundi133/llm-shield/blob/main/examples/guarded_chat.py)
  does input-guard → call model/agent → output-guard against the same Shield
  endpoints, with no gateway at all. Good for custom HTTP agents.

## 9. What you get

Regardless of gateway, the guard runs at the proxy layer, so:

- **No app code changes** — protection is configured at the gateway.
- **Any model/provider** behind the gateway is covered uniformly.
- **Per-tenant policies** via the tenant `x-api-key`.
- **Tool RBAC** for agentic tool calls via `x-agent-key` + `x-user-role`.
- Pairs with [Continuous Identity & Auto-Revoke](/continuous-identity/): a
  guardrail trip on an identified agent can revoke it in real time.

## See also

- [Guard an External Agent](/guard-external-agent/) — end-to-end LiteLLM walkthrough.
- [Identity Provider Interoperability](/idp-interoperability/) — OIDC/OAuth interop with your IdP.
- [Agentic Integration Guide](/agentic-integration-guide/) — agent identity + capability tokens.
- [Guardrails Catalog](/guardrails/) — the checks Shield runs.
