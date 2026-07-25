---
title: LiteLLM + MCP gateway
layout: default
nav_order: 29
permalink: /litellm-mcp-gateway/
description: Route LiteLLM's MCP tool calls through Shield's MCP gateway. Config-only, with no custom guardrail code, because Shield already speaks the MCP protocol LiteLLM's client expects.
---

# LiteLLM + Shield's MCP gateway
{: .no_toc }

LiteLLM guards the model conversation. Shield's MCP gateway guards what the
agent actually does. This page wires the two together so every tool call an
agent makes through LiteLLM is enforced before it reaches your MCP server.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Two gateways, two kinds of traffic

They are complementary, not alternatives. An agentic app uses both.

| | LiteLLM AI gateway | Shield MCP gateway |
|---|---|---|
| Protocol | OpenAI-style HTTP (`chat/completions`) | MCP JSON-RPC (`tools/call`, `tools/list`) |
| Traffic | prompts and completions | tool invocations |
| Unit of enforcement | a prompt / response | a tool call, its params, its destination |
| Downstream | model providers | your MCP servers |

The AI gateway guards **what the model says**. The MCP gateway guards **what
the agent does**, which is why it needs agent + role identity to decide
whether *this* agent may call *this* tool with *these* arguments.

## The integration: point LiteLLM at Shield

No Shield code, no custom LiteLLM guardrail. Shield already implements the MCP
protocol LiteLLM's client speaks, so you change one URL.

In your LiteLLM `config.yaml`, set the MCP server's `url` to Shield's gateway
instead of your real server:

```yaml
mcp_servers:
  files:
    url: "https://<your-shield-data-plane>/gateway/files/mcp"
    transport: "http"
    static_headers:
      x-api-key: os.environ/SHIELD_TENANT_KEY
    extra_headers:
      - "x-agent-key"
      - "x-user-role"
```

A full working file ships at
[`config/litellm_mcp_gateway.example.yaml`](https://github.com/sundi133/llm-shield/blob/main/config/litellm_mcp_gateway.example.yaml).

The route segment (`files`) is a route you registered in Shield, via the
portal's **MCP Gateway** tab, or
`PUT /v1/tenant/me/mcp-gateway/upstreams/files`. Shield holds the real upstream
URL, so it is never exposed to LiteLLM or to the agent.

### Request flow

```text
agent ──► LiteLLM (chat guardrails on prompts)
            │
            └─ tools/call ──► Shield MCP gateway
                                 │  RBAC · allowlist · data access · payload validation
                                 │  kill switch · tool-poisoning heuristics
                                 └─ forwards only if allowed ──► your MCP server
```

## What you get

Verified against the gateway with a standard MCP client handshake:

| MCP call | Behaviour |
|---|---|
| `initialize` | returns `shield-mcp-gateway` server info |
| `notifications/initialized` | accepted |
| `tools/list` | filtered to the tools the caller's role may use, annotated with a risk level |
| `tools/call` (permitted) | enforced, then forwarded to your server |
| `tools/call` (not permitted) | blocked: `isError: true`, "Blocked by Shield: Role 'reader' is not allowed to use tool …" |
| tool result | scanned by output data policy before it returns |

Plus the kill switch: disabling a tool in the portal blocks it immediately for
every agent, without touching LiteLLM.

## Identity: the part to get right

Shield reads three headers ([`api/routes_mcp_server.py`](https://github.com/sundi133/llm-shield/blob/main/api/routes_mcp_server.py)):

| Header | Purpose |
|---|---|
| `x-api-key` | tenant, whose policy applies |
| `x-agent-key` | which agent is calling |
| `x-user-role` | the caller's role, for RBAC |

Two ways to supply the agent identity, and the choice matters:

- **`extra_headers`** forwards the *caller's* headers, so per-agent and
  per-role RBAC work as intended. Requires that your client actually sets
  `x-agent-key` / `x-user-role`.
- **`static_headers`** pins one fixed identity for all LiteLLM traffic. Simpler,
  but every agent behind the proxy looks identical to Shield, so per-agent RBAC
  collapses to per-proxy.

Prefer `extra_headers` unless you cannot control the calling client.

## Agent run tracing across the LiteLLM hop

The same `extra_headers` mechanism carries the run correlator. Shield ties all of
one agent run's guard records together with an `X-Shield-Run-Id` (see
[Agent Run Tracing](agent-run-tracing/)); to keep that correlation when LiteLLM is
in the path, forward the header:

```yaml
mcp_servers:
  files:
    url: https://<shield-host>/gateway/files/mcp
    extra_headers: ["x-agent-key", "x-user-role", "x-shield-run-id"]
```

The client sets `X-Shield-Run-Id` once on its request; LiteLLM forwards it on the
MCP calls (and, via the chat guardrail, on `/guardrails/*`), so every Shield record
for that run shares the same `run_id` — even across LiteLLM. Reconstruct the run
by filtering `metadata.run_id` in the audit log.

### One trace tree for LiteLLM + Shield

To see the run as a **single trace** — LiteLLM's LLM call with Shield's guard
decisions nested underneath — use W3C trace propagation:

1. Enable LiteLLM's OpenTelemetry callback so it emits LLM spans **and** propagates
   `traceparent` downstream:
   ```yaml
   litellm_settings:
     callbacks: ["otel"]
   ```
2. Point Shield at the **same** collector and turn on span emission:
   ```bash
   SHIELD_OTLP_TRACES_ENDPOINT=http://otel-collector:4318
   ```
   Shield honors the incoming `traceparent`, so its guard spans nest under
   LiteLLM's span instead of starting a new trace.

Result — one trace per run in your backend (Jaeger / Tempo / Datadog):

```
run
 └─ LiteLLM: chat.completion          (model, tokens, latency)
     ├─ Shield: /guardrails/input     (blocked? which guardrail)
     ├─ Shield: /gateway/files/mcp    (tool RBAC decision)
     └─ Shield: /guardrails/output    (sanitized?)
```

If the customer already runs LiteLLM with an OTEL collector or Langfuse, this reuses
that sink — no new backend to stand up.

## Limitation: no session-scoped guards on this path

Identity arrives as **headers**, not as a signed Shield agent token, so there is
no verified `session_id`. Two guards are session-scoped and therefore do **not**
fire on this path:

- human-in-the-loop confirmation for sensitive tools
- per-session rate limits

Everything else runs: RBAC, tool allowlist, data-access clearance, payload
validation, kill switch, tool-poisoning heuristics, and output data policy.

Shield does not hide this. When the stricter guard set is enabled, the decision
carries a `session_unavailable` advisory rather than reporting a clean pass, so
the degradation is visible in your audit trail instead of silent.

To get confirmation gating, the caller must present a Shield agent token
carrying a verified session. That is an agent-identity change, not a LiteLLM
setting.

## Non-bypassability

Shield only enforces if your MCP server cannot be reached directly. Set
`isolation_ack: true` on the Shield route **after** restricting the upstream to
the gateway (private network, firewall, mTLS, or a gateway-only bearer token).
With `isolation_ack: false` Shield returns a warning: an agent that knows the
upstream URL can skip the gateway entirely.

## Alternative: a custom LiteLLM guardrail

If a team is standardised on LiteLLM's own MCP gateway and will not put another
hop in front of it, LiteLLM supports MCP guardrail modes (`pre_mcp_call`,
`during_mcp_call`) and custom guardrails via `CustomGuardrail`. Shield ships
`votal_guardrail.py` for the chat path; an MCP-mode hook would call
`POST /v1/shield/tool/check`, which runs the same agentic guard chain.

This is the weaker option and worth choosing deliberately:

- no `isolation_ack`, so LiteLLM reaches your MCP servers directly and the
  servers must be locked down by other means
- no gateway-level `tools/list` filtering or kill switch
- the MCP hook payload is not documented upstream, so it needs a spike against
  a real LiteLLM build before it can be specified

Prefer pointing LiteLLM at Shield's gateway.
