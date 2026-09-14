---
title: Microsoft Foundry Integration
layout: default
nav_order: 22
permalink: /microsoft-foundry-integration/
description: Four supported ways to put Votal Shield guardrails in front of Microsoft Foundry (formerly Azure AI Foundry) - LiteLLM bridge to Foundry Models, Shield as an OpenAI base_url drop-in, Foundry Agent Service tools through the Shield MCP Gateway, and inline guardrail calls from Azure API Management.
---

# Microsoft Foundry integration
{: .no_toc }

Microsoft Foundry (formerly Azure AI Foundry) gives you models, an Agent Service,
and a tool catalog. Shield adds the enforcement layer around them: input safety,
output DLP, tool RBAC, and a tamper-evident audit trail, applied to traffic that
Foundry itself does not inspect.
{: .fs-6 .fw-300 }

This page maps each Foundry surface to the Shield surface that guards it, and is
explicit about which paths we ship and run versus which are integration patterns
you validate in your own subscription.

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Pick your integration point

Foundry has three places traffic can be intercepted. Which one you choose depends
on who owns the calling code.

| You want to guard | Foundry surface | Shield surface | Pattern |
|---|---|---|---|
| Model calls from your own apps | Foundry Models (`/openai/v1`) | LiteLLM proxy + `VotalGuardrail` plugin | [A](#3-pattern-a-litellm-bridge-recommended) |
| Model calls where you cannot add a proxy hop | Foundry Models | Shield OpenAI-compatible endpoint (`/v1/chat/completions`) | [B](#4-pattern-b-shield-as-an-openai-base_url-drop-in) |
| Tools called by a Foundry agent | Foundry Agent Service MCP tool | Shield MCP Gateway (`/gateway/<route>/mcp`) | [C](#5-pattern-c-foundry-agent-service-tools-through-the-shield-mcp-gateway) |
| Traffic already passing through an Azure gateway | Azure API Management in front of Foundry | Stateless `/guardrails/*` HTTP API | [D](#6-pattern-d-inline-guardrail-calls-apim-or-agent-code) |

Most customers end up running **A and C together**: A covers the prompt and
completion path, C covers what the agent is allowed to *do*. They are
independent and can be adopted in either order.

## 2. Maturity tiers

Same honest tiering as our [AI gateway interop](/ai-gateway-interoperability/) page.

| Pattern | Integration | Status |
|---|---|---|
| **A. LiteLLM bridge** | `votal_guardrail.VotalGuardrail` plugin + LiteLLM `azure/` model spec | **Validated** for the LiteLLM half (plugin and config ship in this repo). The Foundry half uses LiteLLM's documented Azure provider. Confirm in your subscription. |
| **B. OpenAI base_url drop-in** | Shield `POST /v1/chat/completions` | **Validated** as an endpoint ([api/routes_openai_compat.py](../api/routes_openai_compat.py)). Reaching Foundry as the upstream needs the credential hop in [section 4.2](#42-the-upstream-credential-gap). |
| **C. Agent Service MCP tool** | Foundry MCP tool (custom headers) to Shield MCP Gateway | Integration pattern. Both halves exist and are documented; the join has not been run end to end by us. |
| **D. Inline guardrail calls** | APIM policy or agent code to `/guardrails/*` | Integration pattern. The Shield API is stable and stateless; the APIM policy is yours to author. |

{: .note }
> **Validated** = code shipped in this repo that we run. **Integration pattern** =
> works through documented extension points on both sides, against Shield's
> stable HTTP API. Confirm it against your deployment before you rely on it.

## 3. Pattern A: LiteLLM bridge (recommended)

This is the shortest path to "every Foundry model call is guardrailed", and it
needs no change to your application beyond a base URL.

```
┌──────────┐            ┌────────────────────┐   pre_call    ┌──────────────────────┐
│ Your app │ ─────────▶ │  LiteLLM proxy     │ ────────────▶ │ Shield data plane    │
│ or agent │            │  + VotalGuardrail  │ ◀──────────── │ /guardrails/input    │
└──────────┘ ◀───────── │                    │   verdict     │ /guardrails/output   │
                        │        │ allowed   └──────────────────────┘
                        │        ▼
                        │  ┌──────────────────────────────────┐
                        └─▶│ Microsoft Foundry                │
                           │ {resource}/openai/v1/chat/...    │
                           └──────────────────────────────────┘
```

LiteLLM holds the Foundry credential, so Shield never needs one. Shield sees the
text, returns a verdict, and LiteLLM blocks or forwards.

### 3.1 Point LiteLLM at Foundry

Foundry exposes an OpenAI-compatible surface at `{resource-endpoint}/openai/v1`,
authenticated with the resource `api-key` header. LiteLLM's `azure/` provider
speaks this. Set the credentials:

```bash
export AZURE_API_KEY="<your Foundry resource key>"
export AZURE_API_BASE="https://<your-resource>.services.ai.azure.com"
export AZURE_API_VERSION="<api-version>"   # optional on the v1 surface
export AZURE_MODEL="<your deployment name>"
```

For the RunPod images, [scripts/generate_litellm_config.py](../scripts/generate_litellm_config.py)
already detects exactly these four variables and writes the matching `azure/`
model spec. Note that it writes to a fixed path (`/runpod/config/litellm_config.yaml`),
so outside that image, hand-write the config as below.

### 3.2 Add the Shield guardrail plugin

Start from [config/litellm_guardrails.example.yaml](../config/litellm_guardrails.example.yaml)
and replace the model list with your Foundry deployment:

```yaml
model_list:
  - model_name: foundry-gpt
    litellm_params:
      model: azure/<your-deployment-name>
      api_key: os.environ/AZURE_API_KEY
      api_base: os.environ/AZURE_API_BASE
      # api_version: os.environ/AZURE_API_VERSION   # only if your surface needs it

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
  api_base: "https://<your-shield-data-plane>"
  api_token: ""          # VotalGuardrail reads RUNPOD_TOKEN / SHIELD_API_TOKEN from env
  last_k_messages: 3

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```

`default_on: true` matters: it makes the guardrails run on every request, so a
plain OpenAI client gets covered without sending a custom `guardrails` field.

```bash
pip install "litellm[proxy]"
litellm --config config/litellm_guardrails.example.yaml --port 4000
```

Your app then points at `http://<litellm-host>:4000/v1` with a LiteLLM virtual
key. Nothing else changes.

### 3.3 What you get

[votal_guardrail.py](../votal_guardrail.py) sends each request to
`/guardrails/input` on `pre_call`, each completion to `/guardrails/output` on
`post_call`, and each tool call to `/guardrails/output` with the full tool
context so tool-argument DLP runs automatically. A denied tool call blocks the
response; set `VOTAL_ENFORCE_TOOL_RBAC=false` for the older advisory behavior.

## 4. Pattern B: Shield as an OpenAI base_url drop-in

If you cannot insert a LiteLLM hop, Shield itself serves an OpenAI-compatible
endpoint and your client points straight at it.

```python
from openai import OpenAI

client = OpenAI(base_url="https://<your-shield-data-plane>/v1", api_key="<tenant-key>")
client.chat.completions.create(model="foundry-gpt", messages=[...])
```

Shield returns a valid `chat.completion` object, streaming included. A blocked
prompt comes back as a **200** whose assistant message is a refusal with
`finish_reason: "content_filter"`, and guardrail detail under a namespaced
`x_shield` field plus an `X-Shield-Blocked` response header. Guardrails fail
closed: if a pipeline errors, Shield refuses rather than proxying unguarded.

The endpoint is on by default and can be disabled with
`SHIELD_OPENAI_COMPAT_ENABLED=0`.

### 4.2 The upstream credential gap

Read this before you plan around Pattern B with Foundry as the upstream.

When an upstream is configured, Shield forwards the body to
`{upstream_url}/v1/chat/completions` **without attaching any headers**
([api/routes_openai_compat.py:271](../api/routes_openai_compat.py),
[api/routes_gateway.py:603](../api/routes_gateway.py)):

```python
resp = await client.post(f"{upstream_url}/v1/chat/completions", json=body)
```

Foundry requires an `api-key` header (or a Microsoft Entra bearer token), and the
path is `/openai/v1/chat/completions`, not `/v1/chat/completions`. So **Shield
cannot today authenticate directly to a Foundry endpoint as its upstream.** You
need one of:

1. **LiteLLM as the credential-bearing hop** (Pattern A). Recommended, and no new
   code.
2. A thin shim in front of Foundry that rewrites the path and injects the key,
   with `upstream_url` pointing at the shim. Keep the shim inside your VNet.
3. A Shield change to attach configurable upstream auth headers. Not implemented.
   If your deployment needs it, that is a spec (`docs/spec-template.md`) and a
   scoped PR, not a configuration change.

## 5. Pattern C: Foundry Agent Service tools through the Shield MCP Gateway

The Foundry MCP tool lets an agent connect to a remote MCP server and pass custom
headers for authentication. That is exactly the shape the Shield MCP Gateway
expects, so a Foundry agent can call your existing MCP servers with Shield
enforcing every `tools/call` in between.

```
┌───────────────────┐  MCP + X-API-Key  ┌────────────────────┐   enforced   ┌──────────────┐
│ Foundry agent     │ ────────────────▶ │ Shield MCP Gateway │ ───────────▶ │ Your MCP     │
│ (MCP tool)        │ ◀──────────────── │ /gateway/<route>/  │ ◀─────────── │ server       │
└───────────────────┘   result (DLP'd)  │        mcp         │              └──────────────┘
                                        └────────────────────┘
                                   RBAC -> input -> forward -> output DLP
```

### 5.1 Register the upstream and the policy

Follow [MCP Gateway](/mcp-gateway/) to register your server as a route and to
declare the role-to-tool permissions Shield enforces. In short:

```bash
export SHIELD=https://<your-shield-data-plane>
export KEY=<your-tenant-api-key>
export ROUTE=myserver
```

Register the agent and its role permissions with `POST $SHIELD/v1/agents/registry`,
then register the upstream with `PUT $SHIELD/v1/tenant/me/mcp-gateway/upstreams/$ROUTE`.

### 5.2 Attach it to the Foundry agent

Add an MCP tool on the agent pointing at:

```
https://<your-shield-data-plane>/gateway/<route>/mcp
```

with these custom headers:

| Header | Value | Required |
|---|---|---|
| `X-API-Key` | Your Shield tenant API key | Yes, unless you send the same key as `Authorization: Bearer` |
| `X-Agent-Key` | The agent identity you registered | Optional, needed for per-agent RBAC |
| `X-User-Role` | The caller role to enforce against | Optional, needed for role-based policy |

Shield resolves identity from these headers, independently per field, falling
back to `mcp-agent` only when nothing is supplied
([api/routes_mcp_server.py:177](../api/routes_mcp_server.py)).

{: .note }
> **Which credential the gateway accepts.** Tenant resolution reads, in order,
> `X-API-Key`, a Shield OAuth bearer token, then a tenant key presented as
> `Authorization: Bearer`. MCP clients send credentials in `Authorization` per
> the MCP authorization spec, so either header works. An unauthenticated call
> answers **401** with an RFC 9728 `WWW-Authenticate` challenge, which is what
> lets a client report an auth failure rather than displaying an empty server;
> `SHIELD_MCP_AUTH_CHALLENGE=off` restores the older HTTP 200 behavior. See
> [the gateway bearer auth spec](/spec-mcp-gateway-bearer-auth/). Treat the key
> you hand Foundry as the secret it is, and scope the route accordingly.

### 5.3 Lock the upstream down

The gateway only protects what cannot be reached around it. Your MCP server must
be reachable **only** from the Shield gateway, or the agent can be pointed
straight at it and skip enforcement entirely. See the non-bypassability section
of [MCP Gateway](/mcp-gateway/).

### 5.4 OpenAPI tools

Foundry's OpenAPI tool supports anonymous, API key, and managed identity auth.
If you would rather expose guarded HTTP APIs than MCP, Shield can import an
OpenAPI spec and serve the generated operations as enforced tools
(`POST /v1/openapi/import`, then `/v1/openapi/tools` and `/v1/openapi/call`,
in [api/routes_openapi_mcp.py](../api/routes_openapi_mcp.py)). The generated
tools auto-register in the agent registry, so role permissions apply to them too.

## 6. Pattern D: inline guardrail calls (APIM or agent code)

If your Foundry traffic already flows through Azure API Management, you can call
Shield from an APIM policy on the inbound and outbound sections, and skip the
extra proxy entirely. The building blocks are the stateless data-plane endpoints:

| Endpoint | Purpose | Body |
|---|---|---|
| `POST {SHIELD}/guardrails/input` | Input safety, pre-call | `{"message": "<user text>"}` |
| `POST {SHIELD}/guardrails/output` | Output validation, and tool-argument DLP with `context.stage="input"` | `{"output": "<text>"}` |
| `POST {SHIELD}/v1/shield/tool/check` | Tool RBAC and injection validation, authorization only | `{"agent_key": "...", "tool_name": "...", "user_role": "...", "tool_params": {...}}` |
| `POST {SHIELD}/v1/shield/tool/output` | Tool-result DLP | `{"tool_output": "<result>", "context": {...}}` |

Send the tenant API key as `x-api-key`. The shared response shape is
`{"safe": bool, "action": "pass"|..., "guardrail_results": [...]}`; block when
`safe` is false.

{: .warning }
> **`/v1/shield/tool/check` is authorization only.** An integration that calls
> only that endpoint gets no content DLP on tool arguments or results. For the
> full four-step tool sequence, see
> [AI gateway interoperability, section 4](/ai-gateway-interoperability/).

## 7. Where Shield runs in Azure

Shield is two planes, and they have different infrastructure needs. State this
in your Azure design review.

| Plane | What it is | Azure shape |
|---|---|---|
| **Data plane** | GPU guardrail server (vLLM), serves `/guardrails/*`, `/v1/chat/completions`, `/gateway/*` | AKS with a GPU node pool, or a GPU VM. This is the latency-sensitive path. |
| **Admin plane** | CPU portal (`admin_app.py`), tenant and policy management | Azure Container Apps or an App Service. No GPU. Never on the guard path. |

Both planes need the tenant store. See
[On-Premises Deployment](/on-premises-deployment-guide/) for the private-network
variant, which is the closest match to a VNet-isolated Foundry deployment.

Network path to confirm with your cloud team:

- Foundry resource reachable from wherever LiteLLM runs (Pattern A) or from your
  shim (Pattern B).
- Shield data plane reachable from Foundry Agent Service over the public internet
  or through Private Link (Pattern C). Foundry's MCP tool calls **out** to Shield,
  so Shield needs an ingress Foundry can resolve.
- Your MCP servers reachable **only** from the Shield gateway.

## 8. What to validate in your subscription

Nothing here is a claim about your environment. Before go-live, confirm:

1. The Foundry deployment name and whether your surface needs `api-version`.
   The v1 surface at `/openai/v1` does not.
2. Whether your organization requires Microsoft Entra managed identity rather
   than an `api-key`. LiteLLM can hold an Entra credential; Shield's upstream
   forwarder cannot (section 4.2).
3. That the Foundry agent can reach your Shield ingress, and that the custom
   headers arrive intact.
4. That your MCP servers reject traffic that does not come from the gateway.
5. Whether Foundry's own Content Safety filters stay on. They are complementary,
   not redundant: Foundry filters content, Shield additionally enforces tool RBAC,
   data policy, and identity, and produces the audit trail.

## 9. Related reading

- [AI Gateway and Proxy Interoperability](/ai-gateway-interoperability/) for the
  generic gateway pattern this page specializes.
- [MCP Gateway](/mcp-gateway/) for the full route registration and lockdown steps.
- [Tool Data Policies](/tool-data-policies/) for what DLP actually enforces.
- [On-Premises Deployment](/on-premises-deployment-guide/) for VNet-isolated installs.
