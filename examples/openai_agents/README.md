# OpenAI + LLM Shield

Protect OpenAI function-calling agents using the **two-plane production
architecture**:

- **LLM + guardrails plane → LiteLLM proxy.** Input/output guardrails run
  *inside* the LiteLLM proxy via the votal.ai guardrails callback configured in
  its `config.yaml`. The OpenAI client just points its `base_url` at the proxy.
- **Agent + RBAC plane → LLM Shield.** Agent registration, role-based tool
  authorization, per-tool data-policy enforcement and shadow discovery go
  through the Shield endpoints.

```
User Message
  │
  ├─ LLM reasoning ─▶ LiteLLM proxy ─▶ [input guardrails] ─▶ LLM ─▶ [output guardrails]
  │                   (votal.ai callback in config.yaml — app never calls /guardrails/*)
  │
  └─ tool call ────▶ Shield /v1/shield/tool/check    RBAC + input data policy
                       ├─ allowed ▶ run tool ▶ Shield /v1/shield/tool/output (sanitize)
                       └─ blocked ▶ deny, reason fed back to the model
```

## Prerequisites

- Python 3.10+
- A **LiteLLM proxy** with the votal.ai guardrails callback configured
- A running **LLM Shield** instance (local or RunPod)

## Setup

```bash
cd examples/openai_agents
pip install -r requirements.txt
```

## Configure

```bash
# Plane 1 — LiteLLM proxy (guardrails live in its config.yaml)
export LITELLM_URL="http://localhost:4000"      # LiteLLM proxy base URL
export LITELLM_API_KEY="sk-litellm-..."          # LiteLLM virtual key
export LLM_MODEL="gpt-4o-mini"                   # model alias in the proxy config

# Plane 2 — LLM Shield (agents + RBAC)
export LLM_SHIELD_URL="http://localhost:8080"    # Shield URL
export API_KEY="tenant-...-key-..."              # tenant API key
export AGENT_ID="openai-support-agent"           # optional
export USER_ROLE="user"                          # user / support / admin
```

See the [LangChain example README](../langchain/README.md#litellm-proxy-configyaml-plane-1)
for a sample LiteLLM `config.yaml` with the votal.ai guardrails callback.

## Run

```bash
python shield_openai_agent.py
```

### Expected output

```
LLM plane  : LiteLLM proxy at http://localhost:4000 (model=gpt-4o-mini)
Agent plane: LLM Shield at http://localhost:8080 (agent=openai-support-agent, role=user)

============================================================
User: What's the status of order ORD-12345?
============================================================
  [ALLOWED] lookup_order({"order_id": "ORD-12345"}) -> Order ORD-12345: shipped...
Response: Your order ORD-12345 is shipped and arriving in 2 days.

============================================================
User: Cancel order ORD-12345, I changed my mind
============================================================
  [Shield] BLOCKED cancel_order: cancel_order blocked for role 'user' — ...
Response: I'm not authorized to cancel orders on your account.
```

A prompt that trips an **input guardrail** never reaches the LLM — the LiteLLM
proxy returns an error, reported as
`[Request blocked by guardrails in the LiteLLM proxy]`.

## Why two planes?

| Concern | Goes through | Endpoint(s) |
|---|---|---|
| Input/output guardrails | **LiteLLM proxy** | proxy `config.yaml` → `/guardrails/input`, `/guardrails/output` (called *by the proxy*) |
| LLM routing / model access | **LiteLLM proxy** | `/v1/chat/completions` |
| Agent registration | **LLM Shield** | `/v1/agents/registry` |
| RBAC + input data policy | **LLM Shield** | `/v1/shield/tool/check` |
| Output sanitization (per tool) | **LLM Shield** | `/v1/shield/tool/output` |
| Shadow discovery | **LLM Shield** | `/v1/agents/unregistered` |

## Test Shadow Discovery

Keep `register_agent()` commented out and run the script — Shield tracks the
agent and its tools as shadow items, printed at the end and visible in the
tenant portal under **Agents → Shadow Discovery**.

## Registering the Agent

Uncomment `register_agent()` in `__main__` to register. This creates:

| Role | Allowed Tools |
|---|---|
| user | `lookup_order`, `get_refund_status` |
| support | `lookup_order`, `cancel_order`, `get_refund_status` |
| admin | `lookup_order`, `cancel_order`, `get_refund_status` |

```bash
USER_ROLE=admin python shield_openai_agent.py    # all tools allowed
USER_ROLE=user  python shield_openai_agent.py    # cancel_order blocked by Shield
```
