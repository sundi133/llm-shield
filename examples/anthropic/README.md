# Anthropic Claude + LLM Shield

Protect Claude tool-use agents using the **two-plane production architecture**:

- **LLM + guardrails plane → LiteLLM proxy.** Input/output guardrails run
  *inside* the LiteLLM proxy via the votal.ai guardrails callback configured in
  its `config.yaml`. The Anthropic SDK points its `base_url` at the proxy's
  Anthropic-compatible `/v1/messages` endpoint.
- **Agent + RBAC plane → LLM Shield.** Agent registration, role-based tool
  authorization, per-tool data-policy enforcement and shadow discovery go
  through the Shield endpoints.

```
User Message
  │
  ├─ LLM reasoning ─▶ LiteLLM proxy ─▶ [input guardrails] ─▶ Claude ─▶ [output guardrails]
  │                   (votal.ai callback in config.yaml — app never calls /guardrails/*)
  │
  └─ tool_use ─────▶ Shield /v1/shield/tool/check    RBAC + input data policy
                       ├─ allowed ▶ run tool ▶ Shield /v1/shield/tool/output (sanitize)
                       └─ blocked ▶ deny, reason fed back as tool_result
```

## Prerequisites

- Python 3.10+
- A **LiteLLM proxy** with the votal.ai guardrails callback configured (and
  Anthropic credentials so the proxy can reach Claude)
- A running **LLM Shield** instance (local or RunPod)

## Setup

```bash
cd examples/anthropic
pip install -r requirements.txt
```

## Configure

```bash
# Plane 1 — LiteLLM proxy (guardrails live in its config.yaml)
export LITELLM_URL="http://localhost:4000"           # LiteLLM proxy base URL
export LITELLM_API_KEY="sk-litellm-..."               # LiteLLM virtual key
export CLAUDE_MODEL="claude-sonnet-4-20250514"        # model alias in the proxy config

# Plane 2 — LLM Shield (agents + RBAC)
export LLM_SHIELD_URL="http://localhost:8080"         # Shield URL
export API_KEY="tenant-...-key-..."                   # tenant API key
export AGENT_ID="claude-support-agent"                # optional
export USER_ROLE="user"                               # user / support / admin
```

The proxy must have a model whose alias is `CLAUDE_MODEL` mapped to
`anthropic/<model>` in its `config.yaml`. See the
[LangChain example README](../langchain/README.md#litellm-proxy-configyaml-plane-1)
for a sample config with the votal.ai guardrails callback.

## Run

```bash
python shield_anthropic_agent.py
```

### Expected output

```
LLM plane  : LiteLLM proxy at http://localhost:4000 (model=claude-sonnet-4-20250514)
Agent plane: LLM Shield at http://localhost:8080 (agent=claude-support-agent, role=user)

============================================================
User: How do I reset my password?
============================================================
  [text] I can help with that...
  [ALLOWED] search_knowledge_base({"query": "reset password"}) -> KB result...
Response: To reset your password, see article #42...

============================================================
User: Create a ticket: billing error on my account
============================================================
  [Shield] BLOCKED create_ticket: create_ticket blocked for role 'user' — ...
Response: I'm not able to open a ticket for you...
```

A prompt that trips an **input guardrail** never reaches Claude — the LiteLLM
proxy returns an error, reported as
`[Request blocked by guardrails in the LiteLLM proxy]`.

## Why two planes?

| Concern | Goes through | Endpoint(s) |
|---|---|---|
| Input/output guardrails | **LiteLLM proxy** | proxy `config.yaml` → `/guardrails/input`, `/guardrails/output` (called *by the proxy*) |
| LLM routing / model access | **LiteLLM proxy** | `/v1/messages` (Anthropic-compatible) |
| Agent registration | **LLM Shield** | `/v1/agents/registry` |
| RBAC + input data policy | **LLM Shield** | `/v1/shield/tool/check` |
| Output sanitization (per tool) | **LLM Shield** | `/v1/shield/tool/output` |
| Shadow discovery | **LLM Shield** | `/v1/agents/unregistered` |

No tool-format conversion is needed anymore: Claude's native `tool_use` blocks
are gated directly against Shield's `/v1/shield/tool/check` by tool name.

## Test Shadow Discovery

Keep `register_agent()` commented out and run the script — Shield tracks the
agent and its tools as shadow items, printed at the end and visible in the
tenant portal under **Agents → Shadow Discovery**.

## Registering the Agent

Uncomment `register_agent()` in `__main__` to register. This creates:

| Role | Allowed Tools |
|---|---|
| user | `search_knowledge_base` |
| support | `search_knowledge_base`, `create_ticket` |
| admin | `search_knowledge_base`, `create_ticket`, `escalate_to_human` |

```bash
USER_ROLE=admin python shield_anthropic_agent.py    # all tools allowed
USER_ROLE=user  python shield_anthropic_agent.py    # only search allowed
```
