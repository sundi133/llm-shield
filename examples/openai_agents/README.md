# OpenAI Agents + LLM Shield

Protect OpenAI function-calling agents with Shield guardrails, RBAC, and shadow discovery.

## Prerequisites

- Python 3.10+
- A running LLM Shield instance (local or RunPod)
- An [OpenAI API key](https://platform.openai.com/)

## Setup

```bash
cd examples/openai_agents
pip install -r requirements.txt
```

## Configure

```bash
export LLM_SHIELD_URL="http://localhost:8080"      # your Shield URL
export API_KEY="tenant-...-key-..."                 # tenant API key
export OPENAI_API_KEY="sk-..."                      # OpenAI key
```

Optional overrides:

```bash
export AGENT_ID="openai-support-agent"              # default agent ID
export USER_ROLE="user"                             # user/support/admin
export LLM_MODEL="gpt-4o-mini"                     # OpenAI model
```

## Run

```bash
python shield_openai_agent.py
```

### Expected output

```
============================================================
User: What's the status of order ORD-12345?
============================================================
[input guardrails] passed
  [ALLOWED] lookup_order({"order_id": "ORD-12345"}) -> Order ORD-12345: shipped...
[output guardrails] passed

============================================================
User: Cancel order ORD-12345, I changed my mind
============================================================
[input guardrails] passed
  [BLOCKED] cancel_order: Tool 'cancel_order' blocked for role 'user'
```

## Two Integration Patterns

This example includes two approaches:

### 1. Shield-managed flow (recommended)

`run_agent()` — sends everything to Shield's `/v1/shield/chat/agent` which
handles the LLM call, tool selection, and RBAC in one request.

### 2. Direct OpenAI flow

`run_agent_direct()` — calls OpenAI directly, then sends tool calls to Shield
for RBAC validation. Use this when you need full control over the OpenAI call.

```python
# Switch to direct flow in __main__:
run_agent_direct("What's the status of order ORD-12345?")
```

## Test Shadow Discovery

Skip registration to see the agent tracked as a shadow agent:

```bash
# Keep register_agent() commented out in the script, then run:
python shield_openai_agent.py
```

At the end it prints any shadow items Shield detected. You can also see them
in the tenant portal under the **Agents** tab → **Shadow Discovery** panel.

## How It Works

```
User Message
  │
  ├──▶ Shield /guardrails/input         block toxic/adversarial/PII
  │
  ├──▶ Shield /v1/shield/chat/agent     LLM picks tools + RBAC enforced
  │      ├── allowed  → execute_tool() locally
  │      ├── blocked  → deny + log
  │      └── unregistered → shadow tracked
  │
  ├──▶ Shield /guardrails/output        block competitors/PII/bias
  │
  └──▶ Response
```

## Registering the Agent

Uncomment `register_agent()` in `__main__` to register. This creates:

| Role | Allowed Tools |
|---|---|
| user | `lookup_order`, `get_refund_status` |
| support | `lookup_order`, `cancel_order`, `get_refund_status` |
| admin | `lookup_order`, `cancel_order`, `get_refund_status` |

Change `USER_ROLE` to test different permission levels:

```bash
USER_ROLE=admin python shield_openai_agent.py    # all tools allowed
USER_ROLE=user python shield_openai_agent.py     # cancel_order blocked
```
