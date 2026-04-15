# LangChain + LLM Shield

Protect LangChain agents with Shield guardrails, RBAC, and shadow discovery.

## Prerequisites

- Python 3.10+
- A running LLM Shield instance (local or RunPod)
- An [OpenAI API key](https://platform.openai.com/)

## Setup

```bash
cd examples/langchain
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
export AGENT_ID="langchain-support-agent"           # default agent ID
export USER_ROLE="user"                             # user/support/admin
export LLM_MODEL="gpt-4o-mini"                     # OpenAI model
```

## Run

```bash
python shield_langchain_agent.py
```

### Expected output

```
============================================================
User: What is your return policy?
============================================================
[input guardrails] passed
  [ALLOWED] search_faq({"query": "return policy"}) -> FAQ result...
[output guardrails] passed

============================================================
User: Create a ticket: billing issue on my last invoice
============================================================
[input guardrails] passed
  [BLOCKED] create_ticket: Tool 'create_ticket' blocked for role 'user'
```

## Test Shadow Discovery

Skip registration to see the agent tracked as a shadow agent:

```bash
# Keep register_agent() commented out in the script, then run:
python shield_langchain_agent.py
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
  │      ├── allowed  → tool.invoke() locally
  │      ├── blocked  → deny + log
  │      └── unregistered → shadow tracked
  │
  ├──▶ Shield /guardrails/output        block competitors/PII/bias
  │
  └──▶ Response
```

LangChain `@tool` functions are converted to OpenAI function-calling format
via `args_schema.schema()` before sending to Shield.

## Registering the Agent

Uncomment `register_agent()` in `__main__` to register. This creates:

| Role | Allowed Tools |
|---|---|
| user | `search_faq`, `check_order_status` |
| support | `search_faq`, `create_ticket`, `check_order_status` |
| admin | `search_faq`, `create_ticket`, `check_order_status` |

Change `USER_ROLE` to test different permission levels:

```bash
USER_ROLE=admin python shield_langchain_agent.py    # all tools allowed
USER_ROLE=user python shield_langchain_agent.py     # create_ticket blocked
```
