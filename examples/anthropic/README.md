# Anthropic Claude + LLM Shield

Protect Claude tool-use agents with Shield guardrails, RBAC, and shadow discovery.

## Prerequisites

- Python 3.10+
- A running LLM Shield instance (local or RunPod)
- An [Anthropic API key](https://console.anthropic.com/)
- An [OpenAI API key](https://platform.openai.com/) (Shield uses OpenAI internally for RBAC)

## Setup

```bash
cd examples/anthropic
pip install -r requirements.txt
```

## Configure

```bash
export LLM_SHIELD_URL="http://localhost:8080"      # your Shield URL
export API_KEY="tenant-...-key-..."                 # tenant API key
export ANTHROPIC_API_KEY="sk-ant-api03-..."         # Anthropic key
export OPENAI_API_KEY="sk-..."                      # OpenAI key (for Shield LLM)
```

Optional overrides:

```bash
export AGENT_ID="claude-support-agent"              # default agent ID
export USER_ROLE="user"                             # user/support/admin
export CLAUDE_MODEL="claude-sonnet-4-20250514"        # Claude model
```

## Run

```bash
python shield_anthropic_agent.py
```

### Expected output

```
============================================================
User: How do I reset my password?
============================================================
[input guardrails] passed
  [text] To reset your password...
  [ALLOWED] search_knowledge_base({"query": "reset password"}) -> KB result...
[output guardrails] passed

============================================================
User: Create a ticket: billing error on my account
============================================================
[input guardrails] passed
  [BLOCKED] create_ticket: Tool 'create_ticket' blocked for role 'user'
```

## Test Shadow Discovery

Skip registration to see the agent tracked as a shadow agent:

```bash
# Keep register_agent() commented out in the script, then run:
python shield_anthropic_agent.py
```

At the end it prints any shadow items Shield detected. You can also see them
in the tenant portal under the **Agents** tab → **Shadow Discovery** panel.

## How It Works

```
User Message
  │
  ├──▶ Shield /guardrails/input         block toxic/adversarial/PII
  │
  ├──▶ Anthropic Claude API             LLM decides tools (tool_use blocks)
  │
  ├──▶ Shield /v1/shield/chat/agent     RBAC on each tool call
  │      ├── allowed  → execute locally
  │      ├── blocked  → deny + log
  │      └── unregistered → shadow tracked
  │
  ├──▶ Shield /guardrails/output        block competitors/PII/bias
  │
  └──▶ Response
```

**Note:** Shield expects OpenAI-format tools. The example automatically converts
Claude's `input_schema` format to OpenAI's `parameters` format before sending
to `/v1/shield/chat/agent`.

## Registering the Agent

Uncomment `register_agent()` in `__main__` to register. This creates:

| Role | Allowed Tools |
|---|---|
| user | `search_knowledge_base` |
| support | `search_knowledge_base`, `create_ticket` |
| admin | `search_knowledge_base`, `create_ticket`, `escalate_to_human` |

Change `USER_ROLE` to test different permission levels:

```bash
USER_ROLE=admin python shield_anthropic_agent.py    # all tools allowed
USER_ROLE=user python shield_anthropic_agent.py     # only search allowed
```
