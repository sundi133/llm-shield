# LLM Shield — Framework Integration Examples

Working examples showing how to integrate LLM Shield with popular agent frameworks.

## Directory Structure

```
examples/
├── langchain/         # LangChain agent with Shield guardrails + RBAC
├── openai_agents/     # OpenAI function-calling agent with Shield
├── crewai/            # Multi-agent CrewAI crew with per-agent RBAC
├── anthropic/         # Anthropic Claude tool-use agent with Shield
├── deep_agent_shield.py   # Advanced async integration (httpx)
└── policy_management_example.py
```

## Quick Start

### 1. Set Environment Variables

```bash
export LLM_SHIELD_URL="http://localhost:8080"     # or your RunPod URL
export API_KEY="tenant-...-key-..."
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."              # only for Anthropic example
```

### 2. Pick a Framework

```bash
# LangChain
cd examples/langchain
pip install -r requirements.txt
python shield_langchain_agent.py

# OpenAI Agents
cd examples/openai_agents
pip install -r requirements.txt
python shield_openai_agent.py

# CrewAI
cd examples/crewai
pip install -r requirements.txt
python shield_crewai_agent.py

# Anthropic Claude
cd examples/anthropic
pip install -r requirements.txt
python shield_anthropic_agent.py
```

## What Each Example Covers

| Feature | LangChain | OpenAI | CrewAI | Anthropic |
|---|---|---|---|---|
| Agent Registration | ✅ | ✅ | ✅ | ✅ |
| Input Guardrails | ✅ | ✅ | ✅ | ✅ |
| Output Guardrails | ✅ | ✅ | ✅ | ✅ |
| Tool RBAC | ✅ | ✅ | ✅ | ✅ |
| Shadow Discovery | ✅ | ✅ | ✅ | ✅ |
| Multi-Agent | — | — | ✅ | — |
| Direct LLM Flow | — | ✅ | — | — |

## Integration Flow

All examples follow the same pattern:

```
User Message
  │
  ├──▶ Shield /guardrails/input     — block toxic / adversarial / PII
  │
  ├──▶ Shield /v1/shield/chat/agent — LLM picks tools, RBAC enforced
  │      ├── allowed  → execute tool locally
  │      ├── blocked  → deny + log
  │      └── unregistered → shadow discovery
  │
  ├──▶ Shield /guardrails/output    — block competitors / PII / bias
  │
  └──▶ Response
```

## Testing Shadow Discovery

To test shadow discovery, **skip the `register_agent()` call**. When the agent
makes API calls without being registered, Shield tracks it as a shadow agent.

```python
# In any example, keep this commented out:
# register_agent()

# Run the agent — it will work but be tracked
run_agent("Check order status")

# Then check what Shield detected:
check_shadow_items()
```

The shadow items will also be visible in the tenant portal under the Agents tab.

## API Endpoints Used

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/agents/registry` | POST | Register an agent |
| `/guardrails/input` | POST | Input guardrails |
| `/guardrails/output` | POST | Output guardrails |
| `/v1/shield/chat/agent` | POST | LLM + RBAC enforcement |
| `/v1/agents/unregistered` | GET | List shadow agents/tools |
