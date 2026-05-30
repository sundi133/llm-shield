# CrewAI + LLM Shield

Protect multi-agent CrewAI crews using the **two-plane production
architecture**, with per-agent RBAC:

- **LLM + guardrails plane → LiteLLM proxy.** Each crew agent's LLM points at
  the LiteLLM proxy whose `config.yaml` has the votal.ai guardrails callback
  configured. Input/output guardrails run *inside* the proxy. (CrewAI already
  uses LiteLLM under the hood, so this is just a `base_url`.)
- **Agent + RBAC plane → LLM Shield.** Each crew member registers as its own
  Shield agent; tool calls are gated by the Shield endpoints.

```
CrewAI Kickoff
  │
  ├─ agent reasoning ─▶ LiteLLM proxy ─▶ [input guardrails] ─▶ LLM ─▶ [output guardrails]
  │                     (votal.ai callback in config.yaml — app never calls /guardrails/*)
  │
  ├─ Researcher (agent_key=research-agent)
  │     └─ tool call ─▶ Shield /v1/shield/tool/check ─▶ run ─▶ /v1/shield/tool/output
  │
  └─ Writer (agent_key=writer-agent)
        └─ tool call ─▶ Shield /v1/shield/tool/check ─▶ run ─▶ /v1/shield/tool/output
```

## Prerequisites

- Python 3.10+
- A **LiteLLM proxy** with the votal.ai guardrails callback configured
- A running **LLM Shield** instance (local or RunPod)

## Setup

```bash
cd examples/crewai
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
export USER_ROLE="analyst"                       # analyst / viewer
```

See the [LangChain example README](../langchain/README.md#litellm-proxy-configyaml-plane-1)
for a sample LiteLLM `config.yaml` with the votal.ai guardrails callback.

## Run

```bash
python shield_crewai_agent.py
```

### Expected output

```
LLM plane  : LiteLLM proxy at http://localhost:4000 (model=gpt-4o-mini)
Agent plane: LLM Shield at http://localhost:8080 (role=analyst)

============================================================
Crew topic: Analyze Q1 2026 market trends in AI infrastructure
============================================================
  [ALLOWED] web_search('AI infrastructure 2026') -> Web results...
  [ALLOWED] generate_report('...') -> Report draft generated...
  [Shield] BLOCKED send_email: send_email blocked for role 'viewer' — ...
Final output: ...
```

## Multi-Agent RBAC

Each crew member registers as a **separate Shield agent** with its own RBAC:

**research-agent:**

| Role | Allowed Tools |
|---|---|
| analyst | `web_search`, `document_search` |
| viewer | `web_search` |

**writer-agent:**

| Role | Allowed Tools |
|---|---|
| analyst | `generate_report`, `send_email` |
| viewer | `generate_report` |

```bash
USER_ROLE=analyst python shield_crewai_agent.py   # all tools allowed
USER_ROLE=viewer  python shield_crewai_agent.py   # some tools blocked by Shield
```

Each `ShieldTool` subclass implements `execute()` for the real work; the base
class gates every call through Shield's `/v1/shield/tool/check` (pre, RBAC +
data policy) and `/v1/shield/tool/output` (post, sanitization), passing its own
`agent_key` so RBAC is enforced per crew member.

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

Keep `register_crew()` commented out and run the script — Shield tracks both
crew members and their tools as shadow items, printed at the end and visible in
the tenant portal under **Agents → Shadow Discovery**.

## Registering the Crew

Uncomment `register_crew()` in `__main__` to register both agents at once.
