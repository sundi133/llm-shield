# CrewAI + LLM Shield

Protect multi-agent CrewAI crews with per-agent RBAC, guardrails, and shadow discovery.

## Prerequisites

- Python 3.10+
- A running LLM Shield instance (local or RunPod)
- An [OpenAI API key](https://platform.openai.com/)

## Setup

```bash
cd examples/crewai
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
export USER_ROLE="analyst"                          # analyst/viewer
```

## Run

```bash
python shield_crewai_agent.py
```

### Expected output

```
============================================================
Crew topic: Analyze Q1 2026 market trends in AI infrastructure
============================================================
[input guardrails] passed

Agent: Research Analyst
  [ALLOWED] web_search — OK
  [ALLOWED] document_search — OK

Agent: Report Writer
  [ALLOWED] generate_report — OK
  [BLOCKED] send_email: Tool 'send_email' blocked for role 'viewer'

[output guardrails] passed
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

Change `USER_ROLE` to test different permission levels:

```bash
USER_ROLE=analyst python shield_crewai_agent.py   # all tools allowed
USER_ROLE=viewer python shield_crewai_agent.py    # some tools blocked
```

## Test Shadow Discovery

Skip registration to see crew members tracked as shadow agents:

```bash
# Keep register_crew() commented out in the script, then run:
python shield_crewai_agent.py
```

At the end it prints any shadow items Shield detected. You can also see them
in the tenant portal under the **Agents** tab → **Shadow Discovery** panel.

## How It Works

```
CrewAI Kickoff
  │
  ├──▶ Shield /guardrails/input         validate crew topic
  │
  ├──▶ Agent 1: Researcher (agent_key=research-agent)
  │      └── Shield /v1/shield/chat/agent   RBAC per tool
  │
  ├──▶ Agent 2: Writer (agent_key=writer-agent)
  │      └── Shield /v1/shield/chat/agent   RBAC per tool
  │
  ├──▶ Shield /guardrails/output        validate final output
  │
  └──▶ Result
```

Each `ShieldTool` subclass routes its execution through Shield's chat/agent
endpoint, passing its own `agent_key` so RBAC is enforced per crew member.

## Registering the Crew

Uncomment `register_crew()` in `__main__` to register both agents at once.
