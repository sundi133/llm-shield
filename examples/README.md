# LLM Shield — Framework Integration Examples

Working examples showing how to integrate LLM Shield with popular agent frameworks.

## Directory Structure

```
examples/
├── langchain/         # LangChain agent with Shield guardrails + RBAC
├── openai_agents/     # OpenAI function-calling agent with Shield
├── crewai/            # Multi-agent CrewAI crew with per-agent RBAC
├── anthropic/         # Anthropic Claude tool-use agent with Shield
├── idp/               # Identity Provider integration guide (Okta, Auth0, Azure AD, Keycloak)
├── mcp_server/            # Deployable MCP server (FastMCP) that guards its own tools via Shield
├── mcp_guarded_agent.py   # Guard an agent turn via Shield's MCP server (stdlib-only, runnable)
├── deep_agent_shield.py   # Advanced async integration (httpx)
└── policy_management_example.py
```

### Guard an agent over MCP (no dependencies)

`mcp_guarded_agent.py` shows the **cooperative** model: an agent connects to
Shield's own MCP server and calls the `shield_*` guardrail tools at each step of
a turn — input → tool call → tool result → final reply. It stubs the LLM and the
business tool, so it runs with just stdlib and a tenant key:

```bash
export SHIELD_URL=https://<your-data-plane-host>
export TENANT_KEY=sk-test-demo        # any sk-test- key hits the sandbox tenant
# export RUNPOD_TOKEN=...              # only if the data plane is behind a proxy
python3 examples/mcp_guarded_agent.py
```

It demonstrates three outcomes: a benign turn passing, a prompt-injection input
blocked, and an RBAC denial. For non-bypassable enforcement, pair it with the
gateway/proxy paths (see the MCP developer guide).

### Deploy your own guarded MCP server

`mcp_server/` is a **deployable** remote MCP server (FastMCP, streamable-HTTP)
that guards the tools *it* exposes: role→tool RBAC (`/v1/shield/tool/check`),
input screening (`/guardrails/input`), and output sanitization
(`/v1/shield/tool/output`). Set `SHIELD_URL` + `SHIELD_TENANT_KEY`, deploy to
Railway (or any container host), and point an MCP client at `/mcp`. See
[`mcp_server/README.md`](mcp_server/README.md).

## Quick Start

### 1. Set Environment Variables

These examples use a **two-plane architecture** — guardrails live in the
LiteLLM proxy, agents/RBAC live in LLM Shield — so there are two sets of vars:

```bash
# Plane 1 — LiteLLM proxy (votal.ai guardrails configured in its config.yaml)
export LITELLM_URL="http://localhost:4000"        # LiteLLM proxy base URL
export LITELLM_API_KEY="sk-litellm-..."            # LiteLLM virtual key
export LLM_MODEL="gpt-4o-mini"                     # model alias in the proxy

# Plane 2 — LLM Shield (agents + RBAC)
export LLM_SHIELD_URL="http://localhost:8080"     # or your RunPod URL
export API_KEY="tenant-...-key-..."
```

> The proxy's API keys for the upstream LLM (OpenAI/Anthropic/...) live in the
> **LiteLLM proxy** config, not in these apps. See any framework README for a
> sample `config.yaml` with the `votal_guardrails` callback.

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
| Guardrails (in LiteLLM proxy) | ✅ | ✅ | ✅ | ✅ |
| Tool RBAC (Shield) | ✅ | ✅ | ✅ | ✅ |
| Per-tool data policy (Shield) | ✅ | ✅ | ✅ | ✅ |
| Shadow Discovery | ✅ | ✅ | ✅ | ✅ |
| Multi-Agent | — | — | ✅ | — |

## Integration Flow

All examples follow the same **two-plane** pattern:

```
User Message
  │
  ├─ LLM reasoning ─▶ LiteLLM proxy ─▶ [input guardrails] ─▶ LLM ─▶ [output guardrails]
  │                   (votal.ai callback in config.yaml — apps never call /guardrails/*)
  │
  └─ tool call ────▶ Shield /v1/shield/tool/check    RBAC + input data policy
                       ├─ allowed ▶ run tool ▶ Shield /v1/shield/tool/output (sanitize)
                       ├─ blocked ▶ deny + log
                       └─ unregistered ▶ shadow discovery
```

**Why split?** Putting guardrails in the LiteLLM proxy means every app and
agent that talks to the gateway is automatically guarded — no per-app guardrail
code. The Shield endpoints add the agent-aware layer (who may call which tool,
with what data) that a proxy can't enforce on its own.

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

| Plane | Endpoint | Method | Purpose |
|---|---|---|---|
| LiteLLM proxy | `/v1/chat/completions` (or `/v1/messages`) | POST | LLM call; guardrails run via the proxy's `votal_guardrails` callback |
| LiteLLM proxy → Shield | `/guardrails/input`, `/guardrails/output` | POST | Called *by the proxy*, not the apps |
| Shield | `/v1/agents/registry` | POST | Register an agent |
| Shield | `/v1/shield/tool/check` | POST | Pre-exec RBAC + input data policy |
| Shield | `/v1/shield/tool/output` | POST | Post-exec output sanitization/redaction |
| Shield | `/v1/agents/unregistered` | GET | List shadow agents/tools |
