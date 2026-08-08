# LangChain + LLM Shield

## Start here

There are several patterns in this folder. **If you just want guardrails on a
LangChain agent, use the middleware** — it hooks LangChain's own extension
points, so you add a class rather than rewrite your agent loop.

```python
from votalai_middleware import VotalAIGuardrail

agent = create_agent(
    model=...,
    tools=[...],
    middleware=[VotalAIGuardrail(agent_key="support-bot", user_role="payments_officer")],
)
```

That one class covers three things:

| LangChain hook | what Shield does |
| --- | --- |
| `before_model` | input guardrails — injection blocked before it reaches the LLM |
| `after_model` | output guardrails — reply sanitized or blocked |
| `wrap_tool_call` | tool RBAC — a tool this role may not use never executes |

Two variables, and nothing else is required:

```bash
export LLM_SHIELD_URL="https://api.guardrails.votal.ai"
export TENANT_API_KEY="<your tenant key>"
```

`SHIELD_URL` also works for the first; `API_KEY` and `SHIELD_TENANT_KEY` also
work for the second, since other examples here use those names.

**Verify against your Shield before writing any code** — this needs no model
and no API key beyond the two above:

```bash
python middleware_demo.py
```

Expect `PASS=5 FAIL=0`: benign input passes, prompt injection is blocked, output
is screened, a forbidden tool never executes, an allowed tool runs. If this
fails, the problem is configuration, not your agent.

Run it with the **default** `AGENT_ID`. Pointing it at an agent you have
registered will fail the "allowed tool runs" case — correctly, because the
demo's tool is not in that agent's `role_permissions`. That is RBAC working,
not the middleware breaking.

### Which example do I want?

| you want | file |
| --- | --- |
| Guardrails on a LangChain agent (**start here**) | `votalai_middleware.py` + `middleware_demo.py` |
| Prove RBAC differs by role | `middleware_demo_rbac.py` |
| Full agent with input/output guardrails | `shield_langchain_agent.py` |
| Per-tool capabilities (mint + verify at the tool boundary) | `langchain_guarded_tools.py` |
| OIDC / workload identity | `langchain_oidc_decorator.py`, `spiffe_guarded_e2e.py` |
| Roles enforced with **no IdP** — your backend is the trusted proxy | `trusted_proxy_app.py` |
| Prove a stolen agent token is useless | `agent_token_theft_demo.py` |
| Prove a delegation chain cannot climb past its limit | `delegation_chain_demo.py` |

Two things worth knowing before you pick:

- The **capability** examples need `SHIELD_AGENT_TOKEN_PRIVATE_KEY` set
  consistently on the Shield deployment. Without it Shield signs agent tokens
  with an ephemeral per-process key and then rejects them — `401 invalid
  signature` at `/v1/shield/cap/mint`, with every tool denied.
- A guarded call against the cloud data plane takes roughly 25 seconds, and the
  first call after idle can fail on a cold start. Fine for a demo; size it into
  your UX before production.


Protect LangChain agents using the **two-plane production architecture**:

- **LLM + guardrails plane → LiteLLM proxy.** Input/output guardrails run
  *inside* the LiteLLM proxy via the votal.ai guardrails callback configured in
  its `config.yaml`. Your app just points the model at the proxy.
- **Agent + RBAC plane → LLM Shield.** Agent registration, role-based tool
  authorization, data-policy enforcement and shadow discovery go through the
  Shield endpoints.

```
User Message
  │
  ├─ LLM reasoning ─▶ LiteLLM proxy ─▶ [input guardrails] ─▶ LLM ─▶ [output guardrails]
  │                   (votal.ai callback in config.yaml — app never calls /guardrails/*)
  │
  └─ tool call ────▶ Shield /v1/shield/tool/check    RBAC + input data policy
                       ├─ allowed ▶ run tool ▶ Shield /v1/shield/tool/output (sanitize)
                       └─ blocked ▶ deny, reason returned to the agent
```

## Prerequisites

- Python 3.10+
- A **LiteLLM proxy** with the votal.ai guardrails callback configured
- A running **LLM Shield** instance (local or RunPod)

## Setup

```bash
cd examples/langchain
pip install -r requirements.txt
```

## Configure

Two planes, two sets of variables:

```bash
# Plane 1 — LiteLLM proxy (guardrails live in its config.yaml)
export LITELLM_URL="http://localhost:4000"      # LiteLLM proxy base URL
export LITELLM_API_KEY="sk-litellm-..."          # LiteLLM virtual key
export LLM_MODEL="gpt-4o-mini"                   # model alias in the proxy config

# Plane 2 — LLM Shield (agents + RBAC)
export LLM_SHIELD_URL="http://localhost:8080"    # Shield URL
export API_KEY="tenant-...-key-..."              # tenant API key
export AGENT_ID="langchain-support-agent"        # optional
export USER_ROLE="user"                          # user / support / admin
```

### LiteLLM proxy `config.yaml` (Plane 1)

The guardrails are configured **once, in the proxy** — not in your app:

```yaml
model_list:
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: os.environ/OPENAI_API_KEY

litellm_settings:
  callbacks:
    - votal_guardrails

votal_guardrails:
  api_url: "http://localhost:8080/guardrails/input"   # your Shield URL
  api_key: "tenant-...-key-..."
  input_guardrails:
    adversarial-prompt-detection: { enabled: true, action: block, threshold: 0.8 }
    pii-detection:                { enabled: true, action: block }
  output_guardrails:
    pii-leakage:        { enabled: true, action: block }
    competitor-mention: { enabled: true, action: warn }
```

## Run

```bash
python shield_langchain_agent.py
```

### Expected output

```
LLM plane  : LiteLLM proxy at http://localhost:4000 (model=gpt-4o-mini)
Agent plane: LLM Shield at http://localhost:8080 (agent=langchain-support-agent, role=user)

============================================================
User: What is your return policy?
============================================================
Response: Our return policy allows returns within 30 days...

============================================================
User: Create a ticket: billing issue on my last invoice
============================================================
  [Shield] BLOCKED create_ticket: create_ticket blocked for role 'user' — ...
Response: I'm not authorized to create a ticket for your account.
```

A prompt that trips an **input guardrail** never reaches the LLM — the LiteLLM
proxy returns an error, which the example reports as
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

Keeping guardrails in the proxy means every app and agent that talks to the
LiteLLM gateway is automatically guarded — no per-app guardrail code. The
Shield endpoints add the agent-aware layer (who may call which tool, with what
data) that a proxy can't enforce on its own.

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
USER_ROLE=user  python shield_langchain_agent.py    # create_ticket blocked by Shield
```

## Test Shadow Discovery

Keep `register_agent()` commented out and run the script. Because the agent
isn't registered, Shield tracks it (and its tools) as shadow items, printed at
the end and visible in the tenant portal under **Agents → Shadow Discovery**.

## Validate the agentic IdP end-to-end (asserting test)

`agentic_idp_e2e_test.py` is a **validating** counterpart to `langchain_e2e.py`:
it asserts the full agent Identity-Provider lifecycle and exits non-zero on any
failure. It covers identity (register, rogue-agent denial, token mint),
capabilities (mint → verify → **replay rejected** → **wrong-tool rejected**),
**RBAC denial** (least privilege), **input guardrail** block, **revocation**,
and **audit/telemetry** counters — plus an optional real LangChain agent turn
through the shielded tools.

```bash
export LLM_SHIELD_URL="https://<data-plane-host>"   # required
export API_KEY="<tenant X-API-Key>"                 # required
export ADMIN_KEY="<X-Admin-Key>"                    # for the revocation step
export RUNPOD_TOKEN="<proxy bearer>"                # if behind RunPod
# optional (enables step 11 — a real LangChain agent turn):
export LITELLM_URL="..."; export OPENAI_API_KEY="..."; export LLM_MODEL="gpt-4o-mini"

python3 agentic_idp_e2e_test.py     # prints PASS/FAIL per scenario; exit 0 = all passed
```

The agentic-IdP plane (steps 1-10) needs only Shield. The LangChain agent turn
(step 11) runs only when LLM creds are present. See also
[Continuous Identity & Auto-Revoke](../../docs/continuous-identity.md).

## One-line middleware: VotalAIGuardrail

For LangChain's `create_agent(middleware=[...])`, `votalai_middleware.py` provides a
single drop-in that replaces separate input/PII/safety middlewares with Shield:

```python
from langchain.agents import create_agent
from votalai_middleware import VotalAIGuardrail

agent = create_agent(
    model="gpt-5.5",
    tools=[search_tool, send_email_tool],
    middleware=[VotalAIGuardrail()],   # input + output guardrails + tool RBAC
)
```

It hooks the agent loop: `before_model` runs Shield input guardrails (unsafe ->
refusal), `after_model` runs output guardrails (sanitize or block), and
`wrap_tool_call` checks each tool against Shield RBAC + kill switch (blocked ->
the tool never runs). Config via constructor args or env (`LLM_SHIELD_URL`,
`TENANT_API_KEY`, `RUNPOD_TOKEN`, `agent_key`, `user_role`); toggle layers with
`check_input` / `check_output` / `check_tools`.

### Test the middleware locally

`middleware_demo.py` validates `VotalAIGuardrail` against a live Shield with no
model required (it exercises the hooks directly), then optionally runs a real
`create_agent` turn:

```bash
pip install langchain langchain-openai requests
export LLM_SHIELD_URL="$RUNPOD_HOST"; export TENANT_API_KEY="$TENANT_API_KEY"; export RUNPOD_TOKEN="$RUNPOD_TOKEN"
python3 examples/langchain/middleware_demo.py
# optional live agent turn:
#   export MODEL_BASE_URL=... MODEL_API_KEY=... MODEL_NAME=gpt-4o
```
Prints PASS/FAIL for: benign input passes, injection blocked, output sanitized,
forbidden tool blocked, allowed tool runs.

### More middleware demos (RBAC, data policy, agentic IdP)

Same pattern as `middleware_demo.py` (live Shield, no model required, PASS/FAIL):

| File | Shows |
|---|---|
| `middleware_demo_rbac.py` | role -> tool RBAC: same tool allowed for one role, blocked for another |
| `middleware_demo_rbac_data_policy.py` | RBAC + data policy: forbidden tool blocked, and a sensitive tool **output** sanitized/redacted by Shield |
| `middleware_demo_idp.py` | agentic IdP at the tool boundary: per-process identity token + per-tool-call capability mint/verify (single-use), forbidden tool blocked, capability replay rejected |

```bash
export LLM_SHIELD_URL="$RUNPOD_HOST"; export TENANT_API_KEY="$TENANT_API_KEY"; export RUNPOD_TOKEN="$RUNPOD_TOKEN"
python3 examples/langchain/middleware_demo_rbac.py
python3 examples/langchain/middleware_demo_rbac_data_policy.py
python3 examples/langchain/middleware_demo_idp.py
```
