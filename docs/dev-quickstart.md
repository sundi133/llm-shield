---
title: Developer Quickstart
layout: default
nav_order: 2
permalink: /dev-quickstart/
description: Protect an agent and see your first role-based block in five minutes — three steps, no policy files, no GPU.
---

# Developer Quickstart
{: .no_toc }

Go from zero to a **visible block** in three steps. You'll mint a capability for an
agent and watch Shield deny a tool call that the role isn't allowed to make — without
changing a line of your agent's logic.
{: .fs-6 .fw-300 }

This path is CPU-only: role-based access control runs in Shield's fast tier, so you do
**not** need a GPU to complete it. (The GPU only powers the LLM content guardrails —
adversarial-prompt, topic, bias, etc.)

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The mental model — three steps

Integrating Shield is three ordered steps. Everything below is just these three:

1. **One-time setup** — install the SDK and point it at a running Shield.
2. **Per-process agent token** — on startup, your process identifies its agent and
   declares which role may use which tool (this is *capability minting*).
3. **Per-action capability check** — before each tool call, Shield says allow or block.

You don't need to know anything about Shield's internal architecture to do this. One SDK,
one decision per tool call.

---

## Step 0 — Point at a Shield

You need a Shield endpoint. Use the one your team already deployed (e.g. on RunPod), or
run one yourself:

```bash
pip install -r requirements.txt && python handler.py   # serves http://localhost:8080
```

Then install the SDK:

```bash
pip install votal
```

> **Sandbox mode.** For the quickstart, the SDK ships a built-in **sandbox** that needs
> no API key and no tenant setup: any `sk-test-…` key resolves to a shared sandbox tenant
> that Shield auto-provisions on first use. Use it to learn the flow, then swap in a real
> tenant key from the portal for production.

---

## Step 1 — Connect

```python
from votal import VotalShield

shield = VotalShield.sandbox(agent_id="support-bot", user_role="support")
# Running Shield somewhere other than localhost:8080?
#   VotalShield.sandbox(..., shield_url="https://YOUR_ENDPOINT")
```

That's the whole "one-time setup." `sandbox()` is shorthand for:

```python
shield = VotalShield(
    shield_url="http://localhost:8080",
    api_key="sk-test-sandbox",        # sandbox key → sandbox tenant
    agent_id="support-bot",
    user_role="support",
    tenant_id="test-tenant-001",      # sandbox tenant
)
```

For production, drop `sandbox()` and pass your real `shield_url` + `api_key`.

---

## Step 2 — Mint capabilities

On startup, declare which role may use which tool. This call is idempotent — safe to run
every boot.

```python
shield.register_agent(
    tools=["get_balance", "transfer_funds"],
    role_permissions={
        "admin":   ["get_balance", "transfer_funds"],
        "support": ["get_balance"],          # support may read, not move money
    },
    name="Support Bot",
)
```

You just minted a capability: `support` can read balances but cannot transfer funds.

---

## Step 3 — See the block

Ask Shield before each tool call. No GPU, no policy file — the answer is deterministic.

```python
for role, tool in [("support", "get_balance"),
                   ("support", "transfer_funds"),   # should be BLOCKED
                   ("admin",   "transfer_funds")]:
    guard = shield.check_tool(tool, user_role=role)
    print("allow" if guard.allowed else "BLOCK", role, "→", tool, "—", guard.reason)
```

```text
allow support → get_balance    — RBAC check passed
BLOCK support → transfer_funds  — Role 'support' is not allowed to use tool 'transfer_funds'
allow admin   → transfer_funds  — RBAC check passed
```

That `BLOCK` is Shield enforcing the capability you minted in Step 2.

**Run the whole thing:** [`examples/quickstart/first_block.py`](https://github.com/) does
exactly the above in one file (with a friendly message if Shield isn't reachable):

```bash
python examples/quickstart/first_block.py
# point elsewhere:  SHIELD_URL=https://YOUR_ENDPOINT python examples/quickstart/first_block.py
```

---

## Wire it into a real agent

You rarely call `check_tool` by hand. Wrap your tools once and every call is checked +
sanitized automatically. LangChain:

```python
@shield.protect
@tool
def transfer_funds(account: str, amount: float) -> str:
    return bank.transfer(account, amount)
```

…or wrap a whole list, or attach a callback that guards every tool the agent has:

```python
tools = shield.wrap_tools([get_balance, transfer_funds])
# or
executor = AgentExecutor(agent=agent, tools=tools, callbacks=[shield.callback()])
```

When a role isn't allowed, the tool returns `DENIED by Shield: …` instead of executing —
the model sees the denial and moves on.

---

## What just happened (the part you didn't have to think about)

Shield has two enforcement points — input/output **content** guardrails and agentic
**tool** RBAC/data policies. This quickstart used only the tool path, and the SDK hides
the rest. When you're ready:

- **Output sanitization** — `shield.sanitize_output(tool, raw)` redacts PII/secrets from
  what a tool returns, per role. `@shield.protect` already does this for you.
- **Content guardrails** (the GPU tier) — adversarial-prompt, topic, bias, PII. These run
  on the message stream; see the [Guardrails Catalog]({{ "/guardrails/" | relative_url }}).
- **Real tenants & keys** — mint a tenant API key in the portal and replace `sandbox()`.

---

## Where to next

- [Agentic Integration Guide]({{ "/agentic-integration-guide/" | relative_url }}) — RBAC,
  data scopes, approval workflows, kill switch
- [Guardrails Catalog]({{ "/guardrails/" | relative_url }}) — what each guardrail does
- [API Reference]({{ "/api-reference/" | relative_url }}) — every endpoint and shape
- [Quickstart (deployment)]({{ "/quickstart/" | relative_url }}) — Docker / RunPod / on-prem install options
