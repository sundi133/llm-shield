#!/usr/bin/env python3
"""LangChain + LLM Shield Integration (production deployment architecture).

This example follows the two-plane deployment architecture:

  ┌──────────────────────────────────────────────────────────────────────┐
  │  PLANE 1 — LLM + GUARDRAILS  →  LiteLLM proxy                         │
  │                                                                       │
  │  The LangChain model (ChatOpenAI) points at the LiteLLM proxy whose  │
  │  config.yaml has the votal.ai guardrails callback configured. Input  │
  │  (PreCall) and output (PostCall) guardrail checks run *inside* the    │
  │  proxy — the app NEVER calls /guardrails/input or /guardrails/output  │
  │  directly. A blocked prompt/response surfaces as an error from the    │
  │  proxy, never reaching (or leaving) the LLM.                          │
  │                                                                       │
  │      LiteLLM config.yaml:                                             │
  │        litellm_settings:                                              │
  │          callbacks: [votal_guardrails]                                │
  │        votal_guardrails:                                              │
  │          api_url: "https://<shield>/guardrails/input"                 │
  │          input_guardrails:  {adversarial-prompt-detection, pii, ...}  │
  │          output_guardrails: {pii-leakage, competitor-mention, ...}    │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │  PLANE 2 — AGENTS + RBAC  →  LLM Shield endpoint                      │
  │                                                                       │
  │  Agent registration, role-based tool authorization, data-policy      │
  │  enforcement and shadow discovery all go through the Shield endpoints │
  │  (NOT through LiteLLM):                                               │
  │                                                                       │
  │      /v1/agents/registry     register agent + role_permissions       │
  │      /v1/shield/tool/check    pre-exec: RBAC + input data policy      │
  │      /v1/shield/tool/output   post-exec: output sanitization/redact   │
  │      /v1/agents/unregistered  shadow discovery                        │
  └──────────────────────────────────────────────────────────────────────┘

Flow per user message:

    User ──▶ LangChain AgentExecutor
               │
               ├─ LLM reasoning ─▶ LiteLLM proxy ─▶ (input/output guardrails) ─▶ LLM
               │
               └─ tool call ─▶ Shield /v1/shield/tool/check   (RBAC + data policy)
                                  ├─ allowed  ▶ run tool ▶ Shield /tool/output (sanitize)
                                  └─ blocked  ▶ deny, return reason to the agent

Usage:
    # Plane 1 — LiteLLM proxy (guardrails configured in its config.yaml)
    export LITELLM_URL="http://localhost:4000"
    export LITELLM_API_KEY="sk-litellm-..."     # LiteLLM virtual key
    export LLM_MODEL="gpt-4o-mini"              # model alias in litellm config

    # Plane 2 — LLM Shield (agents + RBAC)
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."         # tenant API key
    export AGENT_ID="langchain-support-agent"   # optional
    export USER_ROLE="user"                     # user / support / admin

    pip install -r requirements.txt
    python shield_langchain_agent.py
"""

import json
import os
import sys
import time

import requests
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate

try:
    from langchain.agents import create_tool_calling_agent, AgentExecutor
except ImportError:  # older LangChain
    from langchain.agents import create_openai_tools_agent as create_tool_calling_agent
    from langchain.agents import AgentExecutor

# ---------------------------------------------------------------------------
# Config — TWO separate planes
# ---------------------------------------------------------------------------

# Plane 1: LiteLLM proxy (guardrails run inside it via the votal.ai callback)
LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000").rstrip("/")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", os.getenv("OPENAI_API_KEY", "sk-noop"))
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

# Plane 2: LLM Shield (agents + RBAC + data policy)
SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080").rstrip("/")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "langchain-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
SESSION_ID = f"sess-{int(time.time())}"

# Shield session — agent identity + role travel on every Shield request
shield = requests.Session()
shield.headers.update({
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_ID,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
})


# ---------------------------------------------------------------------------
# 1. Register agent with Shield (run once — skip to test shadow discovery)
# ---------------------------------------------------------------------------

def register_agent():
    """Register the agent and its role-based tool permissions with Shield.

    If you skip this step the agent shows up as a *shadow agent* in the
    tenant portal's Agents tab, and every tool call is treated as
    unregistered.
    """
    payload = {
        "agent_id": AGENT_ID,
        "name": "LangChain Support Agent",
        "description": "Customer-facing support agent built with LangChain",
        "tools": ["search_faq", "create_ticket", "check_order_status"],
        "role_permissions": {
            "user": ["search_faq", "check_order_status"],
            "support": ["search_faq", "create_ticket", "check_order_status"],
            "admin": ["search_faq", "create_ticket", "check_order_status"],
        },
    }
    resp = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=payload)
    print(f"[register] {resp.status_code}: {resp.json()}")


# ---------------------------------------------------------------------------
# 2. Shield tool gate — RBAC + data policy around every tool execution
# ---------------------------------------------------------------------------

class ToolBlocked(Exception):
    """Raised when Shield denies a tool call. The message is returned to the
    agent so the LLM can explain the denial to the user."""


def _shield_tool_check(tool_name: str, args: dict) -> None:
    """Pre-execution gate: RBAC + input data-policy via Shield.

    Calls POST /v1/shield/tool/check. Raises ToolBlocked if denied.
    """
    resp = shield.post(
        f"{SHIELD_URL}/v1/shield/tool/check",
        json={
            "agent_key": AGENT_ID,
            "tool_name": tool_name,
            "user_role": USER_ROLE,
            "session_id": SESSION_ID,
            "tool_params": args,
        },
    )
    if resp.status_code != 200:
        # Fail closed on transport/auth errors
        raise ToolBlocked(f"tool/check failed ({resp.status_code}): {resp.text}")

    data = resp.json()
    allowed = data.get("allowed", True) and data.get("action") != "block"
    if not allowed:
        reason = "denied by policy"
        for r in data.get("guardrail_results", []):
            if not r.get("passed", True):
                reason = r.get("message", reason)
                break
        raise ToolBlocked(f"{tool_name} blocked for role '{USER_ROLE}' — {reason}")


def _shield_tool_output(tool_name: str, raw_output: str) -> str:
    """Post-execution gate: sanitize/redact tool output via Shield.

    Calls POST /v1/shield/tool/output. Returns the sanitized output, or
    raises ToolBlocked if the output must be withheld entirely.
    """
    resp = shield.post(
        f"{SHIELD_URL}/v1/shield/tool/output",
        json={
            "tool_name": tool_name,
            "tool_output": str(raw_output),
            "agent_key": AGENT_ID,
            "session_id": SESSION_ID,
        },
    )
    if resp.status_code != 200:
        # Don't leak unsanitized data on error — withhold
        raise ToolBlocked(f"{tool_name} output withheld (sanitizer error)")

    data = resp.json()
    if data.get("action") == "block":
        raise ToolBlocked(f"{tool_name} output blocked by data policy")
    return data.get("sanitized_output", str(raw_output))


def shielded(tool_name: str, args: dict, run):
    """Wrap a tool body: Shield RBAC pre-check → execute → Shield output check.

    `run` is a zero-arg callable that performs the real work. Any denial is
    converted into a plain string the agent (LLM) can read and relay.
    """
    try:
        _shield_tool_check(tool_name, args)
        raw = run()
        return _shield_tool_output(tool_name, raw)
    except ToolBlocked as e:
        print(f"  [Shield] BLOCKED {tool_name}: {e}")
        return f"BLOCKED by LLM Shield: {e}"


# ---------------------------------------------------------------------------
# 3. LangChain tools — each gated by Shield (Plane 2)
# ---------------------------------------------------------------------------

@tool
def search_faq(query: str) -> str:
    """Search the FAQ knowledge base for answers."""
    return shielded(
        "search_faq", {"query": query},
        lambda: f"FAQ result for '{query}': Please visit our help center at /help.",
    )


@tool
def create_ticket(subject: str, description: str) -> str:
    """Create a support ticket for the customer."""
    def run():
        ticket_id = abs(hash(subject)) % 100_000
        return f"Ticket TKT-{ticket_id} created: {subject}"
    return shielded("create_ticket", {"subject": subject, "description": description}, run)


@tool
def check_order_status(order_id: str) -> str:
    """Check the current status of a customer order."""
    return shielded(
        "check_order_status", {"order_id": order_id},
        lambda: f"Order {order_id}: Shipped — arriving in 2 business days.",
    )


TOOLS = [search_faq, create_ticket, check_order_status]


# ---------------------------------------------------------------------------
# 4. LangChain agent — LLM reasoning goes through the LiteLLM proxy (Plane 1)
# ---------------------------------------------------------------------------

def build_agent() -> AgentExecutor:
    """Build a LangChain agent whose LLM is the LiteLLM proxy.

    Because ChatOpenAI's base_url points at the LiteLLM proxy, every LLM
    request passes through the proxy's votal.ai guardrails callback:
    input guardrails run before the LLM, output guardrails run after.
    The app does not call /guardrails/* itself.
    """
    llm = ChatOpenAI(
        model=LLM_MODEL,
        base_url=f"{LITELLM_URL}/v1",   # ← LiteLLM proxy, guardrails live here
        api_key=LITELLM_API_KEY,        # ← LiteLLM virtual key
        temperature=0.1,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "You are a helpful customer support assistant. Use the provided tools "
         "to help the user. If a tool is blocked by policy, briefly explain that "
         "you are not authorized to perform that action."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    agent = create_tool_calling_agent(llm, TOOLS, prompt)
    return AgentExecutor(agent=agent, tools=TOOLS, verbose=False)


def run_agent(executor: AgentExecutor, user_message: str) -> str:
    """Run one turn through the architecture.

    LLM calls (and their input/output guardrails) go through the LiteLLM
    proxy; tool calls are gated by Shield RBAC + data policies.
    """
    print(f"\n{'=' * 60}")
    print(f"User: {user_message}")
    print(f"{'=' * 60}")

    try:
        result = executor.invoke({"input": user_message})
        output = result.get("output", "")
    except Exception as e:  # noqa: BLE001 — surface proxy-side guardrail blocks
        # A guardrail block inside the LiteLLM proxy comes back as an API
        # error (e.g. 400/403). Detect and report it cleanly.
        msg = str(e)
        if any(k in msg.lower() for k in ("guardrail", "blocked", "403", "policy")):
            print(f"[BLOCKED by LiteLLM proxy guardrails] {msg}")
            return "[Request blocked by guardrails in the LiteLLM proxy]"
        print(f"[Agent error] {msg}")
        return f"Error: {msg}"

    print(f"Response: {output}")
    return output


# ---------------------------------------------------------------------------
# 5. Shadow discovery — Shield endpoint
# ---------------------------------------------------------------------------

def check_shadow_items():
    """Fetch unregistered agents/tools that Shield has detected."""
    resp = shield.get(f"{SHIELD_URL}/v1/agents/unregistered")
    if resp.status_code != 200:
        print(f"Could not fetch shadow items: {resp.status_code}")
        return
    data = resp.json()
    if data.get("agents"):
        print("\nShadow Agents:")
        print(json.dumps(data["agents"], indent=2))
    if data.get("tools"):
        print("\nShadow Tools:")
        print(json.dumps(data["tools"], indent=2))
    if not data.get("agents") and not data.get("tools"):
        print("\nNo shadow agents or tools detected.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not API_KEY:
        print("WARNING: API_KEY not set — Shield requests may be rejected")
    print(f"LLM plane  : LiteLLM proxy at {LITELLM_URL} (model={LLM_MODEL})")
    print(f"Agent plane: LLM Shield at {SHIELD_URL} (agent={AGENT_ID}, role={USER_ROLE})")

    # Uncomment on first run to register the agent (skip to test shadow discovery):
    # register_agent()

    executor = build_agent()

    run_agent(executor, "What is your return policy?")
    run_agent(executor, "Check status of order ORD-12345")
    run_agent(executor, "Create a ticket: billing issue on my last invoice")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
