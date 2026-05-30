#!/usr/bin/env python3
"""LangChain + LLM Shield Integration (Production Architecture)

Correct flow based on the production deployment architecture:

  Client/App ──▶ LiteLLM Proxy (port 8000) ──▶ LLMs (GPU)
                     │
                     │  LiteLLM handles input/output guardrails
                     │  automatically via Shield middleware
                     │
                     └──▶ Shield Guardrail Service
                           ├── Input/Output guardrails (automatic)
                           ├── Agent RBAC (/v1/shield/tool/check)
                           ├── Tool output sanitization (/v1/shield/tool/output)
                           └── Agent registry (/v1/agents/registry)

Key principle:
  - The APP never calls /guardrails/input or /guardrails/output directly.
  - LiteLLM proxy applies those automatically on every LLM call.
  - The APP only calls Shield for: agent registration, tool RBAC checks,
    tool output sanitization, and data policy enforcement.
  - LangChain uses LiteLLM as its LLM endpoint (OpenAI-compatible).

Usage:
    export LITELLM_URL="http://localhost:8000"        # LiteLLM proxy
    export LLM_SHIELD_URL="http://localhost:8080"     # Shield service
    export API_KEY="tenant-...-key-..."
    export OPENAI_API_KEY="sk-..."                    # for LiteLLM backend
    export AGENT_ID="my-langchain-agent"              # optional
    export USER_ROLE="user"                           # optional

    pip install langchain langchain-openai
    python shield_langchain_agent.py
"""

import json
import os
import sys
import time

import requests
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

# ---------------------------------------------------------------------------
# Config — TWO separate planes
# ---------------------------------------------------------------------------

# LiteLLM proxy — LangChain talks to this as its LLM.
# LiteLLM automatically applies input/output guardrails via Shield.
LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:8000")

# Shield service — only for agent RBAC, tool checks, data policies.
SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080")

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
# 3. Shield helper: check tool RBAC + data policies before execution
# ---------------------------------------------------------------------------

def shield_check_tool(tool_name: str, tool_args: dict) -> dict:
    """Pre-execution check: RBAC + data policy on tool arguments.

    This is the ONLY Shield call the app makes before executing a tool.
    Returns {"allowed": bool, "reason": str}.
    """
    resp = shield.post(f"{SHIELD_URL}/v1/shield/tool/check", json={
        "tool_name": tool_name,
        "tool_input": tool_args,
        "agent_key": AGENT_ID,
        "user_role": USER_ROLE,
    })
    if resp.status_code != 200:
        return {"allowed": False, "reason": f"Shield error: {resp.status_code}"}
    data = resp.json()
    return {
        "allowed": data.get("allowed", True),
        "reason": data.get("reason", ""),
        "guardrail_results": data.get("guardrail_results", []),
    }


def shield_sanitize_output(tool_name: str, tool_output: str) -> dict:
    """Post-execution: sanitize tool output (PII redaction, data policies).

    This applies mask/redact/block based on the role's data policy
    configured in the tenant portal.
    """
    resp = shield.post(f"{SHIELD_URL}/v1/shield/tool/output", json={
        "tool_name": tool_name,
        "tool_output": tool_output,
        "agent_key": AGENT_ID,
    })
    if resp.status_code != 200:
        return {"sanitized_output": tool_output, "action": "pass"}
    return resp.json()


# ---------------------------------------------------------------------------
# 4. Shield-wrapped agent loop
# ---------------------------------------------------------------------------

def run_agent(user_message: str) -> str:
    """Send a message through the LangChain agent with Shield tool protection.

    Flow:
      1. LangChain calls LiteLLM (input guardrails applied automatically)
      2. LLM returns tool_calls
      3. For each tool call:
         a. Shield /v1/shield/tool/check → RBAC + data policy on args
         b. If allowed → execute tool locally
         c. Shield /v1/shield/tool/output → sanitize output (mask/redact)
      4. Feed sanitized tool results back to LLM
      5. LLM generates final response (output guardrails applied by LiteLLM)
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

    # LangChain LLM pointed at LiteLLM proxy.
    # LiteLLM automatically applies input/output guardrails — no direct
    # /guardrails/input or /guardrails/output calls needed.
    llm = ChatOpenAI(
        model="default",
        base_url=f"{LITELLM_URL}/v1",
        api_key=os.getenv("OPENAI_API_KEY", "not-needed"),
        default_headers={
            "X-API-Key": API_KEY,
            "X-Agent-Key": AGENT_ID,
            "X-User-Role": USER_ROLE,
        },
    )

    # Bind tools so LLM can request function calls
    llm_with_tools = llm.bind_tools(TOOLS)

    # Initial LLM call — LiteLLM applies input guardrails before forwarding
    messages = [HumanMessage(content=user_message)]
    try:
        response = llm_with_tools.invoke(messages)
    except Exception as e:
        # If input guardrails block, LiteLLM returns 400/403
        msg = f"[BLOCKED by guardrails] {e}"
        print(msg)
        return msg

    # If no tool calls, return the text response directly
    # (output guardrails already applied by LiteLLM)
    if not response.tool_calls:
        print(f"Response: {response.content}")
        return response.content

    # Process tool calls with Shield RBAC + data policy checks
    messages.append(response)
    tool_map = {t.name: t for t in TOOLS}
    output_parts = []

    for tc in response.tool_calls:
        name = tc["name"]
        args = tc["args"]
        tool_call_id = tc["id"]

        # Step 3a: Shield RBAC + data policy check on tool arguments
        check = shield_check_tool(name, args)

        if not check["allowed"]:
            reason = check.get("reason", "denied by RBAC/data policy")
            print(f"  [BLOCKED] {name}({args}) — {reason}")
            # Tell the LLM the tool was denied
            messages.append(ToolMessage(
                content=f"DENIED: {reason}",
                tool_call_id=tool_call_id,
            ))
            output_parts.append(f"BLOCKED: {name} — {reason}")
            continue

        # Step 3b: Execute the tool locally
        fn = tool_map.get(name)
        if not fn:
            messages.append(ToolMessage(
                content=f"Unknown tool: {name}",
                tool_call_id=tool_call_id,
            ))
            continue

        raw_output = fn.invoke(args)
        print(f"  [ALLOWED] {name}({args}) -> {raw_output}")

        # Step 3c: Sanitize tool output (mask/redact/block per data policy)
        sanitized = shield_sanitize_output(name, str(raw_output))

        if sanitized.get("action") == "block":
            print(f"  [OUTPUT BLOCKED] {name} output violated data policy")
            messages.append(ToolMessage(
                content="Tool output blocked by data policy.",
                tool_call_id=tool_call_id,
            ))
            output_parts.append(f"BLOCKED: {name} output violated data policy")
        else:
            clean = sanitized.get("sanitized_output", str(raw_output))
            if clean != str(raw_output):
                print(f"  [SANITIZED] {name}: {clean}")
            messages.append(ToolMessage(
                content=clean,
                tool_call_id=tool_call_id,
            ))
            output_parts.append(clean)

    # Step 4: Final LLM call with tool results
    # LiteLLM applies output guardrails automatically on the response
    try:
        final_response = llm_with_tools.invoke(messages)
        print(f"Response: {final_response.content}")
        return final_response.content
    except Exception as e:
        # Output guardrails may block
        fallback = "\n".join(output_parts)
        print(f"[Output blocked or error] {e}")
        return fallback


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
