#!/usr/bin/env python3
"""LangChain + LLM Shield Integration

Demonstrates a LangChain agent protected by LLM Shield:
  - Agent registration with role-based tool permissions
  - Input guardrails (adversarial, toxicity, PII) before LLM call
  - RBAC enforcement via Shield's /v1/shield/chat/agent endpoint
  - Output guardrails on the final response
  - Shadow discovery for unregistered agents/tools

Usage:
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export OPENAI_API_KEY="sk-..."
    export AGENT_ID="my-langchain-agent"    # optional
    export USER_ROLE="user"                 # optional

    pip install -r requirements.txt
    python shield_langchain_agent.py
"""

import json
import os
import sys

import requests
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "langchain-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")

shield = requests.Session()
shield.headers.update({
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_ID,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
})


# ---------------------------------------------------------------------------
# 1. Register agent (run once — skip to test shadow discovery)
# ---------------------------------------------------------------------------

def register_agent():
    """Register the agent and its tools with Shield.

    If you skip this step the agent will appear as a *shadow agent*
    in the tenant portal's Agents tab.
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
# 2. Define LangChain tools
# ---------------------------------------------------------------------------

@tool
def search_faq(query: str) -> str:
    """Search the FAQ knowledge base for answers."""
    return f"FAQ result for '{query}': Please visit our help center at /help."


@tool
def create_ticket(subject: str, description: str) -> str:
    """Create a support ticket for the customer."""
    ticket_id = abs(hash(subject)) % 100_000
    return f"Ticket TKT-{ticket_id} created: {subject}"


@tool
def check_order_status(order_id: str) -> str:
    """Check the current status of a customer order."""
    return f"Order {order_id}: Shipped — arriving in 2 business days."


TOOLS = [search_faq, create_ticket, check_order_status]


# ---------------------------------------------------------------------------
# 3. Convert LangChain tools to OpenAI function-calling format
# ---------------------------------------------------------------------------

def langchain_tools_to_openai(tools: list) -> list[dict]:
    """Convert LangChain @tool definitions to OpenAI function-calling schema."""
    openai_tools = []
    for t in tools:
        schema = t.args_schema.schema()
        props = schema.get("properties", {})
        required = schema.get("required", [])
        # Strip pydantic metadata keys that OpenAI strict mode rejects
        clean_props = {}
        for k, v in props.items():
            clean_props[k] = {"type": v.get("type", "string")}
            if "description" in v:
                clean_props[k]["description"] = v["description"]

        openai_tools.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": clean_props,
                    "required": required,
                    "additionalProperties": False,
                },
            },
        })
    return openai_tools


# ---------------------------------------------------------------------------
# 4. Shield-wrapped agent loop
# ---------------------------------------------------------------------------

def run_agent(user_message: str) -> str:
    """Send a message through the full Shield pipeline.

    Flow:
        1. /guardrails/input   — block toxic / adversarial / PII input
        2. /v1/shield/chat/agent — LLM picks tools, Shield enforces RBAC
        3. Execute allowed tools locally
        4. /guardrails/output  — block competitors / PII in output
    """
    print(f"\n{'='*60}")
    print(f"User: {user_message}")
    print(f"{'='*60}")

    # -- Step 1: input guardrails ------------------------------------------
    guard_in = shield.post(
        f"{SHIELD_URL}/guardrails/input",
        json={"message": user_message},
    )
    if guard_in.status_code == 200:
        gin = guard_in.json()
        if gin.get("action") == "block":
            triggered = [
                r["guardrail"]
                for r in gin.get("guardrail_results", [])
                if r.get("action") == "block"
            ]
            msg = f"[BLOCKED by input guardrails: {', '.join(triggered)}]"
            print(msg)
            return msg
        print("[input guardrails] passed")
    else:
        print(f"[input guardrails] skipped (status {guard_in.status_code})")

    # -- Step 2: Shield agent chat (LLM + RBAC) ---------------------------
    openai_tools = langchain_tools_to_openai(TOOLS)
    chat_resp = shield.post(
        f"{SHIELD_URL}/v1/shield/chat/agent",
        json={
            "messages": [{"role": "user", "content": user_message}],
            "agent_key": AGENT_ID,
            "user_role": USER_ROLE,
            "llm_api_key": os.getenv("OPENAI_API_KEY"),
            "llm_model": os.getenv("LLM_MODEL", "gpt-4o-mini"),
            "tools": openai_tools,
        },
    )
    if chat_resp.status_code != 200:
        err = chat_resp.text
        print(f"[Shield chat error] {chat_resp.status_code}: {err}")
        return f"Error: {err}"

    result = chat_resp.json()

    # -- Step 3: execute allowed tool calls --------------------------------
    tool_map = {t.name: t for t in TOOLS}
    output_parts = []

    for tc in result.get("tool_calls", []):
        name = tc["tool_name"]
        args = tc.get("arguments", {})
        rbac = tc.get("rbac", {})

        if rbac.get("allowed"):
            fn = tool_map.get(name)
            if fn:
                out = fn.invoke(args)
                print(f"  [ALLOWED] {name}({args}) -> {out}")
                output_parts.append(out)
            else:
                print(f"  [ALLOWED] {name} — no local handler")
        else:
            msg = f"BLOCKED: {name} — {rbac.get('message', 'denied by RBAC')}"
            print(f"  [BLOCKED] {name}: {rbac.get('message')}")
            output_parts.append(msg)

    # -- Shadow discovery feedback -----------------------------------------
    unreg = result.get("unregistered", {})
    if unreg.get("agents"):
        print(f"  [SHADOW] Unregistered agent(s): {unreg['agents']}")
    if unreg.get("tools"):
        print(f"  [SHADOW] Unregistered tool(s): {unreg['tools']}")

    # -- Step 4: output guardrails -----------------------------------------
    final_text = result.get("text", "") or "\n".join(output_parts)
    if final_text:
        guard_out = shield.post(
            f"{SHIELD_URL}/guardrails/output",
            json={"output": final_text},
        )
        if guard_out.status_code == 200:
            gout = guard_out.json()
            if gout.get("action") == "block":
                print("[BLOCKED by output guardrails]")
                return "[Response blocked by output policy]"
            print("[output guardrails] passed")

    print(f"Response: {final_text}")
    return final_text


# ---------------------------------------------------------------------------
# 5. Shadow discovery check
# ---------------------------------------------------------------------------

def check_shadow_items():
    """Fetch unregistered agents/tools that Shield has detected."""
    resp = shield.get(f"{SHIELD_URL}/v1/agents/unregistered")
    if resp.status_code == 200:
        data = resp.json()
        if data.get("agents"):
            print("\nShadow Agents:")
            print(json.dumps(data["agents"], indent=2))
        if data.get("tools"):
            print("\nShadow Tools:")
            print(json.dumps(data["tools"], indent=2))
        if not data.get("agents") and not data.get("tools"):
            print("\nNo shadow agents or tools detected.")
    else:
        print(f"Could not fetch shadow items: {resp.status_code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set")
        sys.exit(1)
    if not API_KEY:
        print("WARNING: API_KEY not set — requests may be rejected")

    # Uncomment to register the agent (skip to test shadow discovery):
    # register_agent()

    run_agent("What is your return policy?")
    run_agent("Check status of order ORD-12345")
    run_agent("Create a ticket: billing issue on my last invoice")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
