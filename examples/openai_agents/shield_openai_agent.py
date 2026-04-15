#!/usr/bin/env python3
"""OpenAI Agents SDK + LLM Shield Integration

Demonstrates an OpenAI function-calling agent protected by LLM Shield:
  - Agent registration with role-based tool permissions
  - Input guardrails (adversarial, toxicity, PII) before LLM call
  - RBAC enforcement via Shield's /v1/shield/chat/agent endpoint
  - Output guardrails on the final response
  - Shadow discovery for unregistered agents/tools

Usage:
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export OPENAI_API_KEY="sk-..."
    export AGENT_ID="my-openai-agent"    # optional
    export USER_ROLE="user"              # optional

    pip install -r requirements.txt
    python shield_openai_agent.py
"""

import json
import os
import sys
from typing import Any

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "openai-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

client = OpenAI()

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
        "name": "OpenAI Support Agent",
        "description": "Order management agent built with OpenAI function calling",
        "tools": ["lookup_order", "cancel_order", "get_refund_status"],
        "role_permissions": {
            "user": ["lookup_order", "get_refund_status"],
            "support": ["lookup_order", "cancel_order", "get_refund_status"],
            "admin": ["lookup_order", "cancel_order", "get_refund_status"],
        },
    }
    resp = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=payload)
    print(f"[register] {resp.status_code}: {resp.json()}")


# ---------------------------------------------------------------------------
# 2. Define tools (OpenAI function calling format)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_order",
            "description": "Look up order details by order ID",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "The order ID"},
                },
                "required": ["order_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cancel_order",
            "description": "Cancel an existing order",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "The order ID"},
                    "reason": {"type": "string", "description": "Cancellation reason"},
                },
                "required": ["order_id", "reason"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_refund_status",
            "description": "Check refund status for an order",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "The order ID"},
                },
                "required": ["order_id"],
                "additionalProperties": False,
            },
        },
    },
]


# ---------------------------------------------------------------------------
# 3. Local tool execution stubs
# ---------------------------------------------------------------------------

def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Simulate tool execution locally."""
    if name == "lookup_order":
        return f"Order {args['order_id']}: 2x Widget Pro, shipped via FedEx, ETA 2 days."
    if name == "cancel_order":
        return f"Order {args['order_id']} cancelled. Reason: {args['reason']}"
    if name == "get_refund_status":
        return f"Refund for {args['order_id']}: processed, arriving in 3-5 business days."
    return f"Unknown tool: {name}"


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
    chat_resp = shield.post(
        f"{SHIELD_URL}/v1/shield/chat/agent",
        json={
            "messages": [{"role": "user", "content": user_message}],
            "agent_key": AGENT_ID,
            "user_role": USER_ROLE,
            "llm_api_key": os.getenv("OPENAI_API_KEY"),
            "llm_model": LLM_MODEL,
            "tools": TOOLS,
        },
    )
    if chat_resp.status_code != 200:
        err = chat_resp.text
        print(f"[Shield chat error] {chat_resp.status_code}: {err}")
        return f"Error: {err}"

    result = chat_resp.json()

    # -- Step 3: execute allowed tool calls --------------------------------
    output_parts = []
    for tc in result.get("tool_calls", []):
        name = tc["tool_name"]
        args = tc.get("arguments", {})
        rbac = tc.get("rbac", {})

        if rbac.get("allowed"):
            out = execute_tool(name, args)
            print(f"  [ALLOWED] {name}({json.dumps(args)}) -> {out}")
            output_parts.append(out)
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
# 5. Direct OpenAI loop (without Shield chat endpoint)
# ---------------------------------------------------------------------------

def run_agent_direct(user_message: str) -> str:
    """Alternative flow: call OpenAI directly, then validate with Shield.

    Use this pattern when you want full control over the OpenAI call
    and only use Shield for guardrails + RBAC checking.
    """
    print(f"\n{'='*60}")
    print(f"[direct] User: {user_message}")
    print(f"{'='*60}")

    # Input guardrails
    gin = shield.post(
        f"{SHIELD_URL}/guardrails/input",
        json={"message": user_message},
    ).json()
    if gin.get("action") == "block":
        return "[Blocked by input guardrails]"

    # Call OpenAI directly
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": "You are a helpful support agent."},
            {"role": "user", "content": user_message},
        ],
        tools=TOOLS,
        tool_choice="auto",
    )
    msg = response.choices[0].message

    if msg.tool_calls:
        # Send to Shield for RBAC validation
        result = shield.post(
            f"{SHIELD_URL}/v1/shield/chat/agent",
            json={
                "messages": [{"role": "user", "content": user_message}],
                "agent_key": AGENT_ID,
                "user_role": USER_ROLE,
                "llm_api_key": os.getenv("OPENAI_API_KEY"),
                "tools": TOOLS,
            },
        ).json()

        for tc in result.get("tool_calls", []):
            if tc["rbac"]["allowed"]:
                out = execute_tool(tc["tool_name"], tc.get("arguments", {}))
                print(f"  [ALLOWED] {tc['tool_name']} -> {out}")
            else:
                print(f"  [BLOCKED] {tc['tool_name']}: {tc['rbac']['message']}")

        return result.get("text", "")

    # Plain text response — output guardrails
    if msg.content:
        gout = shield.post(
            f"{SHIELD_URL}/guardrails/output",
            json={"output": msg.content},
        ).json()
        if gout.get("action") == "block":
            return "[Response blocked by output policy]"
        return msg.content

    return ""


# ---------------------------------------------------------------------------
# 6. Shadow discovery check
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

    # --- Shield-managed flow (recommended) ---
    run_agent("What's the status of order ORD-12345?")
    run_agent("Cancel order ORD-12345, I changed my mind")
    run_agent("Check refund for ORD-12345")

    # --- Direct OpenAI flow (alternative) ---
    # run_agent_direct("What's the status of order ORD-12345?")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
