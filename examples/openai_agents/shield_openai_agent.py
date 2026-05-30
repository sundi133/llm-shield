#!/usr/bin/env python3
"""OpenAI + LLM Shield Integration (production deployment architecture).

Two planes, matching the deployment architecture:

  PLANE 1 — LLM + GUARDRAILS  →  LiteLLM proxy
      The OpenAI client points at the LiteLLM proxy whose config.yaml has the
      votal.ai guardrails callback configured. Input (PreCall) and output
      (PostCall) guardrails run *inside* the proxy — the app never calls
      /guardrails/input or /guardrails/output directly. A blocked prompt or
      response comes back as an API error, never reaching/leaving the LLM.

  PLANE 2 — AGENTS + RBAC  →  LLM Shield
      Agent registration, role-based tool authorization and per-tool data
      policy enforcement go through the Shield endpoints (NOT LiteLLM):
        /v1/agents/registry     register agent + role_permissions
        /v1/shield/tool/check    pre-exec: RBAC + input data policy
        /v1/shield/tool/output   post-exec: output sanitization/redaction
        /v1/agents/unregistered  shadow discovery

Flow per user message:

    User ─▶ OpenAI tool-calling loop (LLM via LiteLLM proxy ─▶ guardrails)
              └─ tool call ─▶ Shield /v1/shield/tool/check  (RBAC + data policy)
                               ├─ allowed ▶ run tool ▶ Shield /tool/output (sanitize)
                               └─ blocked ▶ deny, reason fed back to the model

Usage:
    # Plane 1 — LiteLLM proxy (guardrails configured in its config.yaml)
    export LITELLM_URL="http://localhost:4000"
    export LITELLM_API_KEY="sk-litellm-..."     # LiteLLM virtual key
    export LLM_MODEL="gpt-4o-mini"             # model alias in litellm config

    # Plane 2 — LLM Shield (agents + RBAC)
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export AGENT_ID="openai-support-agent"     # optional
    export USER_ROLE="user"                    # user / support / admin

    pip install -r requirements.txt
    python shield_openai_agent.py
"""

import json
import os
import time
from typing import Any

import requests
from openai import OpenAI

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
AGENT_ID = os.getenv("AGENT_ID", "openai-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
SESSION_ID = f"sess-{int(time.time())}"

# OpenAI client → LiteLLM proxy (so guardrails run in the proxy)
client = OpenAI(base_url=f"{LITELLM_URL}/v1", api_key=LITELLM_API_KEY)

# Shield session — agent identity + role on every Shield request
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
    """Register the agent and its role-based tool permissions with Shield."""
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
# 2. Tools (OpenAI function-calling format)
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


def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Simulate the real tool work locally."""
    if name == "lookup_order":
        return f"Order {args['order_id']}: 2x Widget Pro, shipped via FedEx, ETA 2 days."
    if name == "cancel_order":
        return f"Order {args['order_id']} cancelled. Reason: {args['reason']}"
    if name == "get_refund_status":
        return f"Refund for {args['order_id']}: processed, arriving in 3-5 business days."
    return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# 3. Shield tool gate — RBAC + data policy around every tool execution
# ---------------------------------------------------------------------------

class ToolBlocked(Exception):
    """Raised when Shield denies a tool call; message is fed back to the model."""


def _shield_tool_check(tool_name: str, args: dict) -> None:
    """Pre-execution gate: RBAC + input data-policy via Shield /tool/check."""
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
        raise ToolBlocked(f"tool/check failed ({resp.status_code}): {resp.text}")
    data = resp.json()
    if not (data.get("allowed", True) and data.get("action") != "block"):
        reason = "denied by policy"
        for r in data.get("guardrail_results", []):
            if not r.get("passed", True):
                reason = r.get("message", reason)
                break
        raise ToolBlocked(f"{tool_name} blocked for role '{USER_ROLE}' — {reason}")


def _shield_tool_output(tool_name: str, raw_output: str) -> str:
    """Post-execution gate: sanitize/redact tool output via Shield /tool/output."""
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
        raise ToolBlocked(f"{tool_name} output withheld (sanitizer error)")
    data = resp.json()
    if data.get("action") == "block":
        raise ToolBlocked(f"{tool_name} output blocked by data policy")
    return data.get("sanitized_output", str(raw_output))


def shielded(tool_name: str, args: dict) -> str:
    """Shield RBAC pre-check → execute → Shield output check. Returns a string
    the model can read (including a denial reason if blocked)."""
    try:
        _shield_tool_check(tool_name, args)
        raw = execute_tool(tool_name, args)
        out = _shield_tool_output(tool_name, raw)
        print(f"  [ALLOWED] {tool_name}({json.dumps(args)}) -> {out}")
        return out
    except ToolBlocked as e:
        print(f"  [Shield] BLOCKED {tool_name}: {e}")
        return f"BLOCKED by LLM Shield: {e}"


# ---------------------------------------------------------------------------
# 4. Agent loop — LLM through LiteLLM proxy, tools gated by Shield
# ---------------------------------------------------------------------------

def run_agent(user_message: str, max_turns: int = 5) -> str:
    """Run a tool-calling loop. The LLM (and its input/output guardrails) go
    through the LiteLLM proxy; tool calls are gated by Shield."""
    print(f"\n{'=' * 60}")
    print(f"User: {user_message}")
    print(f"{'=' * 60}")

    messages: list[dict] = [
        {"role": "system", "content": "You are a helpful order-support agent. "
         "Use the tools to help the user. If a tool is blocked by policy, "
         "explain that you are not authorized to perform that action."},
        {"role": "user", "content": user_message},
    ]

    for _ in range(max_turns):
        try:
            resp = client.chat.completions.create(
                model=LLM_MODEL, messages=messages, tools=TOOLS, tool_choice="auto",
            )
        except Exception as e:  # noqa: BLE001 — surface proxy-side guardrail blocks
            msg = str(e)
            if any(k in msg.lower() for k in ("guardrail", "blocked", "403", "policy")):
                print(f"[BLOCKED by LiteLLM proxy guardrails] {msg}")
                return "[Request blocked by guardrails in the LiteLLM proxy]"
            print(f"[Agent error] {msg}")
            return f"Error: {msg}"

        choice = resp.choices[0].message
        if not choice.tool_calls:
            print(f"Response: {choice.content}")
            return choice.content or ""

        messages.append(choice)
        for tc in choice.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}")
            result = shielded(name, args)
            messages.append({
                "role": "tool", "tool_call_id": tc.id, "content": result,
            })

    return "[Stopped: max turns reached]"


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

    run_agent("What's the status of order ORD-12345?")
    run_agent("Cancel order ORD-12345, I changed my mind")
    run_agent("Check refund for ORD-12345")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
