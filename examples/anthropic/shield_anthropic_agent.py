#!/usr/bin/env python3
"""Anthropic Claude + LLM Shield Integration (production deployment architecture).

Two planes, matching the deployment architecture:

  PLANE 1 — LLM + GUARDRAILS  →  LiteLLM proxy
      The Anthropic client points at the LiteLLM proxy whose config.yaml has
      the votal.ai guardrails callback configured. Input (PreCall) and output
      (PostCall) guardrails run *inside* the proxy — the app never calls
      /guardrails/input or /guardrails/output directly. The proxy exposes an
      Anthropic-compatible /v1/messages endpoint, so the standard Anthropic
      SDK works unchanged apart from base_url.

  PLANE 2 — AGENTS + RBAC  →  LLM Shield
      Agent registration, role-based tool authorization and per-tool data
      policy enforcement go through the Shield endpoints (NOT LiteLLM):
        /v1/agents/registry     register agent + role_permissions
        /v1/shield/tool/check    pre-exec: RBAC + input data policy
        /v1/shield/tool/output   post-exec: output sanitization/redaction
        /v1/agents/unregistered  shadow discovery

Flow per user message:

    User ─▶ Claude tool-use loop (LLM via LiteLLM proxy ─▶ guardrails)
              └─ tool_use ─▶ Shield /v1/shield/tool/check  (RBAC + data policy)
                              ├─ allowed ▶ run tool ▶ Shield /tool/output (sanitize)
                              └─ blocked ▶ deny, reason fed back as tool_result

Usage:
    # Plane 1 — LiteLLM proxy (guardrails configured in its config.yaml)
    export LITELLM_URL="http://localhost:4000"
    export LITELLM_API_KEY="sk-litellm-..."     # LiteLLM virtual key
    export CLAUDE_MODEL="claude-sonnet-4-20250514"

    # Plane 2 — LLM Shield (agents + RBAC)
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export AGENT_ID="claude-support-agent"     # optional
    export USER_ROLE="user"                    # user / support / admin

    pip install -r requirements.txt
    python shield_anthropic_agent.py
"""

import json
import os
import time
from typing import Any

import anthropic
import requests

# ---------------------------------------------------------------------------
# Config — TWO separate planes
# ---------------------------------------------------------------------------

# Plane 1: LiteLLM proxy (guardrails run inside it via the votal.ai callback)
LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000").rstrip("/")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", os.getenv("ANTHROPIC_API_KEY", "sk-noop"))
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

# Plane 2: LLM Shield (agents + RBAC + data policy)
SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080").rstrip("/")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "claude-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
SESSION_ID = f"sess-{int(time.time())}"

# Anthropic client → LiteLLM proxy (so guardrails run in the proxy)
claude = anthropic.Anthropic(base_url=LITELLM_URL, api_key=LITELLM_API_KEY)

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
        "name": "Claude Support Agent",
        "description": "Customer support agent built with Anthropic Claude",
        "tools": ["search_knowledge_base", "create_ticket", "escalate_to_human"],
        "role_permissions": {
            "user": ["search_knowledge_base"],
            "support": ["search_knowledge_base", "create_ticket"],
            "admin": ["search_knowledge_base", "create_ticket", "escalate_to_human"],
        },
    }
    resp = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=payload)
    print(f"[register] {resp.status_code}: {resp.json()}")


# ---------------------------------------------------------------------------
# 2. Tools (Anthropic format)
# ---------------------------------------------------------------------------

CLAUDE_TOOLS = [
    {
        "name": "search_knowledge_base",
        "description": "Search the support knowledge base for answers",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to search for"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "create_ticket",
        "description": "Create a support ticket",
        "input_schema": {
            "type": "object",
            "properties": {
                "subject": {"type": "string", "description": "Ticket subject"},
                "description": {"type": "string", "description": "Ticket description"},
                "priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Ticket priority",
                },
            },
            "required": ["subject", "description", "priority"],
        },
    },
    {
        "name": "escalate_to_human",
        "description": "Escalate the conversation to a human agent",
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Why escalation is needed"},
            },
            "required": ["reason"],
        },
    },
]


def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Simulate the real tool work locally."""
    if name == "search_knowledge_base":
        return f"KB result for '{args['query']}': See article #42 at /help/42"
    if name == "create_ticket":
        tid = abs(hash(args["subject"])) % 100_000
        return f"Ticket TKT-{tid} created ({args['priority']}): {args['subject']}"
    if name == "escalate_to_human":
        return f"Escalated to human agent. Reason: {args['reason']}"
    return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# 3. Shield tool gate — RBAC + data policy around every tool execution
# ---------------------------------------------------------------------------

class ToolBlocked(Exception):
    """Raised when Shield denies a tool call; message returned as tool_result."""


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
    for the tool_result (including a denial reason if blocked)."""
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
# 4. Claude tool-use loop — LLM through LiteLLM proxy, tools gated by Shield
# ---------------------------------------------------------------------------

def run_agent(user_message: str, max_turns: int = 5) -> str:
    """Run a Claude tool-use loop. The LLM (and its input/output guardrails) go
    through the LiteLLM proxy; tool calls are gated by Shield."""
    print(f"\n{'=' * 60}")
    print(f"User: {user_message}")
    print(f"{'=' * 60}")

    messages: list[dict] = [{"role": "user", "content": user_message}]

    for _ in range(max_turns):
        try:
            resp = claude.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=1024,
                system="You are a helpful support agent. Use tools when needed. "
                       "If a tool is blocked by policy, explain that you are not "
                       "authorized to perform that action.",
                messages=messages,
                tools=CLAUDE_TOOLS,
            )
        except Exception as e:  # noqa: BLE001 — surface proxy-side guardrail blocks
            msg = str(e)
            if any(k in msg.lower() for k in ("guardrail", "blocked", "403", "policy")):
                print(f"[BLOCKED by LiteLLM proxy guardrails] {msg}")
                return "[Request blocked by guardrails in the LiteLLM proxy]"
            print(f"[Agent error] {msg}")
            return f"Error: {msg}"

        text = "".join(b.text for b in resp.content if b.type == "text")
        if text:
            print(f"  [text] {text[:80]}")

        if resp.stop_reason != "tool_use":
            print(f"Response: {text}")
            return text

        # Echo the assistant turn, then answer each tool_use with a Shield-gated result
        messages.append({"role": "assistant", "content": resp.content})
        tool_results = []
        for block in resp.content:
            if block.type == "tool_use":
                result = shielded(block.name, dict(block.input))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
        messages.append({"role": "user", "content": tool_results})

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
    print(f"LLM plane  : LiteLLM proxy at {LITELLM_URL} (model={CLAUDE_MODEL})")
    print(f"Agent plane: LLM Shield at {SHIELD_URL} (agent={AGENT_ID}, role={USER_ROLE})")

    # Uncomment on first run to register the agent (skip to test shadow discovery):
    # register_agent()

    run_agent("How do I reset my password?")
    run_agent("Create a ticket: billing error on my account")
    run_agent("I need to speak to a manager right now")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
