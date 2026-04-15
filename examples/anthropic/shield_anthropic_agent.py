#!/usr/bin/env python3
"""Anthropic Claude + LLM Shield Integration

Demonstrates a Claude tool-use agent protected by LLM Shield:
  - Agent registration with role-based tool permissions
  - Input guardrails (adversarial, toxicity, PII) before Claude call
  - Claude generates tool_use blocks → Shield enforces RBAC
  - Output guardrails on text blocks
  - Shadow discovery for unregistered agents/tools

Note: Shield's /v1/shield/chat/agent uses OpenAI-format tools internally,
so we convert Claude tool definitions before sending to Shield.

Usage:
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export ANTHROPIC_API_KEY="sk-ant-..."
    export OPENAI_API_KEY="sk-..."         # needed for Shield's LLM
    export AGENT_ID="my-claude-agent"      # optional
    export USER_ROLE="user"                # optional

    pip install -r requirements.txt
    python shield_anthropic_agent.py
"""

import json
import os
import sys
from typing import Any

import anthropic
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "claude-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

claude = anthropic.Anthropic()

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
        "name": "Claude Support Agent",
        "description": "Customer support agent built with Anthropic Claude",
        "tools": [
            "search_knowledge_base",
            "create_ticket",
            "escalate_to_human",
        ],
        "role_permissions": {
            "user": ["search_knowledge_base"],
            "support": ["search_knowledge_base", "create_ticket"],
            "admin": [
                "search_knowledge_base",
                "create_ticket",
                "escalate_to_human",
            ],
        },
    }
    resp = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=payload)
    print(f"[register] {resp.status_code}: {resp.json()}")


# ---------------------------------------------------------------------------
# 2. Define tools (Anthropic format)
# ---------------------------------------------------------------------------

CLAUDE_TOOLS = [
    {
        "name": "search_knowledge_base",
        "description": "Search the support knowledge base for answers",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to search for",
                },
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
                "description": {
                    "type": "string",
                    "description": "Ticket description",
                },
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
                "reason": {
                    "type": "string",
                    "description": "Why escalation is needed",
                },
            },
            "required": ["reason"],
        },
    },
]


# ---------------------------------------------------------------------------
# 3. Local tool execution stubs
# ---------------------------------------------------------------------------

def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Simulate tool execution locally."""
    if name == "search_knowledge_base":
        return f"KB result for '{args['query']}': See article #42 at /help/42"
    if name == "create_ticket":
        tid = abs(hash(args["subject"])) % 100_000
        return f"Ticket TKT-{tid} created ({args['priority']}): {args['subject']}"
    if name == "escalate_to_human":
        return f"Escalated to human agent. Reason: {args['reason']}"
    return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# 4. Convert Claude tools to OpenAI format (for Shield)
# ---------------------------------------------------------------------------

def claude_tools_to_openai(tools: list[dict]) -> list[dict]:
    """Convert Anthropic tool definitions to OpenAI function-calling format.

    Shield expects OpenAI-format tools for its /v1/shield/chat/agent endpoint.
    """
    openai_tools = []
    for t in tools:
        schema = t["input_schema"].copy()
        schema["additionalProperties"] = False
        openai_tools.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "strict": True,
                "parameters": schema,
            },
        })
    return openai_tools


# ---------------------------------------------------------------------------
# 5. Shield-wrapped Claude agent
# ---------------------------------------------------------------------------

def run_agent(user_message: str) -> str:
    """Send a message through the full Shield + Claude pipeline.

    Flow:
        1. /guardrails/input    — block toxic / adversarial / PII input
        2. Claude API           — LLM decides which tools to use
        3. /v1/shield/chat/agent — RBAC enforcement on tool calls
        4. Execute allowed tools locally
        5. /guardrails/output   — block competitors / PII in output
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

    # -- Step 2: call Claude -----------------------------------------------
    response = claude.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=1024,
        system="You are a helpful support agent. Use tools when needed.",
        messages=[{"role": "user", "content": user_message}],
        tools=CLAUDE_TOOLS,
    )

    # -- Step 3: process response blocks -----------------------------------
    results = []
    tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
    text_blocks = [b for b in response.content if b.type == "text"]

    # Process text blocks through output guardrails
    for block in text_blocks:
        guard_out = shield.post(
            f"{SHIELD_URL}/guardrails/output",
            json={"output": block.text},
        )
        if guard_out.status_code == 200 and guard_out.json().get("action") == "block":
            results.append("[Text blocked by output policy]")
            print("  [BLOCKED] text block by output guardrails")
        else:
            results.append(block.text)
            print(f"  [text] {block.text[:80]}...")

    # Process tool_use blocks through Shield RBAC
    if tool_use_blocks:
        openai_tools = claude_tools_to_openai(CLAUDE_TOOLS)

        chat_resp = shield.post(
            f"{SHIELD_URL}/v1/shield/chat/agent",
            json={
                "messages": [
                    {"role": "system", "content": "You are a support agent."},
                    {"role": "user", "content": user_message},
                ],
                "agent_key": AGENT_ID,
                "user_role": USER_ROLE,
                "llm_api_key": os.getenv("OPENAI_API_KEY"),
                "tools": openai_tools,
            },
        )

        if chat_resp.status_code == 200:
            shield_result = chat_resp.json()

            for tc in shield_result.get("tool_calls", []):
                name = tc["tool_name"]
                args = tc.get("arguments", {})
                rbac = tc.get("rbac", {})

                if rbac.get("allowed"):
                    out = execute_tool(name, args)
                    print(f"  [ALLOWED] {name}({json.dumps(args)}) -> {out}")
                    results.append(out)
                else:
                    msg = f"BLOCKED: {name} — {rbac.get('message', 'denied')}"
                    print(f"  [BLOCKED] {name}: {rbac.get('message')}")
                    results.append(msg)

            # Shadow discovery feedback
            unreg = shield_result.get("unregistered", {})
            if unreg.get("agents"):
                print(f"  [SHADOW] Unregistered agent(s): {unreg['agents']}")
            if unreg.get("tools"):
                print(f"  [SHADOW] Unregistered tool(s): {unreg['tools']}")
        else:
            print(f"  [Shield error] {chat_resp.status_code}: {chat_resp.text}")
            # Fallback: execute Claude's tool calls without RBAC
            for block in tool_use_blocks:
                out = execute_tool(block.name, block.input)
                results.append(f"[unprotected] {out}")

    final = "\n".join(results)
    print(f"Response: {final}")
    return final


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
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set")
        sys.exit(1)
    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set (needed for Shield's LLM)")
        sys.exit(1)
    if not API_KEY:
        print("WARNING: API_KEY not set — requests may be rejected")

    # Uncomment to register the agent (skip to test shadow discovery):
    # register_agent()

    run_agent("How do I reset my password?")
    run_agent("Create a ticket: billing error on my account")
    run_agent("I need to speak to a manager right now")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
