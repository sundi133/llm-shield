#!/usr/bin/env python3
"""LangChain + LLM Shield — End-to-End Integration with Full Token Chain

Three things a developer does, and only the first is one-time:

  1. ONE-TIME:    Register your agent + Keycloak issuer URL.
  2. PER-PROCESS: Mint a short-lived agent token (~10 min, cache it).
  3. PER-ACTION:  Before each real tool call, check RBAC + mint a capability.

That's it. Three calls total, and this file shows all three.

Architecture:
  ┌─────────────┐     ┌─────────────┐     ┌──────────────┐
  │  Your Agent  │────▶│  LiteLLM    │────▶│   LLM (GPU)  │
  │  (LangChain) │     │  Proxy      │     └──────────────┘
  └──────┬───────┘     └─────────────┘
         │                input/output guardrails
         │                (automatic, you don't call these)
         │
         │  ┌──────────────────────────────────────────┐
         └──▶  LLM Shield                              │
              │  POST /v1/agents/registry       (1)    │
              │  POST /v1/tenant/me/agent-auth/         │
              │        agent-token              (2)    │
              │  POST /v1/shield/tool/check     (3a)   │
              │  POST /v1/shield/cap/mint       (3b)   │
              │  POST /v1/shield/tool/output    (3c)   │
              └────────────────────────────────────────┘

Usage:
    # Required
    export LLM_SHIELD_URL="https://shield.votal.ai"
    export API_KEY="tenant-abc123-key-xyz789"
    export OPENAI_API_KEY="sk-..."

    # Optional (have sane defaults)
    export LITELLM_URL="https://litellm.your-company.com"
    export AGENT_ID="langchain-support-agent"
    export USER_ROLE="user"

    pip install -r requirements.txt
    python langchain_e2e.py
"""

import json
import os
import time
import uuid

import requests
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain_core.messages import HumanMessage, ToolMessage

# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "https://shield.votal.ai")
API_KEY = os.getenv("API_KEY", "")
LITELLM_URL = os.getenv("LITELLM_URL", "https://litellm.your-company.com")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "langchain-support-agent")
USER_ROLE = os.getenv("USER_ROLE", "user")
MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

# Keycloak user identity (in production, comes from your IdP login)
USER_SUB = os.getenv("USER_SUB", "user-001")

# Build identity (in production, comes from your CI/CD pipeline)
BUILD_HASH = os.getenv("BUILD_HASH", "abc123")
MODEL_VERSION = os.getenv("MODEL_VERSION", MODEL)

# Unique per-process — identifies this running instance
AGENT_INSTANCE_ID = f"{AGENT_ID}-{uuid.uuid4().hex[:8]}"
SESSION_ID = f"sess-{int(time.time())}"

# Reusable HTTP session for Shield calls
shield_session = requests.Session()
shield_session.headers.update({
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_ID,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
})


# ──────────────────────────────────────────────────────────────────────────
# STEP 1: Register agent (ONE-TIME)
#
# Do this once — from your deploy script, CI/CD, or first boot.
# If you skip it, Shield tracks the agent as a "shadow agent" and
# every tool call is treated as unregistered.
# ──────────────────────────────────────────────────────────────────────────

def register_agent():
    """Register agent + role-based tool permissions. Idempotent — safe to re-run."""
    resp = shield_session.post(f"{SHIELD_URL}/v1/agents/registry", json={
        "agent_id": AGENT_ID,
        "name": "LangChain Support Agent",
        "description": "Customer support agent built with LangChain",
        "tools": ["search_faq", "create_ticket", "check_order_status"],
        "role_permissions": {
            # user role: can search and check orders, but NOT create tickets
            "user": ["search_faq", "check_order_status"],
            # support role: can do everything
            "support": ["search_faq", "create_ticket", "check_order_status"],
            # admin role: full access
            "admin": ["search_faq", "create_ticket", "check_order_status"],
        },
    })
    print(f"[Step 1 - Register] {resp.status_code}: {resp.json()}")
    return resp.json()


# ──────────────────────────────────────────────────────────────────────────
# STEP 2: Mint agent token (PER-PROCESS)
#
# Your agent already logged the user into Keycloak. Take that identity
# and call Shield once to mint a short-lived agent token (~10 min).
# Cache it for the lifetime of this process.
# ──────────────────────────────────────────────────────────────────────────

_cached_agent_token: dict | None = None


def get_agent_token() -> str:
    """Mint (or return cached) agent token. Call once per process start."""
    global _cached_agent_token

    # Return cached token if still valid (with 60s buffer)
    if _cached_agent_token:
        if _cached_agent_token["expires_at"] > time.time() + 60:
            return _cached_agent_token["token"]

    resp = shield_session.post(
        f"{SHIELD_URL}/v1/tenant/me/agent-auth/agent-token",
        json={
            "user_sub": USER_SUB,                     # from Keycloak login
            "agent_id": AGENT_ID,                     # logical agent name
            "agent_instance_id": AGENT_INSTANCE_ID,   # unique per process
            "build_hash": BUILD_HASH,                 # from CI/CD
            "model_version": MODEL_VERSION,           # LLM version
            "session_id": SESSION_ID,                 # conversation id
            "ttl_seconds": 600,                       # 10 minutes
        },
    )

    if resp.status_code != 200:
        print(f"[Step 2 - Agent Token] FAILED {resp.status_code}: {resp.text}")
        raise RuntimeError(f"Failed to mint agent token: {resp.text}")

    data = resp.json()
    _cached_agent_token = {
        "token": data["agent_token"],
        "expires_at": time.time() + data["expires_in"],
    }
    print(f"[Step 2 - Agent Token] Minted, expires in {data['expires_in']}s")
    return data["agent_token"]


# ──────────────────────────────────────────────────────────────────────────
# STEP 3: Per-action — RBAC check + capability mint + output sanitize
#
# Right before the agent does something real (search, create ticket, etc.),
# ask Shield to authorize it. Three sub-calls per tool action:
#   3a. tool/check  — RBAC: is this role allowed to use this tool?
#   3b. cap/mint    — Capability: mint a single-use token for the action
#   3c. tool/output — Sanitize: redact PII / enforce data policy on output
# ──────────────────────────────────────────────────────────────────────────

def shield_check_and_mint(tool_name: str, tool_args: dict, resource: str = "") -> dict:
    """Step 3a + 3b: RBAC check, then mint a capability token if allowed.

    Returns {"allowed": bool, "reason": str, "cap_token": str | None}.
    """
    # 3a — RBAC check (uses tenant API key)
    check_resp = shield_session.post(f"{SHIELD_URL}/v1/shield/tool/check", json={
        "agent_key": AGENT_ID,
        "tool_name": tool_name,
        "tool_params": tool_args,
        "user_role": USER_ROLE,
        "session_id": SESSION_ID,
    })

    if check_resp.status_code != 200:
        return {"allowed": False, "reason": f"Shield error {check_resp.status_code}", "cap_token": None}

    check = check_resp.json()
    allowed = check.get("allowed", True) and check.get("action") != "block"

    if not allowed:
        reason = "denied by policy"
        for r in check.get("guardrail_results", []):
            if not r.get("passed", True):
                reason = r.get("message", reason)
                break
        return {"allowed": False, "reason": reason, "cap_token": None}

    # 3b — Mint capability token (uses agent token)
    agent_token = get_agent_token()
    cap_resp = requests.post(
        f"{SHIELD_URL}/v1/shield/cap/mint",
        headers={
            "X-API-Key": API_KEY,
            "X-Agent-Token": agent_token,
            "Content-Type": "application/json",
        },
        json={
            "tool": tool_name,
            "resource": resource or f"{tool_name}/{json.dumps(tool_args, sort_keys=True)[:80]}",
            "clearance_max": "public",
            "ttl_seconds": 30,
        },
    )

    cap_token = None
    if cap_resp.status_code == 200:
        cap_data = cap_resp.json()
        cap_token = cap_data.get("cap_token")
        print(f"    [Cap] Minted for {tool_name}, expires in {cap_data.get('expires_in')}s")
    elif cap_resp.status_code == 403:
        # Capability denied — still report why
        return {"allowed": False, "reason": cap_resp.json().get("detail", "cap denied"), "cap_token": None}
    else:
        # Cap minting failed but RBAC passed — proceed without cap
        # (tools that don't verify caps still work)
        print(f"    [Cap] Minting skipped ({cap_resp.status_code}) — tool will run without cap")

    return {"allowed": True, "reason": "", "cap_token": cap_token}


def shield_sanitize_output(tool_name: str, raw_output: str) -> str:
    """Step 3c: Sanitize tool output (mask PII, redact sensitive data)."""
    resp = shield_session.post(f"{SHIELD_URL}/v1/shield/tool/output", json={
        "tool_name": tool_name,
        "tool_output": raw_output,
        "agent_key": AGENT_ID,
        "session_id": SESSION_ID,
    })
    if resp.status_code != 200:
        return raw_output  # fail open on sanitization errors

    data = resp.json()
    if data.get("action") == "block":
        return "[OUTPUT BLOCKED BY DATA POLICY]"
    return data.get("sanitized_output", raw_output)


# ──────────────────────────────────────────────────────────────────────────
# LangChain tools — each wrapped with Shield protection
# ──────────────────────────────────────────────────────────────────────────

def shielded(tool_name: str, args: dict, execute_fn):
    """Wrap any tool: Shield RBAC → execute → Shield sanitize."""
    # Step 3a + 3b: check RBAC and mint capability
    result = shield_check_and_mint(tool_name, args)
    if not result["allowed"]:
        print(f"    [BLOCKED] {tool_name}: {result['reason']}")
        return f"BLOCKED by Shield: {result['reason']}"

    print(f"    [ALLOWED] {tool_name}")

    # Execute the actual tool
    raw_output = execute_fn()

    # Step 3c: sanitize output
    return shield_sanitize_output(tool_name, raw_output)


@tool
def search_faq(query: str) -> str:
    """Search the FAQ knowledge base for answers."""
    return shielded(
        "search_faq", {"query": query},
        lambda: f"FAQ: Our return policy allows returns within 30 days of purchase. "
                f"Contact support@example.com or call +1-555-0199 for help.",
    )


@tool
def create_ticket(subject: str, description: str) -> str:
    """Create a support ticket for the customer."""
    return shielded(
        "create_ticket", {"subject": subject, "description": description},
        lambda: json.dumps({
            "ticket_id": f"TKT-{abs(hash(subject)) % 100_000}",
            "subject": subject,
            "status": "open",
        }),
    )


@tool
def check_order_status(order_id: str) -> str:
    """Check the current status of a customer order."""
    return shielded(
        "check_order_status", {"order_id": order_id},
        lambda: json.dumps({
            "order_id": order_id,
            "status": "shipped",
            "eta": "2 business days",
            "tracking": "1Z999AA10123456784",
        }),
    )


TOOLS = [search_faq, create_ticket, check_order_status]


# ──────────────────────────────────────────────────────────────────────────
# Agent loop
# ──────────────────────────────────────────────────────────────────────────

def run_agent(user_message: str) -> str:
    """Run one turn through the full architecture."""
    print(f"\n{'=' * 60}")
    print(f"User: {user_message}")
    print(f"Role: {USER_ROLE} | Agent: {AGENT_ID}")
    print(f"{'=' * 60}")

    llm = ChatOpenAI(
        model=MODEL,
        base_url=f"{LITELLM_URL}/v1",
        api_key=OPENAI_API_KEY,
        default_headers={
            "X-API-Key": API_KEY,
            "X-Agent-Key": AGENT_ID,
            "X-User-Role": USER_ROLE,
        },
    )

    llm_with_tools = llm.bind_tools(TOOLS)

    messages = [HumanMessage(content=user_message)]
    try:
        response = llm_with_tools.invoke(messages)
    except Exception as e:
        return f"[BLOCKED by input guardrails] {e}"

    # No tool calls — return text directly
    if not response.tool_calls:
        print(f"  Response: {response.content}")
        return response.content

    # Process tool calls through Shield
    messages.append(response)
    tool_map = {t.name: t for t in TOOLS}

    for tc in response.tool_calls:
        name, args, tc_id = tc["name"], tc["args"], tc["id"]

        fn = tool_map.get(name)
        if not fn:
            messages.append(ToolMessage(content=f"Unknown tool: {name}", tool_call_id=tc_id))
            continue

        # Tool execution includes Shield checks (via shielded() wrapper)
        result = fn.invoke(args)
        messages.append(ToolMessage(content=str(result), tool_call_id=tc_id))

    # Final LLM call with tool results
    try:
        final = llm_with_tools.invoke(messages)
        print(f"  Response: {final.content}")
        return final.content
    except Exception as e:
        return f"[Output blocked] {e}"


# ──────────────────────────────────────────────────────────────────────────
# Main — run the demo scenarios
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not API_KEY:
        print("ERROR: Set API_KEY (your tenant API key from the Shield portal)")
        print("  export API_KEY='tenant-abc123-key-xyz789'")
        exit(1)

    print("LLM Shield — LangChain E2E Demo")
    print(f"  Shield:   {SHIELD_URL}")
    print(f"  LiteLLM:  {LITELLM_URL}")
    print(f"  Agent:    {AGENT_ID} (instance: {AGENT_INSTANCE_ID})")
    print(f"  User:     {USER_SUB} (role: {USER_ROLE})")
    print()

    # ── Step 1: Register agent (one-time, idempotent) ──
    print("=" * 60)
    print("STEP 1: Register agent (one-time)")
    print("=" * 60)
    register_agent()

    # ── Step 2: Mint agent token (per-process, cached) ──
    print()
    print("=" * 60)
    print("STEP 2: Mint agent token (per-process)")
    print("=" * 60)
    get_agent_token()

    # ── Step 3: Run agent — each tool call goes through Shield ──
    print()
    print("=" * 60)
    print("STEP 3: Run agent (per-action Shield checks)")
    print("=" * 60)

    # Scenario A: Allowed — user can search FAQ
    run_agent("What is your return policy?")

    # Scenario B: Allowed — user can check orders
    run_agent("Check status of order ORD-12345")

    # Scenario C: BLOCKED — user role can't create tickets (only support/admin can)
    run_agent("Create a ticket: billing issue on my last invoice")
