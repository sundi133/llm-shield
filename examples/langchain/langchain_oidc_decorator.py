#!/usr/bin/env python3
"""LangChain + OIDC + Shield Decorator — the simplest integration.

This is what a developer actually writes. Compare with test_local_oidc.py
which tests the raw API — this file shows the SDK decorator approach.

Three ways to protect tools:

  1. @shield.protect decorator  — one line per tool (recommended)
  2. shield.wrap_tools([...])   — wrap existing tools in bulk
  3. shield.tool_guard() context manager — manual control

Usage:
    # Keycloak running locally (from docker-compose.local.yml)
    # Shield on RunPod or local

    export LLM_SHIELD_URL=https://xxx.api.runpod.ai
    export API_KEY="bank-co-key"
    export RUNPOD_TOKEN="rpa_..."        # only for RunPod
    export OPENAI_API_KEY="sk-..."

    # User identity from Keycloak login
    export USER_ROLE="branch_manager"    # from realm_access.roles
    export USER_SUB="583f23c5-..."       # from id_token sub claim

    python langchain_oidc_decorator.py
"""

import json
import os
import sys
import time
import uuid

# Force UTF-8 console output — Windows defaults to cp1252 and crashes on ✓ ✗ →
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from votal import VotalShield
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage

# ──────────────────────────────────────────────────────────────────────────
# 1. Initialize Shield (once, at import time)
# ──────────────────────────────────────────────────────────────────────────

shield = VotalShield(
    shield_url=os.getenv("LLM_SHIELD_URL", "http://localhost:8000"),
    api_key=os.getenv("API_KEY", ""),
    agent_id=os.getenv("AGENT_ID", "customer-service-agent"),
    user_role=os.getenv("USER_ROLE", "branch_manager"),
    auth_token=os.getenv("RUNPOD_TOKEN", ""),  # RunPod Bearer token
)

# ──────────────────────────────────────────────────────────────────────────
# 2. Define tools with @shield.protect (one line per tool)
#
#    What the decorator does on every call:
#      a) POST /v1/shield/tool/check  → RBAC: is this role allowed?
#      b) If allowed → execute the tool
#      c) POST /v1/shield/tool/output → sanitize output (PII redaction)
#      d) Return sanitized output (or "DENIED by Shield: ..." if blocked)
# ──────────────────────────────────────────────────────────────────────────

# === Option A: @shield.protect decorator (recommended) ===

@shield.protect
@tool
def customer_profile_get(customer_id: str, query_type: str = "basic_info") -> str:
    """Get customer profile information."""
    if query_type == "credit_score":
        return json.dumps({
            "customer_id": customer_id,
            "credit_score": 742,
            "ssn": "123-45-6789",  # Shield will redact this in output
        })
    return json.dumps({
        "customer_id": customer_id,
        "name": "Ahmed Ali",
        "status": "active",
        "since": "2019-03-15",
    })


@shield.protect
@tool
def transaction_history(account_id: str, days: int = 30) -> str:
    """Get transaction history for an account."""
    return json.dumps({
        "account_id": account_id,
        "transactions": [
            {"date": "2026-06-01", "description": "Direct Deposit", "amount": "+$3,200.00"},
            {"date": "2026-05-30", "description": "Grocery Store", "amount": "-$87.50"},
        ],
    })


@shield.protect
@tool
def wire_transfer_execute(from_account: str, to_account: str, amount: float) -> str:
    """Execute a wire transfer between accounts."""
    return json.dumps({
        "status": "completed",
        "from": from_account,
        "to": to_account,
        "amount": amount,
        "confirmation": f"WIR-{abs(hash(from_account)) % 1000000}",
    })


@shield.protect
@tool
def email_send(to: str, subject: str, body: str) -> str:
    """Send an email to a customer or internal team."""
    return json.dumps({"status": "sent", "to": to, "subject": subject})


# All tools — already protected by the decorator
TOOLS = [customer_profile_get, transaction_history, wire_transfer_execute, email_send]


# === Option B: Wrap existing tools in bulk (if you have tools already) ===
#
# from some_library import search_tool, calc_tool
# protected_tools = shield.wrap_tools([search_tool, calc_tool])


# === Option C: Manual control with context manager ===
#
# with shield.tool_guard("customer_profile_get", {"customer_id": "C-123"}) as guard:
#     if guard.allowed:
#         raw = get_profile("C-123")
#         clean = guard.sanitize(raw)
#     else:
#         print(f"Denied: {guard.reason}")


# ──────────────────────────────────────────────────────────────────────────
# 3. Run the agent
# ──────────────────────────────────────────────────────────────────────────

def run(user_message: str):
    print(f"\n{'=' * 60}")
    print(f"User: {user_message}")
    print(f"Role: {shield.user_role} | Agent: {shield.agent_id}")
    print(f"{'=' * 60}")

    llm = ChatOpenAI(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        api_key=os.getenv("OPENAI_API_KEY", ""),
    )

    llm_with_tools = llm.bind_tools(TOOLS)
    messages = [HumanMessage(content=user_message)]
    response = llm_with_tools.invoke(messages)

    if not response.tool_calls:
        print(f"  Response: {response.content}")
        return response.content

    # Process tool calls — Shield decorator handles RBAC + sanitization
    messages.append(response)
    tool_map = {t.name: t for t in TOOLS}

    for tc in response.tool_calls:
        fn = tool_map.get(tc["name"])
        if not fn:
            messages.append(ToolMessage(content=f"Unknown tool: {tc['name']}", tool_call_id=tc["id"]))
            continue

        # This is where the magic happens:
        # fn.invoke() calls the decorated function which internally does:
        #   1. shield.check_tool() → RBAC
        #   2. original function() → execute
        #   3. shield.sanitize_output() → PII redaction
        result = fn.invoke(tc["args"])

        if str(result).startswith("DENIED by Shield"):
            print(f"  [BLOCKED] {tc['name']}: {result}")
        else:
            print(f"  [ALLOWED] {tc['name']} → {str(result)[:100]}...")

        messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    final = llm_with_tools.invoke(messages)
    print(f"  Response: {final.content}")
    return final.content


# ──────────────────────────────────────────────────────────────────────────
# 4. Demo — switch USER_ROLE to see different access levels
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not shield.api_key:
        print("Set API_KEY environment variable")
        exit(1)

    print("LangChain + Shield Decorator Demo")
    print(f"  Shield:  {shield.shield_url}")
    print(f"  Agent:   {shield.agent_id}")
    print(f"  Role:    {shield.user_role}")
    print(f"  Health:  {'OK' if shield.health() else 'UNREACHABLE'}")

    # Switch role to test different access:
    #   USER_ROLE=branch_manager     → all tools
    #   USER_ROLE=customer_support   → profile, statement, email (no wire transfer)
    #   USER_ROLE=compliance_officer → tx history, email only
    #   USER_ROLE=fraud_analyst      → profile, tx history (no wire transfer, no email)

    # Scenario 1: Look up a customer (allowed for most roles)
    run("Look up the profile for customer CUST-12345")

    # Scenario 2: Wire transfer (only branch_manager and payments_officer)
    run("Transfer $500 from CHK-001 to SAV-002")

    # Scenario 3: Email with PII (Shield sanitizes the output)
    run("Get the credit score for CUST-12345 and email it to ops@bank.ae")

    # ── Bonus: Switch role at runtime ─────────────────────────────────
    print(f"\n{'=' * 60}")
    print("Switching to compliance_officer role...")
    print(f"{'=' * 60}")

    # shield.with_role() returns a new client — original is unchanged
    compliance_shield = shield.with_role("compliance_officer")

    # Re-wrap one tool with the new role to demonstrate
    @compliance_shield.protect
    @tool
    def wire_transfer_compliance(from_account: str, to_account: str, amount: float) -> str:
        """Execute a wire transfer (compliance test)."""
        return json.dumps({"status": "completed"})

    # This will be BLOCKED — compliance_officer can't wire transfer
    result = wire_transfer_compliance.invoke({
        "from_account": "CHK-001",
        "to_account": "SAV-002",
        "amount": 500.0,
    })
    print(f"  compliance_officer wire transfer: {result}")
