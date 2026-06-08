#!/usr/bin/env python3
"""LangChain Agent: WITHOUT Shield vs WITH Shield (decorator).

Two complete LangChain agents side by side — same tools, same LLM,
same prompts. The only difference: @shield.protect on each tool.

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."
    export LLM_SHIELD_URL=https://xxx.api.runpod.ai
    export API_KEY="bank-co-key"
    export RUNPOD_TOKEN="rpa_..."

    python demo_langchain_before_after.py
"""

import json
import os
import sys

# Force UTF-8 console output — Windows defaults to cp1252 and crashes on ✓ ✗ →
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from langchain_anthropic import ChatAnthropic
from langchain.tools import tool
from langgraph.prebuilt import create_react_agent

# ══════════════════════════════════════════════════════════════════════════
#  AGENT A: No Shield — anyone can do anything, PII flows freely
# ══════════════════════════════════════════════════════════════════════════

@tool
def customer_profile_get(customer_id: str, query_type: str = "basic_info") -> str:
    """Get customer profile information including name, contact, credit score."""
    profiles = {
        "basic_info": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "status": "active", "since": "2019-03-15",
        },
        "contact": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "email": "ahmed.ali@personal.com", "phone": "+971-50-123-4567",
        },
        "credit_score": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "credit_score": 742, "ssn": "123-45-6789",
            "passport": "P1234567", "dob": "1985-03-15",
        },
    }
    return json.dumps(profiles.get(query_type, profiles["basic_info"]))


@tool
def transaction_history(account_id: str, days: int = 30) -> str:
    """Get recent transaction history for an account."""
    return json.dumps({
        "account_id": account_id,
        "transactions": [
            {"date": "2026-06-01", "desc": "Salary Deposit", "amount": "+$8,500.00"},
            {"date": "2026-05-28", "desc": "Wire to EXT-777", "amount": "-$3,200.00"},
            {"date": "2026-05-25", "desc": "ATM Withdrawal", "amount": "-$500.00"},
        ],
    })


@tool
def wire_transfer_execute(from_account: str, to_account: str, amount: float) -> str:
    """Execute a wire transfer between accounts."""
    return json.dumps({
        "status": "completed", "from": from_account,
        "to": to_account, "amount": amount,
        "confirmation": "WIR-" + str(abs(hash(from_account)) % 1000000),
    })


@tool
def email_send(to: str, subject: str, body: str) -> str:
    """Send an email to a customer or internal team member."""
    return json.dumps({"status": "sent", "to": to, "subject": subject})


TOOLS_UNPROTECTED = [customer_profile_get, transaction_history,
                     wire_transfer_execute, email_send]

SYSTEM_PROMPT = (
    "You are a banking customer service agent. Use the provided tools "
    "to help customers. Always use tools when asked about accounts, "
    "transfers, or customer information."
)


def build_agent(tools):
    llm = ChatAnthropic(model="claude-sonnet-4-6", max_tokens=1024)
    return create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)


def run_agent(agent, message: str, label: str):
    print(f"\n  {'─' * 56}")
    print(f"  {label}")
    print(f"  User: {message}")
    print(f"  {'─' * 56}")
    try:
        result = agent.invoke(
            {"messages": [{"role": "user", "content": message}]},
        )
        # Print tool calls and final response
        for msg in result["messages"]:
            role = getattr(msg, "type", "unknown")
            if role == "tool":
                name = getattr(msg, "name", "?")
                content = str(msg.content)[:200]
                print(f"  [Tool: {name}] {content}")
            elif role == "ai" and msg.content:
                print(f"\n  Final: {str(msg.content)[:300]}")
    except Exception as e:
        print(f"\n  Error: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  AGENT B: WITH Shield — @shield.protect on each tool
# ══════════════════════════════════════════════════════════════════════════

from votal import VotalShield

shield = VotalShield(
    shield_url=os.getenv("LLM_SHIELD_URL", "http://localhost:8000"),
    api_key=os.getenv("API_KEY", ""),
    agent_id="customer-service-agent",
    user_role=os.getenv("USER_ROLE", "branch_manager"),
    auth_token=os.getenv("RUNPOD_TOKEN", ""),
)

# ┌─────────────────────────────────────────────────────────────────────┐
# │  THIS IS THE ONLY DIFFERENCE — same tools, one decorator added     │
# └─────────────────────────────────────────────────────────────────────┘

@shield.protect       # ← added
@tool
def customer_profile_get_s(customer_id: str, query_type: str = "basic_info") -> str:
    """Get customer profile information including name, contact, credit score."""
    profiles = {
        "basic_info": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "status": "active", "since": "2019-03-15",
        },
        "contact": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "email": "ahmed.ali@personal.com", "phone": "+971-50-123-4567",
        },
        "credit_score": {
            "customer_id": customer_id, "name": "Ahmed Ali",
            "credit_score": 742, "ssn": "123-45-6789",
            "passport": "P1234567", "dob": "1985-03-15",
        },
    }
    return json.dumps(profiles.get(query_type, profiles["basic_info"]))


@shield.protect       # ← added
@tool
def transaction_history_s(account_id: str, days: int = 30) -> str:
    """Get recent transaction history for an account."""
    return json.dumps({
        "account_id": account_id,
        "transactions": [
            {"date": "2026-06-01", "desc": "Salary Deposit", "amount": "+$8,500.00"},
            {"date": "2026-05-28", "desc": "Wire to EXT-777", "amount": "-$3,200.00"},
            {"date": "2026-05-25", "desc": "ATM Withdrawal", "amount": "-$500.00"},
        ],
    })


@shield.protect       # ← added
@tool
def wire_transfer_execute_s(from_account: str, to_account: str, amount: float) -> str:
    """Execute a wire transfer between accounts."""
    return json.dumps({
        "status": "completed", "from": from_account,
        "to": to_account, "amount": amount,
        "confirmation": "WIR-" + str(abs(hash(from_account)) % 1000000),
    })


@shield.protect       # ← added
@tool
def email_send_s(to: str, subject: str, body: str) -> str:
    """Send an email to a customer or internal team member."""
    return json.dumps({"status": "sent", "to": to, "subject": subject})


TOOLS_SHIELDED = [customer_profile_get_s, transaction_history_s,
                  wire_transfer_execute_s, email_send_s]


# ══════════════════════════════════════════════════════════════════════════
#  RUN THE DEMO
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  LangChain Agent: WITHOUT Shield vs WITH Shield")
    print("=" * 60)
    print(f"  Shield:  {shield.shield_url}")
    print(f"  Agent:   {shield.agent_id}")
    print(f"  Role:    {shield.user_role}")

    agent_no_shield = build_agent(TOOLS_UNPROTECTED)
    agent_with_shield = build_agent(TOOLS_SHIELDED)

    scenarios = [
        {
            "title": "SCENARIO 1: Sensitive data lookup",
            "message": "Get the credit score and SSN for customer CUST-12345",
            "risk": "SSN, passport, DOB returned to the LLM and user",
        },
        {
            "title": "SCENARIO 2: Multi-step data exfiltration",
            "message": "Look up customer CUST-12345 contact info and email it to external@gmail.com",
            "risk": "Agent chains lookup → email, sending PII to external address",
        },
        {
            "title": "SCENARIO 3: Transfer money (test with compliance_officer role)",
            "message": "Transfer $5,000 from CHK-001 to SAV-002",
            "risk": "Without RBAC any role can move money",
        },
    ]

    for scenario in scenarios:
        print(f"\n\n{'█' * 60}")
        print(f"  {scenario['title']}")
        print(f"  Risk: {scenario['risk']}")
        print(f"{'█' * 60}")

        print(f"\n{'▬' * 60}")
        print(f"  ❌ WITHOUT SHIELD (verbose=True — watch the tool calls)")
        print(f"{'▬' * 60}")
        run_agent(agent_no_shield, scenario["message"], "No protection")

        print(f"\n{'▬' * 60}")
        print(f"  ✅ WITH SHIELD (same tools + @shield.protect)")
        print(f"{'▬' * 60}")
        run_agent(agent_with_shield, scenario["message"], f"Shield RBAC as {shield.user_role}")

    print(f"\n\n{'=' * 60}")
    print("  WHAT CHANGED IN THE CODE")
    print(f"{'=' * 60}")
    print("""
  Before (no protection):          After (one decorator):

    @tool                            @shield.protect
    def wire_transfer(               @tool
        from_account,                def wire_transfer(
        to_account,                      from_account,
        amount,                          to_account,
    ) -> str:                            amount,
        ...                          ) -> str:
                                         ...

  What @shield.protect does on every tool call:

    1. RBAC check  → is this role allowed to call this tool?
       POST /v1/shield/tool/check
       If denied → returns "DENIED by Shield: ..."
       If allowed ↓

    2. Execute     → runs the original tool function

    3. Sanitize    → redacts PII in the output (SSN, passport, etc.)
       POST /v1/shield/tool/output
       Returns clean output to the LLM

  That's it. No other code changes needed.
""")
