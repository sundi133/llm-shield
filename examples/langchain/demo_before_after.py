#!/usr/bin/env python3
"""Side-by-side: same agent WITHOUT Shield vs WITH Shield.

Run both to show a customer the difference.

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."
    export LLM_SHIELD_URL=https://xxx.api.runpod.ai
    export API_KEY="bank-co-key"
    export RUNPOD_TOKEN="rpa_..."

    python demo_before_after.py
"""

import json
import os

from langchain_anthropic import ChatAnthropic
from langchain.tools import tool
from langchain_core.messages import HumanMessage, ToolMessage

# ══════════════════════════════════════════════════════════════════════════
#  PART 1: WITHOUT SHIELD — no guardrails, no RBAC, no sanitization
# ══════════════════════════════════════════════════════════════════════════

# Tools — no protection, anyone can call anything

@tool
def customer_profile_get(customer_id: str, query_type: str = "basic_info") -> str:
    """Get customer profile information."""
    if query_type == "credit_score":
        return json.dumps({
            "customer_id": customer_id,
            "name": "Ahmed Ali",
            "credit_score": 742,
            "ssn": "123-45-6789",
            "passport": "P1234567",
            "dob": "1985-03-15",
            "balance": "$45,230.00",
        })
    return json.dumps({
        "customer_id": customer_id,
        "name": "Ahmed Ali",
        "status": "active",
        "email": "ahmed@personal.com",
        "phone": "+971-50-123-4567",
    })


@tool
def wire_transfer(from_account: str, to_account: str, amount: float) -> str:
    """Execute a wire transfer between accounts."""
    return json.dumps({
        "status": "completed",
        "from": from_account,
        "to": to_account,
        "amount": amount,
        "confirmation": "WIR-892341",
    })


@tool
def email_send(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return json.dumps({"status": "sent", "to": to, "subject": subject})


TOOLS_UNPROTECTED = [customer_profile_get, wire_transfer, email_send]


def run_without_shield(user_message: str, role: str = ""):
    """Run agent with NO Shield. Any role can do anything. PII flows freely."""
    print(f"\n  {'─' * 56}")
    print(f"  User: {user_message}")
    if role:
        print(f"  Role: {role} (ignored — no RBAC)")
    print(f"  {'─' * 56}")

    llm = ChatAnthropic(model="claude-sonnet-4-6", max_tokens=1024)
    llm_with_tools = llm.bind_tools(TOOLS_UNPROTECTED)

    messages = [HumanMessage(content=user_message)]
    response = llm_with_tools.invoke(messages)

    if not response.tool_calls:
        print(f"  Response: {response.content[:200]}")
        return

    messages.append(response)
    tool_map = {t.name: t for t in TOOLS_UNPROTECTED}

    for tc in response.tool_calls:
        fn = tool_map.get(tc["name"])
        if fn:
            result = fn.invoke(tc["args"])
            print(f"  Tool: {tc['name']}({json.dumps(tc['args'])})")
            print(f"  Output: {result}")  # RAW output — SSN, passport, everything
            messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    final = llm_with_tools.invoke(messages)
    print(f"  Response: {final.content[:300]}")


# ══════════════════════════════════════════════════════════════════════════
#  PART 2: WITH SHIELD — RBAC + data policy + output sanitization
# ══════════════════════════════════════════════════════════════════════════

from votal import VotalShield

shield = VotalShield(
    shield_url=os.getenv("LLM_SHIELD_URL", "http://localhost:8000"),
    api_key=os.getenv("API_KEY", ""),
    agent_id="customer-service-agent",
    user_role=os.getenv("USER_ROLE", "branch_manager"),
    auth_token=os.getenv("RUNPOD_TOKEN", ""),
)


# Same tools — but wrapped with @shield.protect

@shield.protect
@tool
def customer_profile_get_shielded(customer_id: str, query_type: str = "basic_info") -> str:
    """Get customer profile information."""
    if query_type == "credit_score":
        return json.dumps({
            "customer_id": customer_id,
            "name": "Ahmed Ali",
            "credit_score": 742,
            "ssn": "123-45-6789",
            "passport": "P1234567",
            "dob": "1985-03-15",
            "balance": "$45,230.00",
        })
    return json.dumps({
        "customer_id": customer_id,
        "name": "Ahmed Ali",
        "status": "active",
        "email": "ahmed@personal.com",
        "phone": "+971-50-123-4567",
    })


@shield.protect
@tool
def wire_transfer_shielded(from_account: str, to_account: str, amount: float) -> str:
    """Execute a wire transfer between accounts."""
    return json.dumps({
        "status": "completed",
        "from": from_account,
        "to": to_account,
        "amount": amount,
        "confirmation": "WIR-892341",
    })


@shield.protect
@tool
def email_send_shielded(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return json.dumps({"status": "sent", "to": to, "subject": subject})


TOOLS_SHIELDED = [customer_profile_get_shielded, wire_transfer_shielded, email_send_shielded]


def run_with_shield(user_message: str, role: str = ""):
    """Run agent WITH Shield. RBAC enforced. PII redacted."""
    if role:
        s = shield.with_role(role)
        # Re-wrap tools with the new role
        tools = [
            _rewrap(customer_profile_get_shielded, s),
            _rewrap(wire_transfer_shielded, s),
            _rewrap(email_send_shielded, s),
        ]
    else:
        s = shield
        tools = TOOLS_SHIELDED

    print(f"\n  {'─' * 56}")
    print(f"  User: {user_message}")
    print(f"  Role: {s.user_role} (RBAC enforced)")
    print(f"  {'─' * 56}")

    llm = ChatAnthropic(model="claude-sonnet-4-6", max_tokens=1024)
    llm_with_tools = llm.bind_tools(tools)

    messages = [HumanMessage(content=user_message)]
    response = llm_with_tools.invoke(messages)

    if not response.tool_calls:
        print(f"  Response: {response.content[:200]}")
        return

    messages.append(response)
    tool_map = {t.name: t for t in tools}

    for tc in response.tool_calls:
        fn = tool_map.get(tc["name"])
        if fn:
            result = fn.invoke(tc["args"])
            print(f"  Tool: {tc['name']}({json.dumps(tc['args'])})")
            if str(result).startswith("DENIED"):
                print(f"  Result: {result}")
            else:
                print(f"  Output: {str(result)[:150]}")  # sanitized
            messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    final = llm_with_tools.invoke(messages)
    print(f"  Response: {final.content[:300]}")


def _rewrap(tool_obj, shield_client):
    """Re-wrap an already-wrapped tool with a different shield client."""
    import copy
    t = copy.copy(tool_obj)
    original_name = t.name.replace("_shielded", "")
    shield_client._wrap_tool(t)
    return t


# ══════════════════════════════════════════════════════════════════════════
#  DEMO
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  BEFORE vs AFTER: LLM Shield Integration")
    print("=" * 60)

    scenarios = [
        {
            "title": "SCENARIO 1: Customer lookup with sensitive data",
            "message": "Get the credit score for customer CUST-12345",
            "risk": "SSN, passport, DOB leak in plain text",
        },
        {
            "title": "SCENARIO 2: Wire transfer by unauthorized role",
            "message": "Transfer $10,000 from CHK-001 to external account EXT-999",
            "role": "compliance_officer",
            "risk": "Compliance officer shouldn't move money",
        },
        {
            "title": "SCENARIO 3: Email customer data to external address",
            "message": "Email the full profile of CUST-12345 to external@gmail.com",
            "risk": "PII sent to personal email, data exfiltration",
        },
    ]

    for scenario in scenarios:
        title = scenario["title"]
        message = scenario["message"]
        role = scenario.get("role", "branch_manager")
        risk = scenario["risk"]

        print(f"\n\n{'█' * 60}")
        print(f"  {title}")
        print(f"  Risk: {risk}")
        print(f"{'█' * 60}")

        # ── WITHOUT SHIELD ────────────────────────────────────────
        print(f"\n{'▬' * 60}")
        print(f"  ❌ WITHOUT SHIELD")
        print(f"{'▬' * 60}")
        try:
            run_without_shield(message, role)
        except Exception as e:
            print(f"  Error: {e}")

        # ── WITH SHIELD ───────────────────────────────────────────
        print(f"\n{'▬' * 60}")
        print(f"  ✅ WITH SHIELD")
        print(f"{'▬' * 60}")
        try:
            run_with_shield(message, role)
        except Exception as e:
            print(f"  Error: {e}")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    print("""
  Without Shield:
    - Any role calls any tool (no RBAC)
    - SSN, passport, DOB returned in plain text (no sanitization)
    - Customer data emailed to external addresses (no data policy)
    - No audit trail

  With Shield (@shield.protect — one line per tool):
    - RBAC: compliance_officer can't wire transfer
    - Output sanitization: SSN/passport redacted automatically
    - Data policy: external email blocked, PII stripped
    - Full audit trail of every tool call

  Code difference: one decorator per tool.

    # Before                        # After
    @tool                           @shield.protect
    def wire_transfer(...)          @tool
        ...                         def wire_transfer(...)
                                        ...
""")
