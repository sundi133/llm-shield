#!/usr/bin/env python3
"""
Votal Shield SDK — Quickstart
Copy this file, set env vars, run it.

    export LITELLM_URL="https://litellm.your-company.com"
    export LITELLM_API_KEY="sk-your-litellm-key"
    export LLM_MODEL="moonshotai/kimi-k2.5"
    export LLM_SHIELD_URL="https://shield.votal.ai"
    export SHIELD_API_KEY="your-tenant-api-key"
    export SHIELD_TOKEN="your-auth-token"

    pip install langchain langchain-openai openai requests
    python quickstart.py
"""

import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from votal import VotalShield
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage

# ── Config (all from env) ─────────────────────────────────────────

LITELLM_URL = os.environ.get("LITELLM_URL", "")
LITELLM_API_KEY = os.environ.get("LITELLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "moonshotai/kimi-k2.5")

if not LITELLM_URL:
    print("ERROR: export LITELLM_URL=https://your-litellm-proxy")
    sys.exit(1)

shield = VotalShield(
    shield_url=os.environ.get("LLM_SHIELD_URL", ""),
    api_key=os.environ.get("SHIELD_API_KEY", ""),
    agent_id=os.environ.get("AGENT_ID", "quickstart-agent"),
    user_role=os.environ.get("USER_ROLE", "branch_manager"),
    auth_token=os.environ.get("SHIELD_TOKEN", ""),
)

# ── Step 1: Register agent + roles ────────────────────────────────

print("\n[1] Registering agent...")
resp = shield.register_agent(
    tools=["search_customer", "get_account_balance", "transfer_funds"],
    role_permissions={
        "teller":          ["search_customer"],
        "branch_manager":  ["search_customer", "get_account_balance"],
        "admin":           ["search_customer", "get_account_balance", "transfer_funds"],
    },
    name="Quickstart Banking Agent",
)
print(f"    {resp.get('message', resp)}")

# ── Step 2: Define tools with @shield.protect ─────────────────────

@shield.protect
@tool
def search_customer(customer_id: str) -> str:
    """Search for a customer by their ID."""
    return (
        f"Customer {customer_id}: Jane Smith\n"
        f"Email: jane.smith@acme.com\n"
        f"Phone: 555-123-4567\n"
        f"Status: Active"
    )

@shield.protect
@tool
def get_account_balance(customer_id: str) -> str:
    """Get account balance and financial details for a customer."""
    return (
        f"Customer {customer_id}: Jane Smith\n"
        f"SSN: 123-45-6789\n"
        f"Email: jane.smith@acme.com\n"
        f"Account: XXXX-XXXX-4521\n"
        f"Balance: $45,230.00\n"
        f"Credit Score: 780"
    )

@shield.protect
@tool
def transfer_funds(from_account: str, to_account: str, amount: str) -> str:
    """Transfer funds between accounts. Admin only."""
    return f"Transferred {amount} from {from_account} to {to_account}"

tools = [search_customer, get_account_balance, transfer_funds]
tool_map = {t.name: t for t in tools}

# ── Step 3: Create LangChain agent via LiteLLM ───────────────────

llm = ChatOpenAI(
    model=LLM_MODEL,
    base_url=f"{LITELLM_URL}/v1",
    api_key=LITELLM_API_KEY,
    temperature=0.1,
)
llm_with_tools = llm.bind_tools(tools)

# ── Step 4: Run conversations ─────────────────────────────────────

def chat(user_message: str):
    """Send a message, handle tool calls, return final response."""
    print(f"\n{'─'*60}")
    print(f"  User: {user_message}")
    print(f"  Role: {shield.user_role}")
    print(f"{'─'*60}")

    messages = [HumanMessage(content=user_message)]
    response = llm_with_tools.invoke(messages)

    # No tool calls — just text
    if not response.tool_calls:
        print(f"\n  Response: {response.content}")
        return response.content

    # Process tool calls (RBAC + sanitize handled by @shield.protect)
    messages.append(response)
    for tc in response.tool_calls:
        name, args = tc["name"], tc["args"]
        fn = tool_map.get(name)
        if not fn:
            continue

        result = fn.invoke(args)
        print(f"\n  Tool [{name}]: {result}")
        messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    # Final LLM response
    final = llm_with_tools.invoke(messages)
    print(f"\n  Response: {final.content}")
    return final.content


# ── Run it ────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print(f"  Votal Shield Quickstart")
print(f"  Agent: {shield.agent_id} | Role: {shield.user_role}")
print(f"  LiteLLM: {LITELLM_URL}")
print(f"  Shield:  {shield.shield_url}")
print("=" * 60)

# Test 1: Allowed tool
chat("Look up customer C-1234")

# Test 2: Allowed tool with PII in output (should be masked/redacted)
chat("What is the account balance for customer C-1234?")

# Test 3: Blocked tool (branch_manager can't transfer funds)
chat("Transfer $5000 from account A-111 to account A-222")

# Test 4: Switch to admin role and try again
print("\n\n" + "=" * 60)
print("  Switching to admin role...")
print("=" * 60)

admin_shield = shield.with_role("admin")

@admin_shield.protect
@tool
def transfer_funds_admin(from_account: str, to_account: str, amount: str) -> str:
    """Transfer funds between accounts. Admin only."""
    return f"Transferred {amount} from {from_account} to {to_account}"

result = transfer_funds_admin.invoke({
    "from_account": "A-111",
    "to_account": "A-222",
    "amount": "$5000",
})
print(f"\n  Admin transfer result: {result}")

print("\n" + "=" * 60)
print("  Done!")
print("=" * 60)
