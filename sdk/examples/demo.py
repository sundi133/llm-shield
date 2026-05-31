#!/usr/bin/env python3
"""Demo: Votal Shield SDK with LangChain (Option 3 architecture).

Shows 3 ways to use the SDK:
  1. @shield.protect decorator
  2. shield.wrap_tools()
  3. shield.tool_guard() context manager

Run:
    export LITELLM_URL="https://litellm.your-company.com"
    export LITELLM_API_KEY="sk-..."
    export LLM_MODEL="moonshotai/kimi-k2.5"       # optional
    export LLM_SHIELD_URL="https://shield.votal.ai"
    export SHIELD_API_KEY="your-tenant-api-key"
    export SHIELD_TOKEN="rpa_..."                  # RunPod auth token (optional)
    export AGENT_ID="my-agent"                     # optional
    export USER_ROLE="branch_manager"              # optional

    pip install votal langchain langchain-openai
    python demo.py
"""

import os
import sys

# Add SDK to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from votal import VotalShield

# ── Initialize Shield ─────────────────────────────────────────────

LITELLM_URL = os.getenv("LITELLM_URL", "")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "moonshotai/kimi-k2.5")
AGENT_ID = os.getenv("AGENT_ID", "sdk-demo-agent")
USER_ROLE = os.getenv("USER_ROLE", "branch_manager")

shield = VotalShield(
    shield_url=os.getenv("LLM_SHIELD_URL", "https://shield.votal.ai"),
    api_key=os.getenv("SHIELD_API_KEY", ""),
    agent_id=AGENT_ID,
    user_role=USER_ROLE,
    auth_token=os.getenv("SHIELD_TOKEN", ""),
)

if not LITELLM_URL or not shield.shield_url:
    print("Set LITELLM_URL and LLM_SHIELD_URL env vars")
    sys.exit(1)

# ── Register agent (once) ────────────────────────────────────────

shield.register_agent(
    tools=["search_customer", "get_account_balance", "send_notification"],
    role_permissions={
        "viewer": ["search_customer"],
        "branch_manager": ["search_customer", "get_account_balance"],
        "admin": ["search_customer", "get_account_balance", "send_notification"],
    },
    name="SDK Demo Agent",
)

# ── Option 1: @shield.protect decorator ──────────────────────────

print("\n" + "=" * 60)
print("  OPTION 1: @shield.protect decorator")
print("=" * 60)

try:
    from langchain.tools import tool
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, ToolMessage

    @shield.protect
    @tool
    def search_customer(customer_id: str) -> str:
        """Search for a customer by ID."""
        return f"Customer {customer_id}: Jane Smith, email: jane@acme.com"

    @shield.protect
    @tool
    def get_account_balance(customer_id: str) -> str:
        """Get account balance. Returns financial details."""
        return f"Customer {customer_id}: SSN: 123-45-6789, Balance: $45,230"

    @shield.protect
    @tool
    def send_notification(customer_id: str, message: str) -> str:
        """Send a notification to a customer."""
        return f"Sent to {customer_id}: {message}"

    # Test each tool directly
    print("\n  Testing search_customer (branch_manager: ALLOWED):")
    result = search_customer.invoke({"customer_id": "C-123"})
    print(f"  Result: {result}")

    print("\n  Testing get_account_balance (branch_manager: ALLOWED, output sanitized):")
    result = get_account_balance.invoke({"customer_id": "C-123"})
    print(f"  Result: {result}")

    print("\n  Testing send_notification (branch_manager: BLOCKED):")
    result = send_notification.invoke({"customer_id": "C-123", "message": "test"})
    print(f"  Result: {result}")

except ImportError:
    print("  LangChain not installed, skipping decorator demo")


# ── Option 2: Full agent with wrap_tools ─────────────────────────

print("\n" + "=" * 60)
print("  OPTION 2: LangChain agent with shield.wrap_tools()")
print("=" * 60)

try:
    from langchain.tools import tool as lc_tool
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, ToolMessage

    @lc_tool
    def lookup_balance(customer_id: str) -> str:
        """Look up a customer's account balance."""
        return f"Customer {customer_id}: SSN: 999-88-7777, Balance: $12,000"

    @lc_tool
    def send_alert(customer_id: str, message: str) -> str:
        """Send an alert to a customer."""
        return f"Alert sent to {customer_id}: {message}"

    # Wrap all tools in one call
    protected_tools = shield.wrap_tools([lookup_balance, send_alert])
    tool_map = {t.name: t for t in protected_tools}

    # Point LangChain at LiteLLM
    llm = ChatOpenAI(
        model=LLM_MODEL,
        base_url=f"{LITELLM_URL}/v1",
        api_key=LITELLM_API_KEY,
        temperature=0.1,
    )
    llm_with_tools = llm.bind_tools(protected_tools)

    print("\n  Sending: 'Get the balance for customer C-999'")
    messages = [HumanMessage(content="Get the balance for customer C-999")]
    response = llm_with_tools.invoke(messages)

    if response.tool_calls:
        messages.append(response)
        for tc in response.tool_calls:
            fn = tool_map.get(tc["name"])
            if fn:
                # Tool is already wrapped — RBAC + sanitize happens inside
                result = fn.invoke(tc["args"])
                print(f"  Tool {tc['name']}: {result}")
                messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

        final = llm_with_tools.invoke(messages)
        print(f"\n  Final: {final.content}")
    else:
        print(f"  Response: {response.content}")

except ImportError:
    print("  LangChain not installed, skipping agent demo")
except Exception as e:
    print(f"  Error: {e}")


# ── Option 3: Manual tool_guard context manager ──────────────────

print("\n" + "=" * 60)
print("  OPTION 3: shield.tool_guard() context manager")
print("=" * 60)

with shield.tool_guard("search_customer", {"customer_id": "C-456"}) as guard:
    print(f"\n  search_customer allowed: {guard.allowed}")
    if guard.allowed:
        raw = "Customer C-456: Bob Jones, SSN: 111-22-3333"
        clean = guard.sanitize(raw)
        print(f"  Raw:   {raw}")
        print(f"  Clean: {clean}")

with shield.tool_guard("send_notification", {"customer_id": "C-456"}) as guard:
    print(f"\n  send_notification allowed: {guard.allowed}")
    if not guard.allowed:
        print(f"  Reason: {guard.reason}")


# ── Role switching ────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  BONUS: Role switching with shield.with_role()")
print("=" * 60)

admin_shield = shield.with_role("admin")
with admin_shield.tool_guard("send_notification", {"customer_id": "C-456"}) as guard:
    print(f"\n  send_notification as admin: allowed={guard.allowed}")

viewer_shield = shield.with_role("viewer")
with viewer_shield.tool_guard("get_account_balance", {"customer_id": "C-456"}) as guard:
    print(f"  get_account_balance as viewer: allowed={guard.allowed}")
    if not guard.allowed:
        print(f"  Reason: {guard.reason}")


print("\n" + "=" * 60)
print("  DONE — SDK makes it easy!")
print("=" * 60)
print("""
  Before (manual):
    check = shield.post("/v1/shield/tool/check", json={...})
    if not check["allowed"]: return "DENIED"
    output = my_tool(args)
    sanitized = shield.post("/v1/shield/tool/output", json={...})

  After (SDK):
    @shield.protect
    @tool
    def my_tool(args): ...
    # That's it. RBAC + mask/redact happens automatically.
""")
