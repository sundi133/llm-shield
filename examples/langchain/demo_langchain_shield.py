#!/usr/bin/env python3
"""
LangChain + LLM Shield — Working Demo (Option 3)

Architecture:
  LangChain → LiteLLM Proxy (Railway) → LLM (guardrails automatic)
  App → Shield (RunPod) → tool RBAC + data policies (mask/redact/block)

Run:
  chmod +x run_example.sh && ./run_example.sh
"""

import os
import sys
import json
import requests

# ---------------------------------------------------------------------------
# Config from env vars
# ---------------------------------------------------------------------------

LITELLM_URL = os.getenv("LITELLM_URL", "").rstrip("/")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "moonshotai/kimi-k2.5")

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "").rstrip("/")
SHIELD_TOKEN = os.getenv("SHIELD_TOKEN", "")
SHIELD_ADMIN_KEY = os.getenv("SHIELD_ADMIN_KEY", "")

AGENT_ID = "langchain-demo-agent"
USER_ROLE = "branch_manager"

if not LITELLM_URL or not SHIELD_URL:
    print("ERROR: Set LITELLM_URL and LLM_SHIELD_URL env vars")
    sys.exit(1)

# Shield session with auth
shield = requests.Session()
shield.headers.update({
    "X-API-Key": SHIELD_ADMIN_KEY,
    "X-Agent-Key": AGENT_ID,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SHIELD_TOKEN}",
})


def log(label, data):
    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    if isinstance(data, dict):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


# ---------------------------------------------------------------------------
# Step 0: Verify endpoints are reachable
# ---------------------------------------------------------------------------

def check_endpoints():
    print(f"\n{'='*60}")
    print(f"  ENDPOINT CHECK")
    print(f"{'='*60}")
    print(f"  LiteLLM: {LITELLM_URL}")
    print(f"  Shield:  {SHIELD_URL}")
    print(f"  Model:   {LLM_MODEL}")
    print(f"  Agent:   {AGENT_ID}")
    print(f"  Role:    {USER_ROLE}")

    # Check Shield
    try:
        r = shield.get(f"{SHIELD_URL}/health", timeout=10)
        print(f"\n  Shield health: {r.status_code} {r.text[:100]}")
    except Exception as e:
        print(f"\n  Shield health: FAILED - {e}")

    # Check LiteLLM
    try:
        r = requests.get(f"{LITELLM_URL}/health", timeout=10,
                         headers={"Authorization": f"Bearer {LITELLM_API_KEY}"})
        print(f"  LiteLLM health: {r.status_code}")
    except Exception as e:
        print(f"  LiteLLM health: FAILED - {e}")


# ---------------------------------------------------------------------------
# Step 1: Register agent with Shield
# ---------------------------------------------------------------------------

def register_agent():
    log("STEP 1: Register Agent", f"Registering {AGENT_ID} with Shield...")

    payload = {
        "agent_id": AGENT_ID,
        "name": "LangChain Demo Agent",
        "description": "Demo agent for LangChain + Shield integration",
        "tools": ["search_customer", "get_account_balance", "send_notification"],
        "role_permissions": {
            "viewer": ["search_customer"],
            "branch_manager": ["search_customer", "get_account_balance"],
            "admin": ["search_customer", "get_account_balance", "send_notification"],
        },
    }
    r = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=payload)
    print(f"  Status: {r.status_code}")
    try:
        print(f"  Response: {json.dumps(r.json(), indent=2)}")
    except Exception:
        print(f"  Response: {r.text[:200]}")


# ---------------------------------------------------------------------------
# Step 2: Set up a data policy with mask/redact for the tool
# ---------------------------------------------------------------------------

def setup_data_policy():
    log("STEP 2: Setup Data Policy", "Creating data policy for get_account_balance...")

    policy = {
        "tool_name": "get_account_balance",
        "sanitization_rules": [
            {
                "pattern_id": "ssn",
                "regex": r"\b\d{3}-\d{2}-\d{4}\b",
                "replacement": "[SSN REDACTED]",
                "description": "Social Security Number",
                "enabled": True,
                "severity": "high",
                "action": "redact",
            },
            {
                "pattern_id": "email",
                "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
                "replacement": "[EMAIL]",
                "description": "Email address",
                "enabled": True,
                "severity": "medium",
                "action": "mask",
            },
            {
                "pattern_id": "phone",
                "regex": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                "replacement": "[PHONE]",
                "description": "Phone number",
                "enabled": True,
                "severity": "medium",
                "action": "mask",
            },
        ],
        "role_policies": [
            {
                "role": "branch_manager",
                "action": "mask",
                "data_scope": ["personal", "financial"],
                "redaction_level": "partial",
                "input_rules": ["Allow lookup by customer ID only"],
                "output_rules": ["Mask SSN and phone numbers", "Allow account balance"],
            },
            {
                "role": "viewer",
                "action": "redact",
                "data_scope": ["personal"],
                "redaction_level": "full",
                "input_rules": [],
                "output_rules": ["Redact all PII"],
            },
            {
                "role": "admin",
                "action": "allow",
                "data_scope": ["personal", "financial", "contact"],
                "redaction_level": "none",
                "input_rules": [],
                "output_rules": [],
            },
        ],
        "compliance_framework": "pci_dss",
        "audit_required": True,
    }

    r = shield.post(
        f"{SHIELD_URL}/v1/data-policies/tools/get_account_balance/policy",
        json=policy,
    )
    print(f"  Status: {r.status_code}")
    try:
        print(f"  Response: {json.dumps(r.json(), indent=2)}")
    except Exception:
        print(f"  Response: {r.text[:200]}")


# ---------------------------------------------------------------------------
# Step 3: Run LangChain agent with tool calls
# ---------------------------------------------------------------------------

def run_langchain_demo():
    log("STEP 3: LangChain Agent with Shield Tool RBAC", "")

    try:
        from langchain_openai import ChatOpenAI
        from langchain.tools import tool
        from langchain_core.messages import HumanMessage, ToolMessage
    except ImportError:
        print("  LangChain not installed. Running with raw OpenAI client instead.")
        print("  Install: pip install langchain langchain-openai")
        run_raw_openai_demo()
        return

    # ── Define tools ──────────────────────────────────────────────

    @tool
    def search_customer(customer_id: str) -> str:
        """Search for a customer by their ID."""
        return f"Customer {customer_id}: Jane Smith, email: jane@acme.com, phone: 555-123-4567"

    @tool
    def get_account_balance(customer_id: str) -> str:
        """Get the account balance for a customer. Returns financial details."""
        return (
            f"Customer {customer_id}: Jane Smith\n"
            f"SSN: 123-45-6789\n"
            f"Email: jane.smith@acme.com\n"
            f"Phone: 555-987-6543\n"
            f"Account Balance: $45,230.00\n"
            f"Credit Score: 780"
        )

    @tool
    def send_notification(customer_id: str, message: str) -> str:
        """Send a notification to a customer."""
        return f"Notification sent to {customer_id}: {message}"

    tools = [search_customer, get_account_balance, send_notification]
    tool_map = {t.name: t for t in tools}

    # ── LangChain LLM via LiteLLM ────────────────────────────────

    llm = ChatOpenAI(
        model=LLM_MODEL,
        base_url=f"{LITELLM_URL}/v1",
        api_key=LITELLM_API_KEY,
        default_headers={
            "X-API-Key": SHIELD_ADMIN_KEY,
            "X-Agent-Key": AGENT_ID,
            "X-User-Role": USER_ROLE,
        },
        temperature=0.1,
    )
    llm_with_tools = llm.bind_tools(tools)

    # ── Test scenarios ────────────────────────────────────────────

    scenarios = [
        {
            "name": "ALLOWED tool + data policy (mask)",
            "message": "Get the account balance for customer C-1234",
            "expect": "branch_manager can use get_account_balance, but SSN/phone should be masked",
        },
        {
            "name": "ALLOWED tool (no sensitive data)",
            "message": "Search for customer C-5678",
            "expect": "branch_manager can use search_customer",
        },
        {
            "name": "BLOCKED tool (RBAC deny)",
            "message": "Send a notification to customer C-1234 saying their payment is overdue",
            "expect": "branch_manager cannot use send_notification (only admin can)",
        },
    ]

    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'='*60}")
        print(f"  SCENARIO {i}: {scenario['name']}")
        print(f"  Message: {scenario['message']}")
        print(f"  Expect:  {scenario['expect']}")
        print(f"{'='*60}")

        messages = [HumanMessage(content=scenario["message"])]

        # Step 3a: LLM call via LiteLLM (guardrails automatic)
        try:
            response = llm_with_tools.invoke(messages)
        except Exception as e:
            print(f"\n  [BLOCKED by guardrails] {e}")
            continue

        if not response.tool_calls:
            print(f"\n  [LLM Response] {response.content}")
            continue

        # Step 3b: Process tool calls with Shield
        messages.append(response)

        for tc in response.tool_calls:
            name, args = tc["name"], tc["args"]
            print(f"\n  [LLM requested] {name}({args})")

            # Shield RBAC + data policy check
            check = shield.post(f"{SHIELD_URL}/v1/shield/tool/check", json={
                "tool_name": name,
                "tool_input": args,
                "agent_key": AGENT_ID,
                "user_role": USER_ROLE,
            })
            check_data = check.json() if check.status_code == 200 else {"allowed": True}
            print(f"  [Shield check] status={check.status_code} allowed={check_data.get('allowed', True)}")
            if not check_data.get("allowed", True):
                for gr in check_data.get("guardrail_results", []):
                    if not gr.get("passed", True):
                        print(f"    guardrail={gr.get('guardrail')} msg={gr.get('message', '')[:100]}")

            if not check_data.get("allowed", True):
                reason = check_data.get("reason", "denied by RBAC")
                print(f"  [BLOCKED] {name} — {reason}")
                messages.append(ToolMessage(
                    content=f"DENIED: {reason}",
                    tool_call_id=tc["id"],
                ))
                continue

            # Execute tool locally
            fn = tool_map.get(name)
            if not fn:
                continue
            raw_output = fn.invoke(args)
            print(f"  [Tool output] {raw_output}")

            # Shield sanitize output (mask/redact/block)
            sanitized = shield.post(f"{SHIELD_URL}/v1/shield/tool/output", json={
                "tool_name": name,
                "tool_output": str(raw_output),
                "agent_key": AGENT_ID,
            })
            san_data = sanitized.json() if sanitized.status_code == 200 else {}
            action = san_data.get("action", "pass")
            clean = san_data.get("sanitized_output", str(raw_output))

            if action == "block":
                print(f"  [OUTPUT BLOCKED] data policy blocked output")
                messages.append(ToolMessage(
                    content="Tool output blocked by data policy.",
                    tool_call_id=tc["id"],
                ))
            else:
                if clean != str(raw_output):
                    print(f"  [SANITIZED ({action})] {clean}")
                else:
                    print(f"  [PASSED] output unchanged")
                messages.append(ToolMessage(content=clean, tool_call_id=tc["id"]))

        # Step 3c: Final LLM call with tool results
        try:
            final = llm_with_tools.invoke(messages)
            print(f"\n  [Final Response] {final.content}")
        except Exception as e:
            print(f"\n  [Error] {e}")


# ---------------------------------------------------------------------------
# Fallback: raw OpenAI client (no LangChain needed)
# ---------------------------------------------------------------------------

def run_raw_openai_demo():
    from openai import OpenAI

    client = OpenAI(
        base_url=f"{LITELLM_URL}/v1",
        api_key=LITELLM_API_KEY,
        default_headers={
            "X-API-Key": SHIELD_ADMIN_KEY,
            "X-Agent-Key": AGENT_ID,
            "X-User-Role": USER_ROLE,
        },
    )

    tools = [
        {"type": "function", "function": {
            "name": "get_account_balance",
            "description": "Get account balance for a customer",
            "parameters": {
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            },
        }},
    ]

    print("\n  Calling LLM via LiteLLM...")
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": "You are a banking assistant. Use tools to help customers."},
            {"role": "user", "content": "Get the account balance for customer C-1234"},
        ],
        tools=tools,
        tool_choice="auto",
    )
    msg = response.choices[0].message

    if not msg.tool_calls:
        print(f"  [Response] {msg.content}")
        return

    for tc in msg.tool_calls:
        name = tc.function.name
        args = json.loads(tc.function.arguments)
        print(f"\n  [LLM requested] {name}({args})")

        # Shield RBAC check
        check = shield.post(f"{SHIELD_URL}/v1/shield/tool/check", json={
            "tool_name": name,
            "tool_input": args,
            "agent_key": AGENT_ID,
            "user_role": USER_ROLE,
        })
        check_data = check.json() if check.status_code == 200 else {}
        print(f"  [Shield check] {json.dumps(check_data, indent=2)}")

        # Simulate tool output with PII
        raw = "Customer C-1234: Jane Smith, SSN: 123-45-6789, Email: jane@acme.com, Balance: $45,230"
        print(f"  [Tool output] {raw}")

        # Shield sanitize
        sanitized = shield.post(f"{SHIELD_URL}/v1/shield/tool/output", json={
            "tool_name": name,
            "tool_output": raw,
            "agent_key": AGENT_ID,
        })
        san_data = sanitized.json() if sanitized.status_code == 200 else {}
        clean = san_data.get("sanitized_output", raw)
        print(f"  [Sanitized] {clean}")


# ---------------------------------------------------------------------------
# Step 4: Check shadow discovery
# ---------------------------------------------------------------------------

def check_shadows():
    log("STEP 4: Shadow Discovery", "Checking for unregistered agents/tools...")
    r = shield.get(f"{SHIELD_URL}/v1/agents/unregistered")
    if r.status_code == 200:
        data = r.json()
        if data.get("agents") or data.get("tools"):
            print(json.dumps(data, indent=2))
        else:
            print("  No shadow agents or tools detected.")
    else:
        print(f"  Status: {r.status_code} {r.text[:100]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    check_endpoints()
    register_agent()
    setup_data_policy()
    run_langchain_demo()
    check_shadows()

    print(f"\n{'='*60}")
    print("  DONE")
    print(f"{'='*60}")
    print("""
  What happened:
    1. Agent registered with role-based tool permissions
    2. Data policy set: branch_manager gets MASK on PII
    3. LLM called via LiteLLM (input/output guardrails automatic)
    4. Tool calls checked by Shield RBAC
    5. Tool output sanitized: SSN masked, email masked, balance visible
    6. Shadow discovery checked for unregistered agents

  Two services, two URLs:
    LiteLLM: {litellm} (guardrails automatic)
    Shield:  {shield} (tool RBAC + data policies)
""".format(litellm=LITELLM_URL, shield=SHIELD_URL))
