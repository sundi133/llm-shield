#!/usr/bin/env python3
"""LangChain + LLM Shield — Single-Pane Architecture

All guardrails, RBAC, and tool validation happen inside Shield automatically.
The client only needs to:
  1. Send messages to Shield /v1/shield/chat/completions (with tools)
  2. Execute ALLOWED tools locally
  3. Send tool results back to Shield for the next LLM turn

No separate /tool/check or /tool/output calls needed.

Architecture:
  App ──> Shield /v1/shield/chat/completions
            ├── 1. Auth + Identity + RBAC resolve
            ├── 2. Input Guardrails (PII, adversarial, toxicity, etc.)
            ├── 3. LLM Call (with tools) ──> LLM Backend
            ├── 4. Tool RBAC per tool_call (RBACGuard + scope_mappings)
            ├── 5. Output Guardrails on text
            └── 6. Return response with per-tool allowed/blocked

  App executes allowed tools, sends results in next turn ──> same pipeline

Setup:
    # 1. Configure data policies with scope_mappings (one-time, via API or portal):
    curl -X POST $SHIELD_URL/v1/data-policies/tools/patient_lookup/policy \\
      -H "X-API-Key: $API_KEY" \\
      -d '{
        "tool_name": "patient_lookup",
        "scope_mappings": [
          {"parameter": "query_type", "values": {"billing": "billing", "history": "medical_history", "demographics": "demographics"}},
          {"parameter": "department", "values": {"hr": "employee_data", "finance": "financial_records"}}
        ],
        "role_policies": [
          {"role": "nurse",         "action": "allow", "data_scope": ["demographics", "allergies", "medical_history"]},
          {"role": "billing_clerk", "action": "allow", "data_scope": ["demographics", "billing"]},
          {"role": "admin",         "action": "allow", "data_scope": ["demographics", "billing", "medical_history", "employee_data"]}
        ]
      }'

    # 2. Configure RBAC roles (in config.yaml or via tenant API):
    #   nurse:
    #     allowed_tools: [patient_lookup, update_vitals]
    #     allowed_data_scopes: [demographics, allergies, medical_history]
    #     denied_data_scopes: [billing, employee_data, financial_records]
    #
    #   billing_clerk:
    #     allowed_tools: [patient_lookup, billing_query]
    #     allowed_data_scopes: [demographics, billing]

    # 3. Run:
    export SHIELD_URL="https://shield.your-company.com"
    export API_KEY="tenant-...-key-..."
    export AGENT_ID="hr-helpdesk-agent"
    export USER_ROLE="nurse"
    python shield_langchain_single_pane.py
"""

import json
import os
import time
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELD_URL = os.getenv("SHIELD_URL", "https://shield.your-company.com")
API_KEY = os.getenv("API_KEY", "")
AGENT_ID = os.getenv("AGENT_ID", "hr-helpdesk-agent")
USER_ROLE = os.getenv("USER_ROLE", "nurse")
SESSION_ID = f"sess-{int(time.time())}"

session = requests.Session()
session.headers.update({
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_ID,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
})

# ---------------------------------------------------------------------------
# Tool definitions — sent to Shield, which forwards them to the LLM
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "patient_lookup",
            "description": "Look up patient records. Accepts patient_id and query_type (demographics, history, billing, allergies).",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string", "description": "Patient identifier"},
                    "query_type": {"type": "string", "enum": ["demographics", "history", "billing", "allergies"]},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_vitals",
            "description": "Record patient vital signs: blood pressure, heart rate, temperature.",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "blood_pressure": {"type": "string"},
                    "heart_rate": {"type": "integer"},
                    "temperature": {"type": "number"},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "billing_query",
            "description": "Query billing records for a patient.",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "date_range": {"type": "string"},
                },
                "required": ["patient_id"],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Local tool implementations (your actual business logic)
# ---------------------------------------------------------------------------

def execute_tool(tool_name: str, args: dict) -> str:
    """Execute a tool locally. This is YOUR code — Shield doesn't run tools."""
    if tool_name == "patient_lookup":
        query_type = args.get("query_type", "demographics")
        pid = args.get("patient_id", "unknown")
        if query_type == "demographics":
            return json.dumps({"patient_id": pid, "name": "Jane Doe", "age": 45, "gender": "F"})
        elif query_type == "billing":
            return json.dumps({"patient_id": pid, "balance": "$1,234.56", "insurance": "BlueCross", "ssn": "123-45-6789"})
        elif query_type == "history":
            return json.dumps({"patient_id": pid, "conditions": ["hypertension", "diabetes"], "surgeries": []})
        elif query_type == "allergies":
            return json.dumps({"patient_id": pid, "allergies": ["penicillin", "latex"]})
    elif tool_name == "update_vitals":
        return json.dumps({"status": "recorded", "patient_id": args.get("patient_id")})
    elif tool_name == "billing_query":
        return json.dumps({"patient_id": args.get("patient_id"), "invoices": [{"amount": "$500", "date": "2024-01-15"}]})
    return json.dumps({"error": f"Unknown tool: {tool_name}"})


# ---------------------------------------------------------------------------
# Single-pane agent loop
# ---------------------------------------------------------------------------

def shield_chat(messages: list[dict], tools: list[dict] | None = None) -> dict:
    """Send a chat request to Shield. Shield handles EVERYTHING:
    - Input guardrails
    - LLM call (with tools)
    - Tool RBAC (RBACGuard + scope_mappings + ToolAllowlist)
    - Output guardrails
    """
    body = {
        "messages": messages,
        "max_tokens": 1024,
        "temperature": 0.3,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    resp = session.post(f"{SHIELD_URL}/v1/shield/chat/completions", json=body)

    if resp.status_code == 403:
        data = resp.json()
        return {"blocked": True, "block_reason": data.get("block_reason", "Blocked by guardrail")}

    if resp.status_code != 200:
        return {"error": f"Shield returned {resp.status_code}: {resp.text}"}

    return resp.json()


def run_agent(user_message: str) -> str:
    """Run a full agent turn with automatic Shield protection.

    Flow:
      1. Send user message + tools to Shield
      2. Shield runs input guardrails, calls LLM, validates tool_calls via RBAC
      3. Client receives response with per-tool allowed/blocked
      4. Client executes only ALLOWED tools
      5. Client sends tool results back to Shield for next LLM turn
      6. Shield runs input guardrails on tool results, calls LLM, runs output guardrails
      7. Client receives final response
    """
    print(f"\n{'=' * 70}")
    print(f"User: {user_message}")
    print(f"Role: {USER_ROLE} | Agent: {AGENT_ID}")
    print(f"{'=' * 70}")

    messages = [
        {"role": "system", "content": "You are a helpful healthcare assistant. Use tools when needed."},
        {"role": "user", "content": user_message},
    ]

    # --- Turn 1: Send to Shield (input guardrails + LLM + tool RBAC + output guardrails) ---
    response = shield_chat(messages, tools=TOOLS)

    if response.get("blocked"):
        reason = response.get("block_reason", "blocked")
        print(f"  [BLOCKED] {reason}")
        return f"Blocked: {reason}"

    if response.get("error"):
        print(f"  [ERROR] {response['error']}")
        return response["error"]

    text = response.get("text", "")
    tool_calls = response.get("tool_calls", [])

    # If no tool calls, return the text (already passed output guardrails)
    if not tool_calls:
        print(f"  Response: {text}")
        return text

    # --- Process tool calls: execute only ALLOWED tools ---
    print(f"\n  Tool calls from LLM ({len(tool_calls)} total):")

    # Build tool result messages for next turn
    messages.append({"role": "assistant", "content": text, "tool_calls": [
        {"id": tc["tool_call_id"], "type": "function",
         "function": {"name": tc["tool_name"], "arguments": json.dumps(tc["arguments"])}}
        for tc in tool_calls
    ]})

    has_allowed_tools = False
    for tc in tool_calls:
        tool_name = tc["tool_name"]
        tool_args = tc["arguments"]
        tool_call_id = tc["tool_call_id"]
        rbac = tc.get("rbac", {})
        allowed = rbac.get("allowed", True)

        if not allowed:
            reason = rbac.get("message", "denied by RBAC")
            print(f"    [BLOCKED] {tool_name}({json.dumps(tool_args)}) -- {reason}")
            # Tell LLM the tool was denied
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": f"DENIED: {reason}",
            })
        else:
            # Execute the tool locally
            result = execute_tool(tool_name, tool_args)
            print(f"    [ALLOWED] {tool_name}({json.dumps(tool_args)}) -> {result}")
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": result,
            })
            has_allowed_tools = True

    # --- Turn 2: Send tool results back to Shield ---
    # Shield runs input guardrails on messages (catches PII in tool results),
    # calls LLM, runs output guardrails on response
    print(f"\n  Sending tool results back to Shield for final response...")
    final_response = shield_chat(messages)

    if final_response.get("blocked"):
        reason = final_response.get("block_reason", "blocked")
        print(f"  [OUTPUT BLOCKED] {reason}")
        return f"Output blocked: {reason}"

    final_text = final_response.get("text", "")
    print(f"  Response: {final_text}")
    return final_text


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not API_KEY:
        print("WARNING: API_KEY not set — Shield requests may be rejected")

    print(f"Shield URL: {SHIELD_URL}")
    print(f"Agent: {AGENT_ID} | Role: {USER_ROLE}")
    print(f"Architecture: Single-pane (Shield handles everything)")

    # Scenario 1: Allowed — nurse looking up demographics (in scope)
    print("\n" + "=" * 70)
    print("SCENARIO 1: Nurse looks up patient demographics (SHOULD PASS)")
    print("=" * 70)
    run_agent("Look up demographics for patient P-12345")

    # Scenario 2: Blocked by scope_mappings — nurse trying to access billing
    # RBACGuard resolves query_type="billing" → scope "billing"
    # nurse.allowed_data_scopes does NOT include "billing" → BLOCKED at fast tier
    print("\n" + "=" * 70)
    print("SCENARIO 2: Nurse tries to access billing data (SHOULD BE BLOCKED)")
    print("=" * 70)
    run_agent("Show me the billing records for patient P-12345")

    # Scenario 3: Blocked by tool allowlist — nurse trying to use billing_query tool
    # nurse.allowed_tools does NOT include "billing_query" → BLOCKED
    print("\n" + "=" * 70)
    print("SCENARIO 3: Nurse tries to use billing_query tool (SHOULD BE BLOCKED)")
    print("=" * 70)
    run_agent("Run a billing query for patient P-12345 for the last 3 months")

    # Scenario 4: Allowed — nurse updating vitals (in scope, in allowed_tools)
    print("\n" + "=" * 70)
    print("SCENARIO 4: Nurse updates patient vitals (SHOULD PASS)")
    print("=" * 70)
    run_agent("Record vitals for patient P-12345: BP 120/80, HR 72, temp 98.6")
