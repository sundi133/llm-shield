#!/usr/bin/env python3
"""LangChain + LLM Shield — Single-Pane Architecture via LiteLLM

The developer hits ONE endpoint: LiteLLM.
LiteLLM internally handles everything via VotalGuardrail plugin:
  - Input guardrails (pre_call → Shield /guardrails/input)
  - LLM call (to configured model)
  - Output guardrails (post_call → Shield /guardrails/output)
  - Tool RBAC (post_call → Shield /v1/shield/tool/check)

The client receives tool_calls in standard OpenAI format.
Client executes only ALLOWED tools, sends results back for next turn.

Usage:
    export LITELLM_URL="https://litellm-guardrails-votal-ai-production.up.railway.app"
    export LITELLM_KEY="sk-my-master-key-..."
    export AGENT_ID="hr-helpdesk-agent"
    export USER_ROLE="nurse"
    export MODEL="moonshotai/kimi-k2.5"

    python shield_langchain_single_pane.py
"""

import json
import os
import time

import requests

# ---------------------------------------------------------------------------
# Config — ONE endpoint: LiteLLM (which calls Shield internally)
# ---------------------------------------------------------------------------

LITELLM_URL = os.getenv("LITELLM_URL", "https://litellm-guardrails-votal-ai-production.up.railway.app")
LITELLM_KEY = os.getenv("LITELLM_KEY", os.getenv("LITELLM_API_KEY", ""))
MODEL = os.getenv("MODEL", "moonshotai/kimi-k2.5")
AGENT_ID = os.getenv("AGENT_ID", "hr-helpdesk-agent")
USER_ROLE = os.getenv("USER_ROLE", "nurse")
TENANT_API_KEY = os.getenv("TENANT_API_KEY", "")  # tenant key for Shield policies
SESSION_ID = f"sess-{int(time.time())}"

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {LITELLM_KEY}",
    "Content-Type": "application/json",
    # NOTE: Do NOT send X-API-Key as a header — LiteLLM intercepts it as a
    # LiteLLM user key and rejects it with "No connected db." error.
    # Instead, pass tenant/agent identity in metadata (see chat() function).
})

# ---------------------------------------------------------------------------
# Tool definitions — sent to LiteLLM, forwarded to LLM
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
    """Execute a tool locally. Neither LiteLLM nor Shield run your tools."""
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
# Single-pane: call LiteLLM (which handles guardrails + tool RBAC via Shield)
# ---------------------------------------------------------------------------

def chat(messages: list[dict], tools: list[dict] | None = None) -> dict:
    """Call LiteLLM with guardrails enabled.

    LiteLLM's VotalGuardrail plugin handles:
      1. Input guardrails (pre_call → Shield)
      2. LLM call
      3. Output guardrails (post_call → Shield)
      4. Tool RBAC (post_call → Shield /v1/shield/tool/check)
    """
    body = {
        "model": MODEL,
        "messages": messages,
        "max_tokens": 1024,
        "temperature": 0.3,
        # Enable Votal guardrails
        "guardrails": ["votal-input-guard", "votal-output-guard"],
        # Pass tenant + agent identity in metadata (NOT headers — LiteLLM
        # intercepts X-API-Key as a LiteLLM user key). VotalGuardrail plugin
        # reads these and forwards to Shield as headers.
        "metadata": {
            "agent_key": AGENT_ID,
            "user_role": USER_ROLE,
            "tenant_api_key": TENANT_API_KEY,
        },
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    resp = session.post(f"{LITELLM_URL}/v1/chat/completions", json=body)

    if resp.status_code == 403 or resp.status_code == 400:
        # Guardrail blocked the request
        try:
            data = resp.json()
            error_msg = data.get("error", {}).get("message", "") if isinstance(data.get("error"), dict) else str(data.get("error", ""))
            return {"blocked": True, "block_reason": error_msg or resp.text}
        except Exception:
            return {"blocked": True, "block_reason": resp.text}

    if resp.status_code != 200:
        return {"error": f"LiteLLM returned {resp.status_code}: {resp.text}"}

    return resp.json()


def extract_tool_calls(response: dict) -> list[dict]:
    """Extract tool_calls from OpenAI-format response."""
    choices = response.get("choices", [])
    if not choices:
        return []

    message = choices[0].get("message", {})
    raw_calls = message.get("tool_calls") or []

    parsed = []
    for tc in raw_calls:
        func = tc.get("function", {})
        args_raw = func.get("arguments", "{}")
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw or {}
        except json.JSONDecodeError:
            args = {"_raw": args_raw}
        parsed.append({
            "tool_call_id": tc.get("id", ""),
            "tool_name": func.get("name", "unknown"),
            "arguments": args,
        })
    return parsed


def run_agent(user_message: str) -> str:
    """Run a full agent turn through LiteLLM (single-pane).

    Flow:
      1. Send user message + tools to LiteLLM
      2. LiteLLM runs input guardrails, calls LLM, runs output guardrails + tool RBAC
      3. Client receives standard OpenAI response with tool_calls
      4. Client executes tools locally
      5. Client sends tool results back to LiteLLM for next turn
    """
    print(f"\n{'=' * 70}")
    print(f"User: {user_message}")
    print(f"Role: {USER_ROLE} | Agent: {AGENT_ID} | Model: {MODEL}")
    print(f"{'=' * 70}")

    messages = [
        {"role": "system", "content": "You are a helpful healthcare assistant. Use tools when needed."},
        {"role": "user", "content": user_message},
    ]

    # --- Turn 1: LiteLLM handles guardrails + LLM + tool RBAC ---
    response = chat(messages, tools=TOOLS)

    if response.get("blocked"):
        reason = response.get("block_reason", "blocked")
        print(f"  [BLOCKED BY GUARDRAIL] {reason}")
        return f"Blocked: {reason}"

    if response.get("error"):
        print(f"  [ERROR] {response['error']}")
        return response["error"]

    # Extract text and tool calls from standard OpenAI response
    text = ""
    choices = response.get("choices", [])
    if choices:
        text = choices[0].get("message", {}).get("content") or ""

    tool_calls = extract_tool_calls(response)

    # If no tool calls, return the text
    if not tool_calls:
        print(f"  Response: {text}")
        return text

    # --- Process tool calls ---
    print(f"\n  Tool calls from LLM ({len(tool_calls)} total):")

    # Build assistant message with tool_calls for next turn
    messages.append({
        "role": "assistant",
        "content": text or None,
        "tool_calls": [
            {"id": tc["tool_call_id"], "type": "function",
             "function": {"name": tc["tool_name"], "arguments": json.dumps(tc["arguments"])}}
            for tc in tool_calls
        ],
    })

    for tc in tool_calls:
        tool_name = tc["tool_name"]
        tool_args = tc["arguments"]
        tool_call_id = tc["tool_call_id"]

        # Execute the tool locally
        result = execute_tool(tool_name, tool_args)
        print(f"    [EXEC] {tool_name}({json.dumps(tool_args)}) -> {result}")
        messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        })

    # --- Turn 2: Send tool results back to LiteLLM ---
    print(f"\n  Sending tool results back for final response...")
    final_response = chat(messages)

    if final_response.get("blocked"):
        reason = final_response.get("block_reason", "blocked")
        print(f"  [OUTPUT BLOCKED] {reason}")
        return f"Output blocked: {reason}"

    final_text = ""
    choices = final_response.get("choices", [])
    if choices:
        final_text = choices[0].get("message", {}).get("content") or ""

    print(f"  Response: {final_text}")
    return final_text


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not LITELLM_KEY:
        print("WARNING: LITELLM_KEY not set — requests may be rejected")

    print(f"LiteLLM: {LITELLM_URL}")
    print(f"Model: {MODEL}")
    print(f"Agent: {AGENT_ID} | Role: {USER_ROLE}")
    print(f"Architecture: Single-pane (LiteLLM + VotalGuardrail handles everything)")

    # Scenario 1: Allowed — nurse looking up demographics
    print("\n" + "=" * 70)
    print("SCENARIO 1: Nurse looks up patient demographics (SHOULD PASS)")
    print("=" * 70)
    run_agent("Look up demographics for patient P-12345")

    # Scenario 2: Nurse tries to access billing (scope_mappings should block)
    print("\n" + "=" * 70)
    print("SCENARIO 2: Nurse tries to access billing data (SHOULD BE BLOCKED)")
    print("=" * 70)
    run_agent("Show me the billing records for patient P-12345")

    # Scenario 3: Nurse tries billing_query tool (tool allowlist should block)
    print("\n" + "=" * 70)
    print("SCENARIO 3: Nurse tries billing_query tool (SHOULD BE BLOCKED)")
    print("=" * 70)
    run_agent("Run a billing query for patient P-12345 for the last 3 months")

    # Scenario 4: Allowed — nurse updating vitals
    print("\n" + "=" * 70)
    print("SCENARIO 4: Nurse updates patient vitals (SHOULD PASS)")
    print("=" * 70)
    run_agent("Record vitals for patient P-12345: BP 120/80, HR 72, temp 98.6")
