#!/usr/bin/env python3
"""RBAC for tools — VotalAIGuardrail enforces role -> tool at the tool boundary.

Registers one agent with two roles (reader, admin) that own different tools, then
shows the SAME tool call allowed for one role and blocked for another. No model
needed (drives the wrap_tool_call hook directly).

Env: LLM_SHIELD_URL/SHIELD_URL, TENANT_API_KEY/API_KEY, RUNPOD_TOKEN (if proxied)
Run: python3 examples/langchain/middleware_demo_rbac.py
"""
import os, sys, requests
sys.path.insert(0, os.path.dirname(__file__))
from langchain_core.messages import ToolMessage
from langchain.agents.middleware.types import ToolCallRequest
from votalai_middleware import VotalAIGuardrail

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL") or "").rstrip("/")
KEY = os.getenv("TENANT_API_KEY") or os.getenv("API_KEY") or ""
TOK = os.getenv("RUNPOD_TOKEN", "")
AGENT = os.getenv("AGENT_ID", "lc-rbac-demo")
if not SHIELD or not KEY:
    sys.exit("set LLM_SHIELD_URL and TENANT_API_KEY")

_p = _f = 0
def ok(n): global _p; _p += 1; print(f"  PASS {n}")
def no(n, d=""): global _f; _f += 1; print(f"  FAIL {n}  {d}")

H = {"X-API-Key": KEY, "Content-Type": "application/json"}
if TOK: H["Authorization"] = f"Bearer {TOK}"

# one agent, two roles with different tool access
requests.post(f"{SHIELD}/v1/agents/registry", headers=H, json={
    "agent_id": AGENT,
    "tools": ["search", "get_account", "delete_account"],
    "role_permissions": {
        "reader": ["search", "get_account"],                       # no delete
        "admin":  ["search", "get_account", "delete_account"],     # full
    },
}, timeout=20)

def handler(req):
    return ToolMessage(content="EXECUTED", tool_call_id=req.tool_call.get("id", ""),
                       name=req.tool_call.get("name", ""))

def call(role, tool):
    g = VotalAIGuardrail(agent_key=AGENT, user_role=role)
    req = ToolCallRequest(tool_call={"name": tool, "args": {}, "id": "1"},
                          tool=None, state={"messages": []}, runtime=None)
    out = g.wrap_tool_call(req, handler)
    return str(out.content)

print("\n=== RBAC: role -> tool enforcement ===")
ok("reader may call search") if call("reader", "search") == "EXECUTED" else no("reader/search not allowed")
ok("reader BLOCKED from delete_account") if call("reader", "delete_account").startswith("BLOCKED") else no("reader/delete not blocked")
ok("admin may call delete_account") if call("admin", "delete_account") == "EXECUTED" else no("admin/delete not allowed")

print(f"\nPASS={_p}  FAIL={_f}")
sys.exit(1 if _f else 0)
