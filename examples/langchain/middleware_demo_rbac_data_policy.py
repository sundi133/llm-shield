#!/usr/bin/env python3
"""RBAC + data policies for tools.

Extends VotalAIGuardrail so a tool call is: (1) RBAC-checked by role, then
(2) its OUTPUT is run through Shield's data-policy sanitizer (/v1/shield/tool/output)
before the agent ever sees it. Shows a forbidden tool blocked, and a sensitive
tool result sanitized/redacted.

Env: LLM_SHIELD_URL/SHIELD_URL, TENANT_API_KEY/API_KEY, RUNPOD_TOKEN (if proxied)
Run: python3 examples/langchain/middleware_demo_rbac_data_policy.py
"""
import os, sys, requests
sys.path.insert(0, os.path.dirname(__file__))
from langchain_core.messages import ToolMessage
from langchain.agents.middleware.types import ToolCallRequest
from votalai_middleware import VotalAIGuardrail

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL") or "").rstrip("/")
KEY = os.getenv("TENANT_API_KEY") or os.getenv("API_KEY") or ""
TOK = os.getenv("RUNPOD_TOKEN", "")
AGENT = os.getenv("AGENT_ID", "lc-rbac-dp-demo")
if not SHIELD or not KEY:
    sys.exit("set LLM_SHIELD_URL and TENANT_API_KEY")

_p = _f = 0
def ok(n): global _p; _p += 1; print(f"  PASS {n}")
def no(n, d=""): global _f; _f += 1; print(f"  FAIL {n}  {d}")

H = {"X-API-Key": KEY, "Content-Type": "application/json"}
if TOK: H["Authorization"] = f"Bearer {TOK}"
requests.post(f"{SHIELD}/v1/agents/registry", headers=H, json={
    "agent_id": AGENT, "tools": ["lookup_customer", "delete_account"],
    "role_permissions": {"support": ["lookup_customer"]},   # no delete for support
}, timeout=20)


class VotalToolDataPolicy(VotalAIGuardrail):
    """RBAC check -> run tool -> sanitize the tool OUTPUT via Shield data policy."""

    def wrap_tool_call(self, request: ToolCallRequest, handler):
        name = request.tool_call.get("name", "")
        # 1) RBAC
        try:
            r = self._s.post(f"{self.shield}/v1/shield/tool/check",
                             json={"agent_key": self.agent_key, "tool_name": name,
                                   "tool_params": request.tool_call.get("args", {}),
                                   "user_role": self.user_role}, timeout=15).json()
            allowed = r.get("allowed", True) and r.get("action") != "block"
        except Exception:
            allowed = True
        if not allowed:
            return ToolMessage(content=f"BLOCKED by Votal Shield: {r.get('message','not permitted')}",
                               tool_call_id=request.tool_call.get("id", ""), name=name)
        # 2) execute
        result = handler(request)
        # 3) data-policy sanitize the tool OUTPUT
        try:
            d = self._s.post(f"{self.shield}/v1/shield/tool/output",
                             json={"tool_name": name, "tool_output": str(result.content),
                                   "agent_key": self.agent_key}, timeout=15).json()
            if d.get("action") == "block":
                return ToolMessage(content="[tool output BLOCKED by data policy]",
                                   tool_call_id=request.tool_call.get("id", ""), name=name)
            san = d.get("sanitized_output")
            if san is not None and san != str(result.content):
                return ToolMessage(content=san, tool_call_id=request.tool_call.get("id", ""), name=name)
        except Exception:
            pass
        return result

g = VotalToolDataPolicy(agent_key=AGENT, user_role="support")

def run(tool, output):
    req = ToolCallRequest(tool_call={"name": tool, "args": {}, "id": "1"},
                          tool=None, state={"messages": []}, runtime=None)
    return str(g.wrap_tool_call(req, lambda r: ToolMessage(content=output, tool_call_id="1", name=tool)).content)

print("\n=== RBAC ===")
ok("support BLOCKED from delete_account") if run("delete_account", "x").startswith("BLOCKED") else no("delete not blocked")

print("\n=== data policy on tool output ===")
SENSITIVE = "Customer 4111 1111 1111 1111, SSN 123-45-6789, key sk-abc123XYZ"
out = run("lookup_customer", SENSITIVE)
ok("allowed tool ran") if out and not out.startswith("BLOCKED") else no("allowed tool blocked unexpectedly", out[:80])
redacted = ("4111 1111 1111 1111" not in out) or ("[" in out) or ("*" in out)
ok("sensitive tool output sanitized by data policy") if redacted else no(
    "tool output not sanitized (does the tenant have a data policy for cards/secrets?)", out[:90])

print(f"\nPASS={_p}  FAIL={_f}")
sys.exit(1 if _f else 0)
