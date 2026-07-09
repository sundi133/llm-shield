#!/usr/bin/env python3
"""Agentic IdP at the tool boundary — identity + per-action capability tokens.

Extends VotalAIGuardrail into a full agent IdP: it mints a per-process agent
IDENTITY token, and for every tool call it mints a single-use CAPABILITY scoped
to that tool+resource and VERIFIES it (nonce burn) before the tool runs. RBAC
still applies. Shows: identity minted, allowed tool -> cap minted+verified+run,
forbidden tool -> blocked, capability replay -> rejected.

Env: LLM_SHIELD_URL/SHIELD_URL, TENANT_API_KEY/API_KEY, RUNPOD_TOKEN (if proxied)
Run: python3 examples/langchain/middleware_demo_idp.py
"""
import os, sys, requests
sys.path.insert(0, os.path.dirname(__file__))
from langchain_core.messages import ToolMessage
from langchain.agents.middleware.types import ToolCallRequest
from votalai_middleware import VotalAIGuardrail

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL") or "").rstrip("/")
KEY = os.getenv("TENANT_API_KEY") or os.getenv("API_KEY") or ""
TOK = os.getenv("RUNPOD_TOKEN", "")
AGENT = os.getenv("AGENT_ID", "lc-idp-demo")
if not SHIELD or not KEY:
    sys.exit("set LLM_SHIELD_URL and TENANT_API_KEY")

_p = _f = 0
def ok(n): global _p; _p += 1; print(f"  PASS {n}")
def no(n, d=""): global _f; _f += 1; print(f"  FAIL {n}  {d}")

H = {"X-API-Key": KEY, "Content-Type": "application/json"}
if TOK: H["Authorization"] = f"Bearer {TOK}"
requests.post(f"{SHIELD}/v1/agents/registry", headers=H, json={
    "agent_id": AGENT, "tools": ["search", "wire_money"],
    "role_permissions": {"user": ["search"]},   # user may NOT wire_money
}, timeout=20)


class VotalIdPGuardrail(VotalAIGuardrail):
    """Per-process agent identity + per-tool-call capability mint/verify."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        import uuid
        self.instance = f"{self.agent_key}-{uuid.uuid4().hex[:8]}"
        r = self._s.post(f"{self.shield}/v1/tenant/me/agent-auth/agent-token", json={
            "user_sub": "demo-user", "agent_id": self.agent_key,
            "agent_instance_id": self.instance, "build_hash": "demo",
            "model_version": "demo", "session_id": "demo", "ttl_seconds": 600}, timeout=20)
        self.agent_token = r.json().get("agent_token") if r.status_code == 200 else None

    def _cap_headers(self):
        h = {"X-API-Key": self.api_key, "Content-Type": "application/json", "X-Agent-Token": self.agent_token or ""}
        if "Authorization" in self._s.headers:
            h["Authorization"] = self._s.headers["Authorization"]
        return h

    def wrap_tool_call(self, request: ToolCallRequest, handler):
        name = request.tool_call.get("name", "")
        resource = f"{name}/{request.tool_call.get('id','')}"
        # mint a single-use capability scoped to this tool+resource
        m = requests.post(f"{self.shield}/v1/shield/cap/mint", headers=self._cap_headers(),
                          json={"tool": name, "resource": resource, "ttl_seconds": 30}, timeout=15)
        if m.status_code == 403:
            return ToolMessage(content=f"BLOCKED by Votal Shield: capability denied for '{name}'",
                               tool_call_id=request.tool_call.get("id", ""), name=name)
        cap = m.json().get("cap_token") if m.status_code == 200 else None
        if not cap:
            return ToolMessage(content="BLOCKED: could not mint capability",
                               tool_call_id=request.tool_call.get("id", ""), name=name)
        # verify (burns the single-use nonce) right before executing
        v = self._s.post(f"{self.shield}/v1/shield/cap/verify",
                         json={"cap_token": cap, "expected_tool": name, "burn_nonce": True}, timeout=15).json()
        if v.get("valid") is not True:
            return ToolMessage(content="BLOCKED: capability did not verify",
                               tool_call_id=request.tool_call.get("id", ""), name=name)
        self._last_cap = cap  # kept only to demonstrate replay rejection below
        return handler(request)

g = VotalIdPGuardrail(agent_key=AGENT, user_role="user")

print("\n=== agent identity ===")
ok("per-process agent identity token minted") if g.agent_token else no("identity token not minted")

def run(tool):
    req = ToolCallRequest(tool_call={"name": tool, "args": {}, "id": "1"},
                          tool=None, state={"messages": []}, runtime=None)
    return str(g.wrap_tool_call(req, lambda r: ToolMessage(content="EXECUTED", tool_call_id="1", name=tool)).content)

print("\n=== capability per tool call ===")
ok("allowed tool: cap minted+verified, then runs") if run("search") == "EXECUTED" else no("search not executed")
ok("forbidden tool blocked (capability denied)") if run("wire_money").startswith("BLOCKED") else no("wire_money not blocked")

print("\n=== single-use capability (replay) ===")
cap = getattr(g, "_last_cap", None)
if cap:
    v = requests.post(f"{SHIELD}/v1/shield/cap/verify", headers=H,
                      json={"cap_token": cap, "expected_tool": "search", "burn_nonce": True},
                      timeout=15).json()
    ok("replaying a used capability is rejected") if v.get("valid") is False else no("replay not rejected", str(v)[:80])
else:
    no("no capability captured to replay")

print(f"\nPASS={_p}  FAIL={_f}")
sys.exit(1 if _f else 0)
