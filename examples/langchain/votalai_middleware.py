"""VotalAIGuardrail — one LangChain middleware for Shield input/output/tool guardrails.

Drop-in for LangChain's create_agent(middleware=[...]). Replaces several separate
guardrail middlewares with a single line backed by Votal Shield:

    from langchain.agents import create_agent
    from votalai_middleware import VotalAIGuardrail

    agent = create_agent(
        model="gpt-5.5",
        tools=[search_tool, send_email_tool],
        middleware=[VotalAIGuardrail()],          # input + output + tool RBAC
    )

What it does (per the agent loop):
  - before_model : run the user message through Shield input guardrails
                   (prompt-injection, PII, toxicity). Unsafe -> stop with a refusal.
  - after_model  : run the model reply through Shield output guardrails
                   (leakage/PII). Sanitize, or block.
  - wrap_tool_call: check each tool call against Shield RBAC + kill switch.
                    Not allowed -> return a blocked ToolMessage (tool never runs).

Config (constructor args or env):
  shield_url   = LLM_SHIELD_URL / SHIELD_URL        (required)
  api_key      = TENANT_API_KEY / API_KEY           (required)
  runpod_token = RUNPOD_TOKEN                        (if Shield is behind a proxy)
  agent_key, user_role                               (for tool RBAC)
  check_tools=True, check_input=True, check_output=True
"""

from __future__ import annotations

import os
import requests

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage


class VotalAIGuardrail(AgentMiddleware):
    """Shield guardrails (input + output + tool RBAC) as one middleware."""

    def __init__(
        self,
        shield_url: str | None = None,
        api_key: str | None = None,
        runpod_token: str | None = None,
        agent_key: str = "langchain-agent",
        user_role: str = "user",
        check_input: bool = True,
        check_output: bool = True,
        check_tools: bool = True,
        block_message: str = "I can't help with that request.",
    ) -> None:
        super().__init__()
        self.shield = (shield_url or os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL") or "").rstrip("/")
        self.api_key = api_key or os.getenv("TENANT_API_KEY") or os.getenv("API_KEY") or ""
        token = runpod_token if runpod_token is not None else os.getenv("RUNPOD_TOKEN", "")
        if not self.shield or not self.api_key:
            raise ValueError("VotalAIGuardrail needs shield_url and api_key (or LLM_SHIELD_URL / TENANT_API_KEY env)")
        self.agent_key, self.user_role = agent_key, user_role
        self.check_input, self.check_output, self.check_tools = check_input, check_output, check_tools
        self.block_message = block_message
        self._s = requests.Session()
        self._s.headers.update({"X-API-Key": self.api_key, "Content-Type": "application/json"})
        if token:
            self._s.headers["Authorization"] = f"Bearer {token}"

    # ── input ──────────────────────────────────────────────────────────
    def before_model(self, state, runtime):
        if not self.check_input:
            return None
        msgs = state["messages"]
        last = next((m for m in reversed(msgs) if isinstance(m, HumanMessage)), None)
        if not last or not last.content:
            return None
        try:
            r = self._s.post(f"{self.shield}/guardrails/input",
                             json={"message": str(last.content)}, timeout=15).json()
        except Exception:
            return None  # fail-open on transport errors; Shield logs the gap
        if r.get("safe") is False:
            why = ", ".join(g.get("guardrail") for g in r.get("guardrail_results", []) if not g.get("passed"))
            # short-circuit the agent with a refusal as the final answer
            return {"jump_to": "end",
                    "messages": [AIMessage(content=f"{self.block_message} [blocked: {why}]")]}
        return None

    # ── output ─────────────────────────────────────────────────────────
    def after_model(self, state, runtime):
        if not self.check_output:
            return None
        msgs = state["messages"]
        last = msgs[-1] if msgs else None
        if not isinstance(last, AIMessage) or not last.content:
            return None
        try:
            r = self._s.post(f"{self.shield}/guardrails/output",
                             json={"output": str(last.content)}, timeout=15).json()
        except Exception:
            return None
        if r.get("safe") is False:
            return {"messages": [AIMessage(content=self.block_message, id=last.id)]}
        sanitized = r.get("sanitized_output")
        if sanitized and sanitized != last.content:
            # overwrite the message in place (same id => add_messages replaces it)
            return {"messages": [AIMessage(content=sanitized, id=last.id,
                                           tool_calls=getattr(last, "tool_calls", []) or [])]}
        return None

    # ── tool RBAC + kill switch ────────────────────────────────────────
    def wrap_tool_call(self, request: ToolCallRequest, handler):
        if not self.check_tools:
            return handler(request)
        name = request.tool_call.get("name", "")
        try:
            r = self._s.post(f"{self.shield}/v1/shield/tool/check",
                             json={"agent_key": self.agent_key, "tool_name": name,
                                   "tool_params": request.tool_call.get("args", {}),
                                   "user_role": self.user_role},
                             timeout=15).json()
            allowed = r.get("allowed", True) and r.get("action") != "block"
        except Exception:
            allowed = True  # fail-open on transport errors
        if not allowed:
            reason = r.get("message") or "not permitted by policy"
            return ToolMessage(content=f"BLOCKED by Votal Shield: {reason}",
                               tool_call_id=request.tool_call.get("id", ""), name=name)
        return handler(request)
