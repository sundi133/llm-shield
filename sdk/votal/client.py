"""VotalShield — main SDK client for tool RBAC + data policy enforcement.

Handles:
  - Tool RBAC checks (/v1/shield/tool/check)
  - Tool output sanitization (/v1/shield/tool/output)
  - Agent registration (/v1/agents/registry)
  - LangChain/CrewAI/OpenAI tool wrapping
  - LangChain callback handler
"""

from __future__ import annotations

import functools
import json
import logging
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional

import requests

from votal.guard import ToolGuard, ToolGuardContext

logger = logging.getLogger("votal")


class VotalShield:
    """Votal Shield SDK client.

    Args:
        shield_url: Shield service URL (e.g., "https://shield.votal.ai")
        api_key: Tenant API key from the portal
        agent_id: Agent identifier (register in portal or via register_agent())
        user_role: Default user role for RBAC checks
        auth_token: Optional RunPod/proxy auth token
        timeout: HTTP request timeout in seconds
    """

    def __init__(
        self,
        shield_url: str,
        api_key: str,
        agent_id: str = "default-agent",
        user_role: str = "user",
        auth_token: str = "",
        timeout: float = 30.0,
    ):
        self.shield_url = shield_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_role = user_role
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": api_key,
            "X-Agent-Key": agent_id,
            "X-User-Role": user_role,
            "Content-Type": "application/json",
        })
        if auth_token:
            self._session.headers["Authorization"] = f"Bearer {auth_token}"

    # ── Core API calls ────────────────────────────────────────────

    def check_tool(
        self,
        tool_name: str,
        tool_input: dict = None,
        *,
        user_role: str = None,
        session_id: str = "",
    ) -> ToolGuard:
        """Pre-execution: check if this role can use this tool with these args.

        Returns a ToolGuard with allowed=True/False.
        """
        body = {
            "tool_name": tool_name,
            "tool_params": tool_input or {},
            "agent_key": self.agent_id,
            "user_role": user_role or self.user_role,
        }
        if session_id:
            body["session_id"] = session_id

        try:
            resp = self._session.post(
                f"{self.shield_url}/v1/shield/tool/check",
                json=body,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return ToolGuard(
                    allowed=data.get("allowed", True),
                    action=data.get("action", "pass"),
                    reason=self._extract_reason(data),
                    guardrail_results=data.get("guardrail_results", []),
                )
            else:
                logger.warning(f"Shield tool/check returned {resp.status_code}: {resp.text[:200]}")
                return ToolGuard(allowed=True, reason=f"Shield error {resp.status_code}, failing open")
        except requests.RequestException as e:
            logger.error(f"Shield tool/check failed: {e}")
            return ToolGuard(allowed=True, reason=f"Shield unreachable, failing open")

    def sanitize_output(
        self,
        tool_name: str,
        tool_output: str,
        *,
        session_id: str = "",
    ) -> dict:
        """Post-execution: sanitize tool output per data policies (mask/redact/block).

        Returns dict with 'sanitized_output' and 'action'.
        """
        body = {
            "tool_name": tool_name,
            "tool_output": tool_output,
            "agent_key": self.agent_id,
        }
        if session_id:
            body["session_id"] = session_id

        try:
            resp = self._session.post(
                f"{self.shield_url}/v1/shield/tool/output",
                json=body,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"Shield tool/output returned {resp.status_code}")
                return {"sanitized_output": tool_output, "action": "pass"}
        except requests.RequestException as e:
            logger.error(f"Shield tool/output failed: {e}")
            return {"sanitized_output": tool_output, "action": "pass"}

    def register_agent(
        self,
        tools: List[str],
        role_permissions: Dict[str, List[str]],
        *,
        name: str = "",
        description: str = "",
    ) -> dict:
        """Register this agent with Shield. Idempotent — safe to call on startup."""
        body = {
            "agent_id": self.agent_id,
            "name": name or self.agent_id,
            "description": description,
            "tools": tools,
            "role_permissions": role_permissions,
        }
        try:
            resp = self._session.post(
                f"{self.shield_url}/v1/agents/registry",
                json=body,
                timeout=self.timeout,
            )
            return resp.json()
        except requests.RequestException as e:
            logger.error(f"Agent registration failed: {e}")
            return {"error": str(e)}

    # ── Tool wrapping ─────────────────────────────────────────────

    def protect(self, tool_or_fn):
        """Decorator: wrap a LangChain @tool with Shield RBAC + sanitization.

        Usage:
            @shield.protect
            @tool
            def get_balance(customer_id: str) -> str:
                return db.query(customer_id)
        """
        return self._wrap_tool(tool_or_fn)

    def wrap_tools(self, tools: list) -> list:
        """Wrap a list of LangChain tools with Shield protection."""
        return [self._wrap_tool(t) for t in tools]

    def _wrap_tool(self, tool_obj):
        """Internal: wrap a LangChain tool's _run method."""
        original_run = getattr(tool_obj, "_run", None)
        if original_run is None:
            original_run = tool_obj.run

        tool_name = getattr(tool_obj, "name", tool_obj.__class__.__name__)
        shield = self

        @functools.wraps(original_run)
        def shielded_run(*args, **kwargs):
            # Build tool_input from args/kwargs, filtering out LangChain internals
            _LC_INTERNALS = {"run_manager", "config", "callbacks", "tags", "metadata"}
            tool_input = {k: v for k, v in kwargs.items()
                          if k not in _LC_INTERNALS and isinstance(v, (str, int, float, bool, list, dict, type(None)))}
            if args:
                schema = getattr(tool_obj, "args_schema", None)
                if schema:
                    props = list(schema.model_fields.keys()) if hasattr(schema, 'model_fields') else list(schema.schema().get("properties", {}).keys())
                    for i, arg in enumerate(args):
                        if i < len(props):
                            tool_input[props[i]] = arg

            # 1. RBAC check
            guard = shield.check_tool(tool_name, tool_input)
            if not guard.allowed:
                return f"DENIED by Shield: {guard.reason}"

            # 2. Execute original tool
            raw_output = original_run(*args, **kwargs)

            # 3. Sanitize output
            result = shield.sanitize_output(tool_name, str(raw_output))
            if result.get("action") == "block":
                return "[OUTPUT BLOCKED BY DATA POLICY]"
            return result.get("sanitized_output", str(raw_output))

        tool_obj._run = shielded_run
        return tool_obj

    # ── Context manager ───────────────────────────────────────────

    def tool_guard(self, tool_name: str, tool_input: dict = None) -> ToolGuardContext:
        """Context manager for manual tool guarding.

        Usage:
            with shield.tool_guard("get_balance", {"id": "C-123"}) as guard:
                if guard.allowed:
                    raw = get_balance("C-123")
                    result = guard.sanitize(raw)
        """
        return ToolGuardContext(self, tool_name, tool_input or {})

    # ── LangChain callback ────────────────────────────────────────

    def callback(self):
        """Create a LangChain callback handler that intercepts all tool calls.

        Usage:
            executor = AgentExecutor(
                agent=agent, tools=tools,
                callbacks=[shield.callback()],
            )
        """
        return VotalLangChainCallback(self)

    # ── Helpers ───────────────────────────────────────────────────

    def with_role(self, user_role: str) -> "VotalShield":
        """Return a copy of this client with a different user role."""
        new = VotalShield(
            shield_url=self.shield_url,
            api_key=self.api_key,
            agent_id=self.agent_id,
            user_role=user_role,
            timeout=self.timeout,
        )
        # Copy auth token if present
        auth = self._session.headers.get("Authorization")
        if auth:
            new._session.headers["Authorization"] = auth
        return new

    def health(self) -> bool:
        """Check if Shield is reachable."""
        try:
            resp = self._session.get(f"{self.shield_url}/health", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    @staticmethod
    def _extract_reason(data: dict) -> str:
        for gr in data.get("guardrail_results", []):
            if not gr.get("passed", True):
                return gr.get("message", "denied")
        return data.get("reason", "")


# ── LangChain Callback Handler ────────────────────────────────────


class VotalLangChainCallback:
    """LangChain callback that intercepts tool calls for Shield RBAC.

    This is a lightweight callback — it logs tool executions and can
    be used alongside shield.wrap_tools() for full protection, or
    standalone for audit-only mode.
    """

    def __init__(self, client: VotalShield):
        self.client = client

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        tool_name = serialized.get("name", "unknown")
        try:
            tool_input = json.loads(input_str) if isinstance(input_str, str) else input_str
        except (json.JSONDecodeError, TypeError):
            tool_input = {"raw_input": str(input_str)}

        guard = self.client.check_tool(tool_name, tool_input)
        if not guard.allowed:
            logger.warning(f"[Votal] Tool '{tool_name}' BLOCKED: {guard.reason}")
            raise PermissionError(f"Shield RBAC denied: {guard.reason}")
        logger.info(f"[Votal] Tool '{tool_name}' ALLOWED")

    def on_tool_end(self, output: str, **kwargs):
        pass  # Sanitization happens in wrap_tools, not here

    def on_tool_error(self, error: Exception, **kwargs):
        pass
