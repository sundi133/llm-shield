"""Votal Shield guard helpers for an MCP server — httpx only, no MCP runtime.

This module is deliberately free of any `mcp`/FastMCP import so it can be unit
tested (and reused) without the server runtime. It wraps the three Shield calls
that guard a single tool invocation:

    check_rbac       -> POST /v1/shield/tool/check     (role -> tool authorization)
    screen_input     -> POST /guardrails/input         (argument content screening)
    sanitize_output  -> POST /v1/shield/tool/output    (result PII/data sanitization)

plus a one-shot ``register_agent`` (POST /v1/agents/registry) for boot-time policy
registration.

Fail policy: by default the guard **fails closed** — if Shield is unreachable or
returns a non-2xx, the tool call is blocked. Set ``fail_open=True`` (env
``SHIELD_FAIL_OPEN=1`` in server.py) to allow calls through when Shield is down,
matching Shield's own middleware default. Choose per your risk tolerance.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Optional

import httpx

# Shield caps request sizes server-side; we also cap locally to keep payloads sane.
MAX_INPUT_CHARS = 20_000
MAX_OUTPUT_CHARS = 50_000


class Blocked(Exception):
    """Raised when Shield blocks a tool call at some stage.

    ``stage`` is one of ``rbac`` | ``input`` | ``output`` | ``unavailable`` so
    callers can tell an authorization denial from a content block from a
    transport failure.
    """

    def __init__(self, message: str, *, stage: str):
        super().__init__(message)
        self.stage = stage


class _Unavailable(Exception):
    """Internal: a non-2xx response from Shield (treated as a transport failure)."""


class ShieldGuard:
    """Guards one MCP tool call through Votal Shield.

    Holds the tenant key + agent identity and a shared async HTTP client. All
    request-screening methods are coroutines. Construct once at server start and
    reuse across requests (the client is concurrency-safe).
    """

    def __init__(
        self,
        *,
        base_url: str,
        tenant_key: str,
        agent_id: str,
        auth_token: str = "",
        fail_open: bool = False,
        timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        if not base_url or not tenant_key:
            raise ValueError("base_url and tenant_key are required")
        self.base_url = base_url.rstrip("/")
        self.tenant_key = tenant_key
        self.agent_id = agent_id
        self.auth_token = auth_token
        self.fail_open = fail_open
        # Injectable for tests (httpx.MockTransport); real server passes none.
        self._client = client or httpx.AsyncClient(timeout=timeout)

    # ── internals ────────────────────────────────────────────────────

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "X-API-Key": self.tenant_key}
        if self.auth_token:  # RunPod / reverse-proxy bearer, if the deploy needs it
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    async def _post(self, path: str, body: dict, *, stage: str) -> Optional[dict]:
        """POST to Shield. Returns parsed JSON, or ``None`` when Shield is
        unavailable AND we're configured fail-open (caller then allows)."""
        try:
            r = await self._client.post(
                f"{self.base_url}{path}", json=body, headers=self._headers()
            )
            if r.status_code // 100 != 2:
                raise _Unavailable(f"HTTP {r.status_code}")
            return r.json()
        except (httpx.HTTPError, _Unavailable) as e:
            if self.fail_open:
                return None
            raise Blocked(f"Shield unavailable at {stage}: {e}", stage="unavailable")

    @staticmethod
    def _reason(data: dict, default: str) -> str:
        """First failing guardrail's message, else the response message, else default."""
        for g in data.get("guardrail_results") or []:
            if not g.get("passed", True):
                return g.get("message") or default
        return data.get("message") or default

    # ── the three guard calls ────────────────────────────────────────

    async def check_rbac(
        self,
        tool_name: str,
        tool_params: Optional[dict],
        user_role: str,
        session_id: Optional[str] = None,
    ) -> None:
        """Role -> tool authorization + input data policy. Raises Blocked if denied."""
        body: dict = {
            "agent_key": self.agent_id,
            "tool_name": tool_name,
            "tool_params": tool_params or {},
            "user_role": user_role or "",
        }
        if session_id:
            body["session_id"] = session_id
        data = await self._post("/v1/shield/tool/check", body, stage="rbac")
        if data is None:  # fail-open
            return
        if not (data.get("allowed", True) and data.get("action") != "block"):
            raise Blocked(
                self._reason(data, f"role '{user_role}' not permitted for '{tool_name}'"),
                stage="rbac",
            )

    async def screen_input(self, args: dict) -> None:
        """Content-screen the tool arguments. Raises Blocked if the input is unsafe."""
        text = json.dumps(args, default=str)[:MAX_INPUT_CHARS]
        data = await self._post("/guardrails/input", {"message": text}, stage="input")
        if data is None:  # fail-open
            return
        if data.get("action") == "block" or data.get("safe") is False:
            raise Blocked(self._reason(data, "input blocked by guardrails"), stage="input")

    async def sanitize_output(
        self, tool_name: str, output: Any, session_id: Optional[str] = None
    ) -> Any:
        """Sanitize a tool result. Returns (possibly redacted) output, or raises
        Blocked if the data policy blocks it outright."""
        text = str(output)[:MAX_OUTPUT_CHARS]
        body: dict = {
            "tool_name": tool_name,
            "tool_output": text,
            "agent_key": self.agent_id,
        }
        if session_id:
            body["session_id"] = session_id
        data = await self._post("/v1/shield/tool/output", body, stage="output")
        if data is None:  # fail-open: return the raw output unmodified
            return output
        if data.get("action") == "block":
            raise Blocked(self._reason(data, "output blocked by data policy"), stage="output")
        return data.get("sanitized_output", text)

    # ── orchestration ────────────────────────────────────────────────

    async def guard_call(
        self,
        *,
        tool_name: str,
        args: dict,
        user_role: str,
        session_id: Optional[str],
        run: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Full guarded tool call: RBAC -> input screen -> run -> output sanitize.

        ``run`` is an async callable that executes the real tool body and returns
        its raw output. It is only awaited if RBAC and input screening pass.
        """
        await self.check_rbac(tool_name, args, user_role, session_id)
        await self.screen_input(args)
        result = await run()
        return await self.sanitize_output(tool_name, result, session_id)

    async def aclose(self) -> None:
        await self._client.aclose()


def register_agent(
    *,
    base_url: str,
    tenant_key: str,
    agent_id: str,
    tools: list[str],
    role_permissions: dict[str, list[str]],
    auth_token: str = "",
    timeout: float = 20.0,
) -> dict:
    """Idempotently register this server's agent + role->tool policy with Shield.

    Synchronous (uses httpx.Client) so it can run at boot before the event loop
    or from a standalone ``register.py``. Returns Shield's JSON response. Raises
    httpx.HTTPStatusError on a hard failure — callers may choose to log-and-continue
    (an unregistered agent still RBAC-checks live and shows up as a shadow agent).
    """
    headers = {"Content-Type": "application/json", "X-API-Key": tenant_key}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    body = {
        "agent_id": agent_id,
        "tools": tools,
        "role_permissions": role_permissions,
    }
    with httpx.Client(timeout=timeout) as c:
        r = c.post(f"{base_url.rstrip('/')}/v1/agents/registry", json=body, headers=headers)
        r.raise_for_status()
        return r.json()
