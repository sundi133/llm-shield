"""In-sandbox agent runtime — cooperative L1 checks + the L3 cap request flow.

Runs INSIDE the sandbox, as part of the trusted orchestration loop
(docs/sandbox-guardrails-design.md §2, mixed trust). Everything here is
cooperative: it guards the loop's own calls with near-zero friction, but
nothing in this module is load-bearing for security. The hard boundaries
live outside the sandbox — the broker holds the tenant key (L0,
examples/sandbox/broker.py), the egress gateway screens LLM I/O (L2), and
the tool executor verifies-and-burns caps (L3,
examples/sandbox/tool_executor.py).

The runtime holds exactly ONE credential — the instance-bound agent token
the broker injected at launch — and never the tenant key. Its env contract
is what the broker writes:

    SHIELD_AGENT_TOKEN        the only secret in the box (short TTL)
    SHIELD_BASE_URL           Shield deployment (cooperative checks + cap mint)
    SHIELD_AGENT_INSTANCE_ID  this sandbox's identity
    SHIELD_AGENT_ID           logical agent identity
    SHIELD_SESSION_ID         conversation/session id

Fail policy (spec §5): cooperative checks fail CLOSED by default, with the
existing SHIELD_FAIL_OPEN=1 escape hatch (same knob as
examples/mcp_server/server.py). The capability path has NO fail-open — a
mint that does not succeed is a denial, whatever the cause.

Spec: docs/spec-sandbox-guardrails.md (task 3).

Usage (inside the sandbox):

    runtime = SandboxRuntime.from_env()

    # L1 — guard the loop's own work cooperatively
    await runtime.check_tool("search_kb", {"q": q}, user_role="analyst")
    await runtime.screen_input({"q": q})

    # L3 — side effects: mint a single-use cap, hand it to the executor
    result = await runtime.guarded_tool_call(
        mcp_call, "send_email",
        {"to": "u1@acme.com", "subject": subj, "body": body},
        resource="u1@acme.com",
    )
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import time
from typing import Any, Callable, Optional, Sequence, Union

import httpx

try:  # repo layout: pytest / scripts run from the repo root
    from examples.mcp_server.shield_guard import Blocked, ShieldGuard  # noqa: F401
    from examples.shield_client import AgentToken, Capability
except ImportError:  # folder copied standalone next to the helpers
    from shield_client import AgentToken, Capability  # type: ignore
    from shield_guard import Blocked, ShieldGuard  # type: ignore  # noqa: F401


_TRUTHY = ("1", "true", "yes", "on")


class CapDenied(Exception):
    """Shield did not mint the capability — the side effect must not happen.

    ``stage`` tells callers why:
      * ``policy`` — AuthZ said no (403). ``reasons`` is filled when the
        server runs with SHIELD_VERBOSE_REASONS; ``approval`` carries the
        HITL request (request_id, required_approvals, expires_at) when the
        tool needs a human sign-off first.
      * ``auth`` — the agent token was rejected (expired/revoked) and no
        remint hook recovered it.
      * ``unavailable`` — Shield unreachable or non-2xx. Never fail open.
    """

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        reasons: Sequence[str] = (),
        approval: Optional[dict] = None,
    ):
        super().__init__(message)
        self.stage = stage
        self.reasons = list(reasons)
        self.approval = approval


def _jwt_exp(token: str) -> Optional[float]:
    """Best-effort read of the token's ``exp`` claim. No verification —
    expiry is enforced server-side against a trusted clock (spec §7); this
    only schedules proactive re-mint."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        exp = claims.get("exp")
        return float(exp) if exp is not None else None
    except (IndexError, ValueError, TypeError, binascii.Error):
        return None


def _denial_from(r: httpx.Response) -> CapDenied:
    """Map a 403 mint response onto CapDenied, surfacing HITL approvals."""
    try:
        detail = r.json().get("detail")
    except ValueError:
        detail = None
    if not isinstance(detail, dict):
        detail = {"error": str(detail) if detail else r.text}
    if detail.get("reason") == "approval_required":
        return CapDenied(
            f"cap denied: human approval required (request {detail.get('request_id')})",
            stage="policy",
            approval=detail,
        )
    reasons = detail.get("reasons") or []
    message = "; ".join(reasons) or detail.get("error") or "authz denied"
    return CapDenied(f"cap denied: {message}", stage="policy", reasons=reasons)


class SandboxRuntime:
    """The trusted loop's handle on Shield from inside one sandbox instance."""

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        *,
        agent_id: str = "",
        agent_instance_id: str = "",
        session_id: str = "",
        fail_open: bool = False,
        remint: Optional[Callable[[], Union[str, AgentToken]]] = None,
        refresh_margin_seconds: float = 30.0,
        timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        if not base_url or not agent_token:
            raise ValueError("base_url and agent_token are required")
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_instance_id = agent_instance_id
        self.session_id = session_id
        self.remint = remint
        self.refresh_margin_seconds = refresh_margin_seconds
        # One shared client for guard + cap calls; injectable for tests.
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self.guard = ShieldGuard(
            base_url=self.base_url,
            agent_token=agent_token,
            agent_id=agent_id,
            fail_open=fail_open,
            client=self._client,
        )
        self._token = ""
        self._token_exp: Optional[float] = None
        self._set_token(agent_token)

    @classmethod
    def from_env(cls, environ=os.environ, **kwargs) -> "SandboxRuntime":
        """Build from the env the broker injected at launch. A sandbox that
        boots without its credential must not run at all (fail closed) — it
        would be an unregistered shadow agent with no identity to revoke."""
        base_url = environ.get("SHIELD_BASE_URL", "").strip()
        agent_token = environ.get("SHIELD_AGENT_TOKEN", "").strip()
        if not base_url or not agent_token:
            raise RuntimeError(
                "SHIELD_BASE_URL and SHIELD_AGENT_TOKEN are missing — the broker "
                "injects them at launch (examples/sandbox/broker.py); refusing "
                "to run ungoverned"
            )
        kwargs.setdefault(
            "fail_open",
            environ.get("SHIELD_FAIL_OPEN", "").strip().lower() in _TRUTHY,
        )
        return cls(
            base_url,
            agent_token,
            agent_id=environ.get("SHIELD_AGENT_ID", ""),
            agent_instance_id=environ.get("SHIELD_AGENT_INSTANCE_ID", ""),
            session_id=environ.get("SHIELD_SESSION_ID", ""),
            **kwargs,
        )

    # ── token lifecycle ─────────────────────────────────────────────

    @property
    def token(self) -> str:
        return self._token

    def _set_token(self, token: Union[str, AgentToken]) -> None:
        raw = token.token if isinstance(token, AgentToken) else str(token)
        self._token = raw
        self._token_exp = _jwt_exp(raw)
        self.guard.agent_token = raw  # keep L1 checks on the fresh credential

    def needs_refresh(self) -> bool:
        if self._token_exp is None:
            return False
        return time.time() >= self._token_exp - self.refresh_margin_seconds

    async def _refresh_now(self) -> None:
        """Re-mint through the broker. The tenant key lives outside the
        sandbox, so ``remint`` is the customer's channel back to the broker
        (e.g. a broker-side endpoint that re-runs SandboxBroker.mint_token
        for this instance, spec §7). Without a hook the token simply ages
        out and Shield starts refusing — fail closed."""
        new = self.remint()
        if hasattr(new, "__await__"):
            new = await new
        self._set_token(new)

    async def ensure_fresh_token(self) -> None:
        if self.remint is not None and self.needs_refresh():
            await self._refresh_now()

    # ── L3: the cap request flow ────────────────────────────────────

    async def request_cap(
        self,
        tool: str,
        resource: str,
        *,
        scope_constraints: Optional[Sequence[str]] = None,
        clearance_max: str = "public",
        ttl_seconds: int = 30,
        data_scope: Optional[str] = None,
        tool_params: Optional[dict] = None,
        approval_grant: Optional[str] = None,
    ) -> Capability:
        """Ask Shield to authorize ONE side-effecting call.

        Auth is the agent token alone. The decision (role, tools, scopes)
        runs server-side against the token's verified claims — nothing the
        sandbox sends here can widen it. Raises CapDenied on anything but a
        minted cap."""
        await self.ensure_fresh_token()
        body: dict = {
            "tool": tool,
            "resource": resource,
            "clearance_max": clearance_max,
            "ttl_seconds": ttl_seconds,
            "scope_constraints": list(scope_constraints or []),
        }
        if data_scope:
            body["data_scope"] = data_scope
        if tool_params is not None:
            body["tool_params"] = tool_params
        if approval_grant:
            body["approval_grant"] = approval_grant
        if self.session_id:
            body["session_id"] = self.session_id

        r = await self._mint_once(body)
        if r.status_code == 401 and self.remint is not None:
            # Token aged out mid-task: re-mint once through the broker, retry.
            await self._refresh_now()
            r = await self._mint_once(body)

        if r.status_code == 401:
            raise CapDenied(f"agent token rejected: {r.text}", stage="auth")
        if r.status_code == 403:
            raise _denial_from(r)
        if r.status_code // 100 != 2:
            raise CapDenied(f"cap mint HTTP {r.status_code}", stage="unavailable")
        data = r.json()
        return Capability(
            cap_token=data["cap_token"],
            expires_in=data["expires_in"],
            decision=data["decision"],
        )

    async def _mint_once(self, body: dict) -> httpx.Response:
        try:
            return await self._client.post(
                f"{self.base_url}/v1/shield/cap/mint",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Agent-Token": self._token,
                },
            )
        except httpx.HTTPError as e:
            raise CapDenied(f"cap mint unavailable: {e}", stage="unavailable")

    async def guarded_tool_call(
        self,
        call: Callable[[str, dict], Any],
        tool: str,
        params: dict,
        *,
        resource: str,
        **mint_kwargs,
    ) -> Any:
        """Mint-then-invoke for the executor path: request a single-use cap
        for exactly (tool, resource), then hand it to ``call`` — typically
        an MCP tool invocation on the tool executor, which re-verifies and
        burns it OUTSIDE the sandbox. A denial raises before ``call`` runs;
        the executor never sees an unauthorized request from this loop."""
        cap = await self.request_cap(
            tool, resource, tool_params=params, **mint_kwargs
        )
        result = call(tool, {"cap_token": cap.cap_token, **dict(params)})
        if hasattr(result, "__await__"):
            result = await result
        return result

    # ── L1: cooperative checks (session-aware ShieldGuard passthrough) ──

    async def check_tool(
        self, tool_name: str, tool_params: Optional[dict] = None, *, user_role: str = ""
    ) -> None:
        await self.guard.check_rbac(tool_name, tool_params, user_role, self.session_id)

    async def screen_input(self, args: dict) -> None:
        await self.guard.screen_input(args)

    async def sanitize_output(self, tool_name: str, output: Any) -> Any:
        return await self.guard.sanitize_output(tool_name, output, self.session_id)

    async def aclose(self) -> None:
        await self._client.aclose()
