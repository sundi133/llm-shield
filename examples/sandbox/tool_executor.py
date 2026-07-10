"""Cap-gated tool executor — the L3 enforcement point for sandboxed agents.

Runs OUTSIDE the sandbox, in the customer's trusted plane. Side-effecting
tools (send_email, delete_account, db writes...) execute only here; the
sandbox can *request* an action but cannot *perform* it. Every execution
requires a single-use capability that Shield minted for exactly this tool
and resource (`/v1/shield/cap/mint`, policy-gated by the sandbox's agent
token) and that this executor verifies — and burns — before running
anything (`/v1/shield/cap/verify`).

Security contract (docs/spec-sandbox-guardrails.md §5):

* **Fail closed, no exceptions.** There is deliberately no ``fail_open``
  option here. Shield unreachable, non-2xx, invalid/replayed/mismatched
  cap — the tool does not run.
* ``expected_tool`` comes from this executor's own registration, and
  ``expected_resource`` from the actual call parameters — never from
  anything the sandbox claims. A cap minted for tool A / resource X can
  neither run tool B nor act on resource Y.
* Cap verification needs NO secret (bearer-of-cap). The tenant API key is
  optional and used ONLY for result DLP (`/v1/shield/tool/output`);
  configure it in production so results are sanitized before returning
  into the sandbox.

Exposed as a guarded MCP server (spec §10 recommendation) via
``build_demo_server()`` — the sandbox speaks one protocol for both the
guarded upstream and the executor.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Awaitable, Callable, Optional

import httpx

MAX_OUTPUT_CHARS = 50_000


class Denied(Exception):
    """The executor refused to run a tool.

    ``stage`` is one of ``verify`` | ``unknown_tool`` | ``output`` so callers
    can tell a capability rejection from a data-policy block. Transport
    failures surface as the stage they interrupted (fail closed)."""

    def __init__(self, message: str, *, stage: str):
        super().__init__(message)
        self.stage = stage


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Awaitable[Any]]
    # Name of the call parameter that identifies the resource the cap must be
    # scoped to (e.g. "account_id"). When set, the cap is verified against the
    # actual parameter value; when None, only the tool binding is enforced and
    # resource scoping relies on the mint-side policy alone.
    resource_arg: Optional[str] = None


class CapGatedExecutor:
    """Verify-then-execute for one registry of real tools.

    Construct once, ``register_tool`` each real tool body, then serve
    ``execute`` to sandboxes (directly or through the MCP wrapper below).
    """

    def __init__(
        self,
        base_url: str,
        *,
        tenant_key: str = "",
        auth_token: str = "",
        timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.tenant_key = tenant_key
        self.auth_token = auth_token
        # Injectable for tests (MockTransport / ASGITransport).
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._tools: dict[str, ToolSpec] = {}

    # ── registry ─────────────────────────────────────────────────────

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Awaitable[Any]],
        *,
        resource_arg: Optional[str] = None,
    ) -> None:
        self._tools[name] = ToolSpec(name=name, fn=fn, resource_arg=resource_arg)

    # ── the gate ─────────────────────────────────────────────────────

    async def verify_cap(
        self,
        cap_token: str,
        expected_tool: str,
        expected_resource: Optional[str] = None,
    ) -> dict:
        """Verify + burn the cap. Returns the cap claims on success.

        Bearer-of-cap: no tenant key is sent. Any deviation — transport
        error, non-2xx, ``valid != true`` — is a Denied. Never fail open."""
        body: dict = {
            "cap_token": cap_token,
            "expected_tool": expected_tool,
            "burn_nonce": True,
        }
        if expected_resource is not None:
            body["expected_resource"] = expected_resource
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            r = await self._client.post(
                f"{self.base_url}/v1/shield/cap/verify", json=body, headers=headers
            )
        except httpx.HTTPError as e:
            raise Denied(f"cap verify unavailable: {e}", stage="verify")
        if r.status_code // 100 != 2:
            raise Denied(f"cap verify HTTP {r.status_code}", stage="verify")
        data = r.json()
        if not data.get("valid"):
            raise Denied(
                f"cap rejected: {data.get('error', 'invalid')}", stage="verify"
            )
        return data.get("claims") or {}

    async def sanitize_output(self, tool_name: str, output: Any) -> str:
        """Result DLP before anything returns into the sandbox.

        Runs only when a tenant key is configured; a DLP block or a DLP
        transport failure withholds the result (fail closed)."""
        text = str(output)[:MAX_OUTPUT_CHARS]
        if not self.tenant_key:
            return text
        headers = {"Content-Type": "application/json", "X-API-Key": self.tenant_key}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            r = await self._client.post(
                f"{self.base_url}/v1/shield/tool/output",
                json={"tool_name": tool_name, "tool_output": text},
                headers=headers,
            )
        except httpx.HTTPError as e:
            raise Denied(f"output DLP unavailable: {e}", stage="output")
        if r.status_code // 100 != 2:
            raise Denied(f"output DLP HTTP {r.status_code}", stage="output")
        data = r.json()
        if data.get("action") == "block":
            raise Denied(
                data.get("message") or "output blocked by data policy",
                stage="output",
            )
        return data.get("sanitized_output", text)

    async def execute(self, tool_name: str, cap_token: str, params: dict) -> str:
        """The full L3 path: verify (and burn) the cap, run the real tool,
        DLP-sanitize the result. The tool body is only awaited after the cap
        for exactly this tool + resource verified."""
        spec = self._tools.get(tool_name)
        if spec is None:
            raise Denied(f"unknown tool {tool_name!r}", stage="unknown_tool")
        expected_resource = (
            str(params[spec.resource_arg])
            if spec.resource_arg and spec.resource_arg in params
            else None
        )
        await self.verify_cap(cap_token, tool_name, expected_resource)
        result = await spec.fn(**params)
        return await self.sanitize_output(tool_name, result)

    async def aclose(self) -> None:
        await self._client.aclose()


# ── MCP wrapper (reference deployment) ──────────────────────────────
# The executor is exposed as an MCP server so the sandbox speaks one
# protocol. Replace the demo tool bodies with your real side effects; the
# cap gate stays the same. `mcp` is imported lazily so the core above is
# testable without the MCP runtime.


def build_demo_server(executor: CapGatedExecutor, *, port: int = 8100):
    from mcp.server.fastmcp import FastMCP

    async def _send_email(to: str, subject: str, body: str) -> str:
        return f"[email] sent to {to!r} subject={subject!r}"

    async def _delete_account(account_id: str) -> str:
        return f"[account] deleted {account_id}"

    executor.register_tool("send_email", _send_email, resource_arg="to")
    executor.register_tool("delete_account", _delete_account, resource_arg="account_id")

    mcp = FastMCP(
        "votal-sandbox-executor",
        host="0.0.0.0",
        port=port,
        stateless_http=True,
        json_response=True,
    )

    async def _run(tool: str, cap_token: str, params: dict) -> str:
        try:
            return await executor.execute(tool, cap_token, params)
        except Denied as d:
            return f"DENIED by Votal Shield [{d.stage}]: {d}"

    @mcp.tool()
    async def send_email(cap_token: str, to: str, subject: str, body: str) -> str:
        """Send an email. Requires a cap minted for tool=send_email, resource=<to>."""
        return await _run(
            "send_email", cap_token, {"to": to, "subject": subject, "body": body}
        )

    @mcp.tool()
    async def delete_account(cap_token: str, account_id: str) -> str:
        """Delete an account. Requires a cap minted for tool=delete_account,
        resource=<account_id>."""
        return await _run("delete_account", cap_token, {"account_id": account_id})

    return mcp


if __name__ == "__main__":
    import os

    shield_url = os.environ.get("SHIELD_URL", "").rstrip("/")
    if not shield_url:
        raise SystemExit("Set SHIELD_URL (and SHIELD_TENANT_KEY for result DLP).")
    executor = CapGatedExecutor(
        shield_url,
        tenant_key=os.environ.get("SHIELD_TENANT_KEY", ""),
        auth_token=os.environ.get("RUNPOD_TOKEN", ""),
    )
    build_demo_server(
        executor, port=int(os.environ.get("PORT", "8100"))
    ).run(transport="streamable-http")
