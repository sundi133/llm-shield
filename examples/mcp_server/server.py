"""A remote MCP server (FastMCP, streamable-HTTP) guarded by Votal Shield.

Every tool call is screened through Shield before and after it runs:

    resolve role (from request header) ->
        RBAC  (/v1/shield/tool/check)  ->
        input (/guardrails/input)      ->
        RUN THE TOOL                   ->
        output (/v1/shield/tool/output)-> sanitized result

Deploy anywhere that can host a long-running HTTP process (Railway, Fly, Render,
a container). The MCP endpoint is served at ``/mcp`` on ``$PORT``.

Required env: SHIELD_URL, SHIELD_TENANT_KEY.
See .env.example for the full list.
"""

import os
import uuid

from mcp.server.fastmcp import Context, FastMCP

from shield_guard import Blocked, ShieldGuard, register_agent

# ── config ───────────────────────────────────────────────────────────

SHIELD_URL = os.environ.get("SHIELD_URL", "").rstrip("/")
TENANT_KEY = os.environ.get("SHIELD_TENANT_KEY", "")
AGENT_ID = os.environ.get("AGENT_ID", "example-mcp-server")
AUTH_TOKEN = os.environ.get("RUNPOD_TOKEN", "")
FAIL_OPEN = os.environ.get("SHIELD_FAIL_OPEN", "") == "1"
# Fallback role when the request carries no identity header. Empty string is an
# unprivileged role in Shield — NEVER default this to "admin".
DEFAULT_ROLE = os.environ.get("SHIELD_DEFAULT_ROLE", "")

if not SHIELD_URL or not TENANT_KEY:
    raise SystemExit("Set SHIELD_URL and SHIELD_TENANT_KEY (see .env.example).")

# The role -> tool policy this server advertises. Registered with Shield at boot
# (when REGISTER_ON_BOOT=1) and enforced on every call via /v1/shield/tool/check.
ROLE_PERMISSIONS = {
    "reader":  ["search_knowledge_base"],
    "support": ["search_knowledge_base", "create_ticket"],
    "admin":   ["search_knowledge_base", "create_ticket", "delete_account"],
}
TOOLS = sorted({t for tools in ROLE_PERMISSIONS.values() for t in tools})

guard = ShieldGuard(
    base_url=SHIELD_URL,
    tenant_key=TENANT_KEY,
    agent_id=AGENT_ID,
    auth_token=AUTH_TOKEN,
    fail_open=FAIL_OPEN,
)

mcp = FastMCP(
    "votal-guarded-mcp",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", "8000")),
    stateless_http=True,   # each request is self-contained -> horizontally scalable
    json_response=True,
)

# ── role + session resolution ────────────────────────────────────────


def _role(ctx: Context) -> str:
    """Resolve the caller's role from the authenticated transport, NOT tool args.

    Demo: reads the ``X-User-Role`` header. In production, terminate a real
    identity here — validate a JWT/OIDC token from ``Authorization`` and derive
    the role from its verified claims. A plaintext ``X-User-Role`` is trusted
    only because your gateway/IdP set it; do not expose this server unauthenticated.
    """
    try:
        headers = ctx.request_context.request.headers
        role = headers.get("x-user-role")
        if role:
            return role
    except Exception:
        pass
    return DEFAULT_ROLE


def _session_id(ctx: Context) -> str:
    try:
        rid = ctx.request_context.request.headers.get("x-session-id")
        if rid:
            return rid
    except Exception:
        pass
    return f"sess-{uuid.uuid4().hex[:12]}"


async def _guarded(ctx: Context, tool_name: str, args: dict, run) -> str:
    """Run a tool body through the full Shield guard, returning text.

    On a block, returns a clear ``BLOCKED ...`` string so the MCP client sees the
    reason and the unsafe action never took effect."""
    try:
        result = await guard.guard_call(
            tool_name=tool_name,
            args=args,
            user_role=_role(ctx),
            session_id=_session_id(ctx),
            run=run,
        )
        return str(result)
    except Blocked as b:
        return f"BLOCKED by Votal Shield [{b.stage}]: {b}"


# ── demo tools ───────────────────────────────────────────────────────
# Replace the bodies with your real logic. The guard wrapping stays the same.


@mcp.tool()
async def search_knowledge_base(query: str, ctx: Context) -> str:
    """Search the knowledge base. Allowed for any role (reader+)."""
    async def run():
        return f"[kb] top results for {query!r}: article-12, article-47"
    return await _guarded(ctx, "search_knowledge_base", {"query": query}, run)


@mcp.tool()
async def create_ticket(subject: str, body: str, ctx: Context) -> str:
    """Open a support ticket. Requires the 'support' role or higher."""
    async def run():
        return f"[ticket] created TCK-1042 subject={subject!r}"
    return await _guarded(ctx, "create_ticket", {"subject": subject, "body": body}, run)


@mcp.tool()
async def delete_account(account_id: str, ctx: Context) -> str:
    """Delete a customer account. Restricted to the 'admin' role."""
    async def run():
        return f"[account] deleted {account_id}"
    return await _guarded(ctx, "delete_account", {"account_id": account_id}, run)


# ── boot ─────────────────────────────────────────────────────────────

if os.environ.get("REGISTER_ON_BOOT", "") == "1":
    try:
        register_agent(
            base_url=SHIELD_URL,
            tenant_key=TENANT_KEY,
            agent_id=AGENT_ID,
            tools=TOOLS,
            role_permissions=ROLE_PERMISSIONS,
            auth_token=AUTH_TOKEN,
        )
        print(f"[votal] registered agent {AGENT_ID!r} with {len(TOOLS)} tools")
    except Exception as e:  # non-fatal: unregistered -> shadow agent, still RBAC-checked
        print(f"[votal] registry write failed (continuing, shows as shadow agent): {e}")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
