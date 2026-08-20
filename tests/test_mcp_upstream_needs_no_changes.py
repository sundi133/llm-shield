"""An existing MCP server must work behind the gateway unmodified.

This is the load-bearing claim in the JumpCloud proposal: put Shield in front of
a server by changing a URL, and the server needs no code changes, no Shield SDK,
no awareness that it is being proxied. If that stops being true, the integration
story collapses, and it would collapse silently - the proxy would still work
against the fakes in test_mcp_proxy.py, which are permissive.

So the upstream here is STRICT. It rejects anything a real vendor MCP server
would not accept: unknown kwargs, injected argument keys, Shield metadata. A
leak fails the test rather than being quietly tolerated.

Scope: this covers what Shield sends UPSTREAM. What Shield returns DOWNSTREAM to
the caller is deliberately not identical (tools are filtered, and carry an
x-shield-risk annotation) - see test_downstream_tool_shape_is_additive_only.
"""
import asyncio
import inspect
import pathlib
import sys

import pytest

import guardrails.agentic.tool.tool_call_validation as _tcv
import guardrails.agentic.tool.tool_output_sanitization as _tos
from core.mcp.proxy_server import MCPProxy
from storage.tenant_store import kv_set

TENANT = "vanilla-upstream-tenant"
AGENT = "support-bot"


async def _no_issue(*a, **k):
    return None


async def _boom(*a, **k):
    raise RuntimeError("offline")


@pytest.fixture(autouse=True)
def _stub_llms(monkeypatch):
    monkeypatch.setattr(_tcv, "evaluate_payload_policy_llm", _no_issue)
    monkeypatch.setattr(_tos, "async_llm_call", _boom)


@pytest.fixture(autouse=True)
def _seed():
    kv_set(f"agents:{TENANT}", {
        AGENT: {
            "agent_id": AGENT,
            "tools": ["get_balance", "wire_transfer"],
            "role_permissions": {
                "admin": ["get_balance", "wire_transfer"],
                "support": ["get_balance"],
            },
            "status": "active",
        }
    })


class VanillaMCPServer:
    """A server written before Shield existed and never updated for it.

    Implements exactly the MCP surface and nothing else. Anything Shield-shaped
    that arrives is an error, because a real vendor server would reject it too.
    """

    SHIELD_MARKERS = ("shield", "x-shield", "_meta", "tenant", "agent_key",
                      "user_role", "workflow", "confirmation")

    def __init__(self):
        self.tool_calls = []
        self.list_calls = 0

    async def list_tools(self, *args, **kwargs):
        if args or kwargs:
            raise AssertionError(
                f"list_tools called with extra arguments: {args} {kwargs}. "
                "A stock MCP server takes none.")
        self.list_calls += 1
        return [
            {"name": "get_balance", "description": "read a balance",
             "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
            {"name": "wire_transfer", "description": "move money",
             "inputSchema": {"type": "object"}},
        ]

    async def call_tool(self, name, arguments, *args, **kwargs):
        if args or kwargs:
            raise AssertionError(
                f"call_tool got arguments a stock server cannot accept: "
                f"{args} {kwargs}")
        for key in (arguments or {}):
            low = str(key).lower()
            if any(m in low for m in self.SHIELD_MARKERS):
                raise AssertionError(
                    f"Shield leaked {key!r} into the tool arguments. The "
                    "upstream would have to be changed to tolerate it.")
        self.tool_calls.append((name, arguments))
        return {"ok": True, "tool": name}


def _proxy(up):
    return MCPProxy(up)


# ── the claim ────────────────────────────────────────────────────────────


def test_a_stock_server_serves_a_call_unmodified():
    """The whole proposal in one test: an unaware server, proxied, works."""
    up = VanillaMCPServer()
    res = asyncio.run(_proxy(up).call_tool(
        "get_balance", {"id": "C-1"},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))

    assert res["isError"] is False
    assert up.tool_calls == [("get_balance", {"id": "C-1"})]


def test_arguments_reach_the_upstream_byte_identical():
    """Shield must not enrich, rewrite, or annotate the payload. The upstream's
    own schema validation has to keep passing."""
    up = VanillaMCPServer()
    args = {"id": "C-1", "nested": {"k": [1, 2, {"deep": True}]}, "n": 0}
    asyncio.run(_proxy(up).call_tool(
        "get_balance", dict(args),
        agent_key=AGENT, user_role="support", tenant_id=TENANT))

    assert up.tool_calls[0][1] == args


def test_shield_only_needs_list_tools_and_call_tool():
    """The adapter surface a server must satisfy. If the proxy grows a
    requirement for some Shield-specific upstream method, an existing server
    stops working and this catches it at the seam."""
    required = {
        n for n, _ in inspect.getmembers(VanillaMCPServer, inspect.isfunction)
        if not n.startswith("_")
    }
    assert required == {"list_tools", "call_tool"}

    up = VanillaMCPServer()
    asyncio.run(_proxy(up).list_tools(
        agent_key=AGENT, user_role="support", tenant_id=TENANT))
    asyncio.run(_proxy(up).call_tool(
        "get_balance", {"id": "C-1"},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))


def test_identity_is_not_forwarded_upstream():
    """Tenant, agent and role are Shield's concern. A stock server has no field
    for them, so they must be consumed at the proxy."""
    up = VanillaMCPServer()
    asyncio.run(_proxy(up).call_tool(
        "get_balance", {"id": "C-1"},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))

    name, args = up.tool_calls[0]
    blob = repr(args).lower()
    for leaked in (TENANT.lower(), AGENT.lower(), "support"):
        assert leaked not in blob, f"{leaked!r} reached the upstream"


def test_meta_fields_are_consumed_not_forwarded():
    """workflow and confirmation_token come from the caller's _meta. They are
    Shield protocol; a stock server would reject or misread them."""
    up = VanillaMCPServer()
    asyncio.run(_proxy(up).call_tool(
        "get_balance", {"id": "C-1"},
        agent_key=AGENT, user_role="support", tenant_id=TENANT,
        session_id="sess-1", workflow="refund-flow",
        confirmation_token="tok-123"))

    assert up.tool_calls == [("get_balance", {"id": "C-1"})]


def test_list_tools_asks_the_upstream_for_everything():
    """Filtering happens in Shield, not by asking the upstream to filter. A
    server that cannot filter by role (i.e. every existing one) is fine."""
    up = VanillaMCPServer()
    visible = asyncio.run(_proxy(up).list_tools(
        agent_key=AGENT, user_role="support", tenant_id=TENANT))

    assert up.list_calls == 1
    assert {t["name"] for t in visible} == {"get_balance"}   # Shield filtered


def test_a_blocked_call_never_touches_the_upstream():
    """The server is not consulted, so it needs no notion of a denial."""
    up = VanillaMCPServer()
    res = asyncio.run(_proxy(up).call_tool(
        "wire_transfer", {"amount": 999},
        agent_key=AGENT, user_role="support", tenant_id=TENANT))

    assert res["isError"] is True
    assert up.tool_calls == []


# ── the downstream side, stated honestly ─────────────────────────────────


def test_downstream_tool_shape_is_additive_only():
    """What the CALLER receives is not byte-identical: tools are filtered, and
    Shield annotates each with x-shield-risk.

    Filtering is the product. The annotation is an extra key on an MCP tool
    object, so this pins it as ADDITIVE - every standard field survives with its
    original value, and a client that ignores unknown keys (the norm) is
    unaffected. If Shield ever rewrote name/description/inputSchema, a strict
    client could break, and that would be a real integration change.
    """
    up = VanillaMCPServer()
    original = {t["name"]: t for t in asyncio.run(up.list_tools())}

    visible = asyncio.run(_proxy(up).list_tools(
        agent_key=AGENT, user_role="admin", tenant_id=TENANT))

    for tool in visible:
        src = original[tool["name"]]
        for field in ("name", "description", "inputSchema"):
            assert tool[field] == src[field], (
                f"Shield rewrote {field!r} on {tool['name']!r}; the caller no "
                "longer sees the server's own contract")
        extra = set(tool) - set(src)
        assert extra <= {"x-shield-risk"}, f"unexpected added fields: {extra}"


# ── end to end, against a real server over a real transport ──────────────
#
# Everything above uses a fake upstream, so it proves the proxy seam and not the
# transport. These drive tests/fixtures/stock_mcp_server.py - a genuine MCP
# server built on the official SDK with no Shield import anywhere in it - as a
# real subprocess over real stdio. That is the actual claim being made to a
# partner: take a server you already run, change nothing, put Shield in front.

STOCK_SERVER = str(pathlib.Path(__file__).parent / "fixtures" / "stock_mcp_server.py")

pytest.importorskip("mcp", reason="official MCP SDK not installed")


async def _with_stock_server(fn):
    """Connect, run fn(upstream), close - all inside ONE task.

    The exit stack must be closed from the task that opened it; anyio raises
    'Attempted to exit cancel scope in a different task' otherwise.
    """
    from core.mcp.upstream import connect_upstream
    up = await connect_upstream({
        "transport": "stdio",
        "command": sys.executable,
        "args": [STOCK_SERVER],
    })
    try:
        return await fn(up)
    finally:
        try:
            await up.aclose()
        except RuntimeError:
            pass        # teardown races on anyio scopes; not what we assert here


def test_e2e_a_real_unmodified_server_works_behind_the_proxy():
    """The proposal, proven against a real process rather than a fake object."""
    async def scenario(up):
        proxy = MCPProxy(up)
        visible = await proxy.list_tools(
            agent_key=AGENT, user_role="support", tenant_id=TENANT)
        allowed = await proxy.call_tool(
            "get_balance", {"account_id": "C-1"},
            agent_key=AGENT, user_role="support", tenant_id=TENANT)
        denied = await proxy.call_tool(
            "wire_transfer", {"account_id": "C-1", "amount": 999},
            agent_key=AGENT, user_role="support", tenant_id=TENANT)
        return visible, allowed, denied

    visible, allowed, denied = asyncio.run(_with_stock_server(scenario))

    # role filtering applied to a server that has no concept of roles
    assert {t["name"] for t in visible} == {"get_balance"}
    # the permitted call really executed on the real server
    assert allowed["isError"] is False
    assert "42.00" in repr(allowed["content"])
    # the denied one was stopped at Shield
    assert denied["isError"] is True


def test_e2e_the_server_advertises_its_own_unmodified_schema():
    """Shield forwards the server's real inputSchema. A client generating tool
    calls against it must see the server's contract, not a rewritten one."""
    async def scenario(up):
        raw = await up.list_tools()
        proxied = await MCPProxy(up).list_tools(
            agent_key=AGENT, user_role="admin", tenant_id=TENANT)
        return raw, proxied

    raw, proxied = asyncio.run(_with_stock_server(scenario))

    by_name = {t["name"]: t for t in raw}
    assert by_name, "the stock server advertised no tools"
    for tool in proxied:
        assert tool["inputSchema"] == by_name[tool["name"]]["inputSchema"]


def test_the_stock_server_fixture_stays_shield_free():
    """Guards the fixture itself. If someone 'fixes' it by importing Shield,
    the e2e tests above would still pass while proving nothing."""
    src = pathlib.Path(STOCK_SERVER).read_text().lower()
    for marker in ("import shield", "from core.", "from api.", "from storage.",
                   "x-api-key", "x-shield"):
        assert marker not in src, (
            f"the stock server fixture references {marker!r} - it is supposed "
            "to be a server that knows nothing about Shield")
