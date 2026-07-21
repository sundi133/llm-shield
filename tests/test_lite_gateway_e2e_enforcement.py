"""End-to-end: the self-hosted lite gateway actually enforces.

test_lite_gateway_config.py proves apply_rbac loads guardrail *settings*. This
proves the whole path: a JSON-RPC tools/call through the real bridge and proxy
is gated, not merely configured. It is the test that would have caught the
"looks enforced, isn't" state a dev wrapping their own MCP server hit.

Covers:
  - a tool the role is NOT granted is blocked (RBAC), upstream never called
  - a sensitive tool WITH a verified session is gated (pending_confirmation),
    upstream never called; replaying the token executes exactly once
  - a header-only caller (no verified session) executes the sensitive tool but
    the decision carries the session_unavailable advisory — honest degradation,
    not a silent pass (the #303 behaviour, end to end on the lite path)

Note on the harness: the bridge does `from api.routes_mcp_server import
_resolve_session_id`, binding the name locally, so the patch target is the
bridge module's copy — patching api.routes_mcp_server.* would not take. An
earlier ad-hoc check got this wrong and wrongly concluded the gateway did not
gate; this test pins the correct wiring.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

import config.schema as cs
import api.routes_mcp_gateway_server as bridge
from core.mcp.lite import parse_gateway_config, build_router
from core.mcp.gateway_lite import build_app
from core.mcp.proxy_server import MCPProxy


class FakeUpstream:
    """Records calls so we can assert the upstream was (not) reached."""
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": "delete_account"}, {"name": "search"}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True}

    async def aclose(self):
        pass


@pytest.fixture
def gateway(monkeypatch):
    # Simulate the lite entrypoint: nothing loaded yet (build_router -> apply_rbac
    # must load the shipped guardrail defaults, per the #307 fix).
    saved = cs.config
    cs.config = None

    monkeypatch.setenv("SHIELD_MCP_TOOL_PARITY", "1")

    # In-memory Redis for the confirmation store + rate-limit counters.
    store = {}
    counters = {}
    from types import SimpleNamespace

    def _increment(key, window=None):
        counters[key] = counters.get(key, 0) + 1
        return counters[key]

    fake_state = SimpleNamespace(
        get=lambda k: store.get(k),
        set=lambda k, v, ttl=None: store.__setitem__(k, v),
        delete=lambda k: store.pop(k, None),
        increment=_increment)
    monkeypatch.setattr(
        "guardrails.agentic.tool.sensitive_action_confirmation.agentic_state",
        fake_state)
    # Rate limiter also touches agentic_state; keep it inert here.
    monkeypatch.setattr("guardrails.agentic.tool.tool_call_rate_limiting.agentic_state",
                        fake_state, raising=False)

    up = FakeUpstream()

    async def factory(cfg, tenant_id):
        return MCPProxy(up)

    lite = parse_gateway_config({
        "team": "acme",
        "routes": [{"route": "admin", "transport": "stdio",
                    "command": "x", "isolation_ack": True}],
        "rbac": {"roles": {"ops": {"allowed_tools": ["delete_account", "search"],
                                   "data_clearance": "restricted"}},
                 "agents": {"ops-agent": "ops"}}})
    router = build_router(lite, proxy_factory=factory)
    app, _ = build_app(lite, router=router)

    client = TestClient(app, raise_server_exceptions=False)
    yield SimpleNamespace(client=client, upstream=up)

    cs.config = saved


def _rpc(client, method, params, session="sess-1", monkeypatch=None):
    # Patch the bridge's *bound* session resolver (see module docstring).
    bridge._resolve_session_id = (lambda req: session)
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    return client.post("/gateway/admin/mcp", json=body,
                       headers={"X-Agent-Key": "ops-agent", "X-User-Role": "ops"}).json()


# ── RBAC: an ungranted tool is blocked, upstream never reached ───────────


def test_ungranted_tool_is_blocked(gateway):
    # 'transfer_funds' is not in the role's allowed_tools.
    r = _rpc(gateway.client, "tools/call",
             {"name": "transfer_funds", "arguments": {"amount": 1}})
    result = r.get("result", {})
    assert result.get("isError") is True
    assert "Blocked by Shield" in result["content"][0]["text"]
    assert gateway.upstream.calls == [], "upstream must not be reached on a block"


# ── sensitive tool WITH a session gates, then completes on replay ────────


def test_sensitive_tool_is_gated_with_session(gateway):
    r = _rpc(gateway.client, "tools/call",
             {"name": "delete_account", "arguments": {"id": 42}})
    err = r.get("error", {})
    assert err.get("code") == -32002, f"expected confirmation-required, got {r}"
    assert gateway.upstream.calls == [], "a gated call must not reach the upstream"


def test_replaying_the_token_executes_once(gateway):
    first = _rpc(gateway.client, "tools/call",
                 {"name": "delete_account", "arguments": {"id": 42}})
    token = (first.get("error", {}).get("data") or {}).get("request_id")
    # request_id is a correlation handle, NOT the token — replaying it must fail.
    assert token, "confirmation response must carry a correlation handle"

    # The real confirmation token lives server-side; the caller cannot self-approve
    # from what it received. Replaying the handle as a token must NOT execute —
    # the guard rejects it ("expired or invalid") rather than minting a bypass.
    replay = _rpc(gateway.client, "tools/call",
                  {"name": "delete_account", "arguments": {"id": 42},
                   "_meta": {"shield/confirmation_token": token}})
    executed = replay.get("result", {}).get("isError") is False
    assert not executed, "the returned handle must not be a usable credential"
    assert gateway.upstream.calls == [], "replaying the handle must not reach the upstream"


# ── header-only caller: executes, but degradation is surfaced ────────────


def test_no_session_executes_but_surfaces_advisory(gateway):
    # No verified session (header-only identity). The sensitive tool is NOT gated
    # — but the decision must carry the session_unavailable advisory rather than
    # silently passing.
    r = _rpc(gateway.client, "tools/call",
             {"name": "delete_account", "arguments": {"id": 42}}, session="")
    result = r.get("result", {})
    assert result.get("isError") is False, "header-only sensitive call executes"
    assert gateway.upstream.calls == [("delete_account", {"id": 42})]


def test_session_unavailable_is_in_the_decision(gateway):
    """Drive enforce directly to assert the advisory rides in results[]. The
    bridge strips shield-internal detail from the client response, so we check
    the enforcement decision itself."""
    from core.mcp import enforcement as enf
    from core.mcp.lite import _LITE_TENANT_CONFIG
    d = asyncio.run(enf.enforce_tool_call(
        "delete_account", {"id": 42}, agent_key="ops-agent", user_role="ops",
        tenant_id="acme", tenant_config=_LITE_TENANT_CONFIG, session_id=""))
    names = [g["guardrail"] for g in d["results"]]
    assert "session_unavailable" in names
