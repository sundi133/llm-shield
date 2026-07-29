"""Server-scoped tool floor (fleet control plane, phase 3) — first enforcement.

A *floor* is a per-server control enforced on every call regardless of who the
caller claims to be. That distinction is the whole point: the gateway resolves a
role from the X-User-Role header unless verified-identity middleware supplied one
(api/routes_mcp_server.py::_resolve_identity), so a caller can pick its own role.
Role-scoped GRANTS are only worth as much as that identity; a floor holds anyway.

So every enforcement test here passes user_role="admin" — the most privileged
role an attacker would claim — and asserts the floor still holds.
"""

import asyncio
from unittest.mock import patch

import pytest

from core.mcp.enforcement import (
    filter_tools_by_floor,
    fleet_policy_enabled,
    tool_floor_decision,
)
from core.mcp.proxy_server import MCPProxy


def run(coro):
    return asyncio.run(coro)


class _FakeUpstream:
    """Records whether the vendor was contacted at all."""

    def __init__(self, tools=None):
        self._tools = tools or [{"name": "list_jobs"}, {"name": "generate_video"}]
        self.calls = []

    async def list_tools(self):
        return list(self._tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}


class _PassEnforcer:
    """Allows everything, so any block observed comes from the floor alone."""

    async def enforce_tool_call(self, name, arguments, **kw):
        return {"allowed": True, "action": "pass", "mode": "enforce",
                "would_block": [], "risk": "low", "reason": "", "results": []}

    async def sanitize_tool_result(self, name, raw, **kw):
        return {"sanitized_output": raw, "action": "pass", "blocked": False}

    def filter_tools_for_role(self, tools, **kw):
        return tools


def _proxy(policy, upstream=None):
    return MCPProxy(upstream or _FakeUpstream(), enforcer=_PassEnforcer(), policy=policy)


_ATTACKER = dict(agent_key="bot", user_role="admin", tenant_id="acme")


# ── decision semantics ───────────────────────────────────────────────


def test_no_policy_allows_everything():
    """An unbound server must behave exactly as it did before this feature."""
    assert tool_floor_decision(None, "anything") is None
    assert tool_floor_decision({}, "anything") is None
    assert tool_floor_decision({"dlp": {}}, "anything") is None


def test_allow_list_admits_and_bars():
    policy = {"tools": {"allow": ["list_jobs"]}}
    assert tool_floor_decision(policy, "list_jobs") is None
    assert "allowed tool list" in tool_floor_decision(policy, "generate_video")


def test_allow_null_means_inherit_not_deny():
    assert tool_floor_decision({"tools": {"allow": None}}, "anything") is None


def test_allow_empty_list_denies_everything():
    """`[]` and `null` are deliberately different: an operator who writes an
    empty list means 'nothing', not 'everything'."""
    assert tool_floor_decision({"tools": {"allow": []}}, "anything") is not None


def test_deny_beats_allow():
    policy = {"tools": {"allow": ["danger"], "deny": ["danger"]}}
    assert "denied" in tool_floor_decision(policy, "danger")


def test_deny_alone_bars_only_listed():
    policy = {"tools": {"deny": ["delete_account"]}}
    assert tool_floor_decision(policy, "delete_account") is not None
    assert tool_floor_decision(policy, "list_jobs") is None


def test_malformed_tools_block_is_ignored():
    """Bad config must not become an accidental deny-all outage."""
    for bad in ({"tools": "nonsense"}, {"tools": None}, {"tools": []}):
        assert tool_floor_decision(bad, "anything") is None


def test_tool_names_are_compared_literally():
    """A poisoned upstream advertising a qualified-looking name must not slip
    past a floor by resembling another route's tool."""
    policy = {"tools": {"allow": ["list_jobs"]}}
    assert tool_floor_decision(policy, "other-route:list_jobs") is not None


# ── tools/list filtering ─────────────────────────────────────────────


def test_listing_hides_barred_tools():
    tools = [{"name": "list_jobs"}, {"name": "generate_video"}]
    out = filter_tools_by_floor(tools, {"tools": {"allow": ["list_jobs"]}})
    assert [t["name"] for t in out] == ["list_jobs"]


def test_listing_unchanged_without_policy():
    tools = [{"name": "a"}, {"name": "b"}]
    assert filter_tools_by_floor(tools, None) == tools


def test_proxy_listing_hides_barred_tools_from_admin():
    out = run(_proxy({"tools": {"allow": ["list_jobs"]}}).list_tools(**_ATTACKER))
    assert [t["name"] for t in out] == ["list_jobs"]


# ── tools/call enforcement ───────────────────────────────────────────


def test_barred_call_is_blocked_for_a_self_declared_admin():
    up = _FakeUpstream()
    out = run(_proxy({"tools": {"allow": ["list_jobs"]}}, up).call_tool(
        "generate_video", {}, **_ATTACKER))
    assert out["isError"] is True
    assert "Blocked by Shield" in out["content"][0]["text"]


def test_barred_call_never_reaches_the_vendor():
    """The floor runs before any upstream connection: a barred call must not be
    forwarded, billed, or logged by the third party."""
    up = _FakeUpstream()
    run(_proxy({"tools": {"allow": ["list_jobs"]}}, up).call_tool(
        "generate_video", {}, **_ATTACKER))
    assert up.calls == []


def test_allowed_call_passes_through():
    up = _FakeUpstream()
    out = run(_proxy({"tools": {"allow": ["list_jobs"]}}, up).call_tool(
        "list_jobs", {"x": 1}, **_ATTACKER))
    assert out["isError"] is False
    assert up.calls == [("list_jobs", {"x": 1})]


def test_unbound_server_forwards_everything():
    up = _FakeUpstream()
    out = run(_proxy(None, up).call_tool("generate_video", {}, **_ATTACKER))
    assert out["isError"] is False
    assert up.calls == [("generate_video", {})]


def test_block_is_administrative_so_monitor_mode_cannot_suppress_it():
    """Monitor mode is a dry-run for detection heuristics. An operator who barred
    a tool on a server expects it barred, same as the kill switch."""
    up = _FakeUpstream()
    out = run(_proxy({"tools": {"deny": ["generate_video"]}}, up).call_tool(
        "generate_video", {}, **_ATTACKER))
    result = out["shield"]["results"][0]
    assert result["details"]["administrative"] is True
    assert result["guardrail"] == "mcp_tool_floor"


def test_decision_is_recorded_for_audit():
    recorded = []

    async def sink(d):
        recorded.append(d)

    proxy = MCPProxy(_FakeUpstream(), enforcer=_PassEnforcer(),
                     policy={"tools": {"allow": []}}, on_decision=sink)
    run(proxy.call_tool("anything", {}, **_ATTACKER))
    assert recorded and recorded[0]["allowed"] is False
    assert recorded[0]["tool"] == "anything"


def test_two_servers_with_the_same_tool_name_are_independent():
    """The collision this whole workstream exists to fix: one server's grant
    must not imply the same tool elsewhere."""
    alpha, beta = _FakeUpstream([{"name": "search"}]), _FakeUpstream([{"name": "search"}])
    allowed = run(_proxy({"tools": {"allow": ["search"]}}, alpha).call_tool(
        "search", {}, **_ATTACKER))
    blocked = run(_proxy({"tools": {"allow": []}}, beta).call_tool(
        "search", {}, **_ATTACKER))
    assert allowed["isError"] is False and alpha.calls
    assert blocked["isError"] is True and beta.calls == []


# ── escape hatch ─────────────────────────────────────────────────────


def test_env_flag_off_reverts_to_previous_behavior():
    up = _FakeUpstream()
    with patch.dict("os.environ", {"SHIELD_MCP_FLEET_POLICY": "0"}):
        assert fleet_policy_enabled() is False
        assert tool_floor_decision({"tools": {"allow": []}}, "x") is None
        out = run(_proxy({"tools": {"allow": []}}, up).call_tool(
            "generate_video", {}, **_ATTACKER))
    assert out["isError"] is False
    assert up.calls == [("generate_video", {})]


def test_env_flag_defaults_on():
    with patch.dict("os.environ", {}, clear=False):
        import os
        os.environ.pop("SHIELD_MCP_FLEET_POLICY", None)
        assert fleet_policy_enabled() is True


# ── pooled connections must not pin a stale policy ───────────────────


def test_set_policy_refreshes_a_pooled_proxy():
    """stdio upstreams are pooled across requests. If policy were pinned at
    construction, a tightened profile would not take effect until the subprocess
    happened to cycle."""
    up = _FakeUpstream()
    proxy = MCPProxy(up, enforcer=_PassEnforcer(), policy=None)
    assert run(proxy.call_tool("generate_video", {}, **_ATTACKER))["isError"] is False

    proxy.set_policy({"tools": {"allow": ["list_jobs"]}})
    assert run(proxy.call_tool("generate_video", {}, **_ATTACKER))["isError"] is True

    proxy.set_policy(None)
    assert run(proxy.call_tool("generate_video", {}, **_ATTACKER))["isError"] is False


# ── end-to-end through the gateway router ────────────────────────────


def test_gateway_applies_the_route_s_materialized_policy():
    """Full path: route config carries effective_policy, the router hands it to
    the proxy, and the floor holds for a caller claiming admin."""
    from unittest.mock import patch as _patch

    from core.mcp.gateway import MCPGatewayRouter
    from storage import mcp_gateway_store as gstore
    from storage.tenant_store import _fallback_store

    for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
        del _fallback_store[k]

    with _patch("storage.tenant_store._get_redis", return_value=None):
        gstore.set_upstream("acme", "higgsfield", {
            "route": "higgsfield", "transport": "stdio", "command": "x",
            "isolation_ack": True,
            "effective_policy": {"tools": {"allow": ["list_jobs"]}},
        })
        up = _FakeUpstream()

        async def factory(cfg, tenant_id):
            return MCPProxy(up, enforcer=_PassEnforcer(),
                            policy=cfg.get("effective_policy"))

        router = MCPGatewayRouter(proxy_factory=factory)

        blocked = run(router.call_tool("acme", "higgsfield", "generate_video", {},
                                       agent_key="bot", user_role="admin"))
        assert blocked["isError"] is True
        assert up.calls == []

        ok = run(router.call_tool("acme", "higgsfield", "list_jobs", {},
                                  agent_key="bot", user_role="admin"))
        assert ok["isError"] is False

        listed = run(router.list_tools("acme", "higgsfield",
                                       agent_key="bot", user_role="admin"))
        assert [t["name"] for t in listed] == ["list_jobs"]

    for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
        del _fallback_store[k]


# ── latency contract ─────────────────────────────────────────────────


@pytest.mark.parametrize("policy", [None, {"tools": {"allow": ["list_jobs"]}}])
def test_policy_adds_no_extra_config_reads(policy):
    """The §2 contract of docs/spec-mcp-fleet-control-plane.md, as a test.

    Policy is denormalized onto the route document precisely so the guard path
    stays at its current round-trip count. If someone later resolves the profile
    at call time instead, this fails — which is the point, because the cost would
    otherwise be invisible until it showed up in p99.
    """
    from unittest.mock import patch as _patch

    import core.mcp.gateway as gw
    from core.mcp.gateway import MCPGatewayRouter

    cfg = {"route": "r", "transport": "stdio", "command": "x",
           "isolation_ack": True}
    if policy:
        cfg["effective_policy"] = policy

    reads = []

    def _counting_get_upstream(tenant_id, route):
        reads.append((tenant_id, route))
        return cfg

    up = _FakeUpstream()

    async def factory(c, tenant_id):
        return MCPProxy(up, enforcer=_PassEnforcer(), policy=c.get("effective_policy"))

    with _patch.object(gw, "get_upstream", _counting_get_upstream):
        router = MCPGatewayRouter(proxy_factory=factory)
        run(router.call_tool("acme", "r", "list_jobs", {},
                             agent_key="bot", user_role="admin"))

    assert len(reads) == 1, f"expected one config read per call, got {len(reads)}"
