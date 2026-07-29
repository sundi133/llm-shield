"""Route-scoped kill switch (fleet control plane, phase 4).

During an incident an operator usually wants to isolate the ONE compromised
server, not disable that tool name on every server exposing it. The set gains
qualified `route:tool` members alongside the bare ones.

The compatibility property under test throughout: bare members keep their
original fleet-wide meaning, so every tool disabled before route scoping existed
behaves exactly as it did.
"""

import asyncio
from unittest.mock import patch

import pytest

from core.mcp.enforcement import _killswitch_blocks
from storage import tool_killswitch as ks


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith("killswitch:")]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


# ── scoping ──────────────────────────────────────────────────────────


def test_fleet_wide_disable_blocks_every_route():
    """The original behavior, unchanged."""
    ks.disable_tool("acme", "delete_record", reason="cve")
    assert ks.is_tool_disabled("acme", "delete_record") is True
    assert ks.is_tool_disabled("acme", "delete_record", route="higgsfield") is True
    assert ks.is_tool_disabled("acme", "delete_record", route="vendor-x") is True


def test_route_scoped_disable_blocks_only_that_route():
    ks.disable_tool("acme", "generate_video", route="higgsfield")
    assert ks.is_tool_disabled("acme", "generate_video", route="higgsfield") is True
    assert ks.is_tool_disabled("acme", "generate_video", route="vendor-x") is False
    # ...and does not become a fleet-wide disable for callers with no route.
    assert ks.is_tool_disabled("acme", "generate_video") is False


def test_both_scopes_can_coexist():
    ks.disable_tool("acme", "t", reason="fleet")
    ks.disable_tool("acme", "t", route="higgsfield", reason="route")
    assert ks.is_tool_disabled("acme", "t") is True
    assert ks.is_tool_disabled("acme", "t", route="higgsfield") is True

    ks.enable_tool("acme", "t")  # lift the fleet-wide one only
    assert ks.is_tool_disabled("acme", "t") is False
    assert ks.is_tool_disabled("acme", "t", route="higgsfield") is True


def test_route_enable_does_not_lift_a_fleet_wide_disable():
    """Otherwise a narrow 'unblock this server' would silently unblock the fleet."""
    ks.disable_tool("acme", "t", reason="fleet")
    assert ks.enable_tool("acme", "t", route="higgsfield") is False
    assert ks.is_tool_disabled("acme", "t") is True


def test_enable_returns_false_when_not_disabled():
    assert ks.enable_tool("acme", "never") is False
    assert ks.enable_tool("acme", "never", route="r") is False


def test_tenant_isolation():
    ks.disable_tool("acme", "t", route="r")
    assert ks.is_tool_disabled("other", "t", route="r") is False


# ── listing ──────────────────────────────────────────────────────────


def test_listing_reports_scope():
    ks.disable_tool("acme", "fleet_tool", reason="a")
    ks.disable_tool("acme", "route_tool", route="higgsfield", reason="b")
    by_name = {d["tool_name"]: d for d in ks.list_disabled_tools("acme")}

    assert by_name["fleet_tool"]["route"] is None
    assert by_name["route_tool"]["route"] == "higgsfield"


def test_listing_without_metadata_falls_back_to_the_member():
    """Metadata can be missing (expired, or written out of band). The scope is
    still recoverable from the member, since a route id cannot contain ':'."""
    from storage.tenant_store import _fallback_store
    import json

    _fallback_store["killswitch:tools:acme"] = json.dumps(["higgsfield:gen", "bare"])
    listed = {d["tool_name"]: d for d in ks.list_disabled_tools("acme")}
    assert listed["gen"]["route"] == "higgsfield"
    assert listed["bare"]["route"] is None


def test_a_tool_whose_own_name_has_a_colon_is_reported_from_metadata():
    """Parsing the member would misread this as route-scoped, so the scope is
    recorded at write time rather than inferred."""
    ks.disable_tool("acme", "weird:name", reason="x")
    entry = ks.list_disabled_tools("acme")[0]
    assert entry["tool_name"] == "weird:name"
    assert entry["route"] is None


# ── guard-path integration ───────────────────────────────────────────


def test_guard_path_check_is_route_aware():
    with patch("core.feature_flags.KILLSWITCH_ENABLED", True):
        ks.disable_tool("acme", "generate_video", route="higgsfield")
        assert _killswitch_blocks("acme", "generate_video", "higgsfield") is True
        assert _killswitch_blocks("acme", "generate_video", "vendor-x") is False
        assert _killswitch_blocks("acme", "generate_video") is False


def test_guard_path_fails_open_on_storage_error():
    """Today's posture, deliberately preserved: losing Redis must not take the
    whole MCP fleet down with it."""
    with patch("core.feature_flags.KILLSWITCH_ENABLED", True), \
         patch("storage.tool_killswitch.is_tool_disabled", side_effect=RuntimeError):
        assert _killswitch_blocks("acme", "t", "higgsfield") is False


def test_no_tenant_never_blocks():
    assert _killswitch_blocks(None, "t", "higgsfield") is False


# ── one round trip for both scopes ───────────────────────────────────


def test_both_scopes_resolve_in_a_single_round_trip():
    """Route scoping must not add a Redis call to the guard path: SMISMEMBER
    covers the fleet-wide and route-scoped members together."""
    calls = []

    class _FakeRedis:
        def smismember(self, key, members):
            calls.append(("smismember", tuple(members)))
            return [0] * len(members)

        def sismember(self, key, member):  # pragma: no cover - must not be used
            calls.append(("sismember", member))
            return 0

    with patch("storage.tool_killswitch._get_redis", return_value=_FakeRedis()):
        assert ks.is_tool_disabled("acme", "t", route="higgsfield") is False

    assert len(calls) == 1
    assert calls[0] == ("smismember", ("t", "higgsfield:t"))


def test_falls_back_to_sismember_on_older_redis():
    """SMISMEMBER needs Redis >= 6.2. An older server must degrade in latency,
    never in correctness."""
    calls = []

    class _OldRedis:
        def smismember(self, key, members):
            raise Exception("ERR unknown command 'SMISMEMBER'")

        def sismember(self, key, member):
            calls.append(member)
            return member == "higgsfield:t"

    with patch("storage.tool_killswitch._get_redis", return_value=_OldRedis()):
        assert ks.is_tool_disabled("acme", "t", route="higgsfield") is True

    assert calls == ["t", "higgsfield:t"]
