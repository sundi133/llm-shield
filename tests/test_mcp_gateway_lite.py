"""Small-team gateway file-config core (Phase 4 Task 1).

Reuses the shipped MCPProxy + in-process enforcement via a fake upstream, so the
allowlist is exercised for real without a live MCP server.
"""

import io
import json

import pytest

from core.mcp.lite import (
    parse_gateway_config,
    load_gateway_config,
    apply_rbac,
    make_decision_sink,
    FileConfigRouter,
    LiteConfig,
)
from core.mcp.gateway import GatewayError
from core.mcp.proxy_server import MCPProxy


# ── fixtures ────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _restore_config():
    """apply_rbac mutates the global config singleton; save/restore around tests."""
    import config.schema as cs
    from core.rbac import enforcer
    saved = cs.config
    yield
    cs.config = saved
    enforcer.reload()


class FakeUpstream:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": "read_file", "description": "read a file"},
                {"name": "delete_file", "description": "delete a file"}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True, "path": arguments.get("path")}

    async def aclose(self):
        pass


def _lite(routes=None, rbac=None, log=None):
    return LiteConfig(
        team="acme",
        routes=routes or {"files": {"route": "files", "transport": "stdio",
                                    "command": "x", "isolation_ack": True}},
        rbac=rbac or {},
        log=log or {"format": "json", "path": "-"},
    )


# ── config parsing / validation ─────────────────────────────────────────
def test_parse_valid_config():
    cfg = parse_gateway_config({
        "team": "acme",
        "routes": [{"route": "files", "transport": "stdio", "command": "npx",
                    "args": ["-y", "srv"], "isolation_ack": True}],
        "rbac": {"roles": {"reader": {"allowed_tools": ["read_file"]}},
                 "agents": {"a": "reader"}},
    })
    assert cfg.team == "acme"
    assert cfg.routes["files"]["command"] == "npx"
    assert cfg.rbac["agents"] == {"a": "reader"}


@pytest.mark.parametrize("raw,msg", [
    ({"routes": []}, "non-empty 'routes'"),
    ({"routes": [{"transport": "stdio", "command": "x"}]}, "missing 'route'"),
    ({"routes": [{"route": "a", "transport": "stdio"}]}, "needs 'command'"),
    ({"routes": [{"route": "a", "transport": "http"}]}, "needs 'url'"),
    ({"routes": [{"route": "a", "transport": "carrier-pigeon"}]}, "invalid transport"),
    ({"routes": [{"route": "a", "transport": "stdio", "command": "x"},
                 {"route": "a", "transport": "stdio", "command": "y"}]}, "duplicate route"),
])
def test_parse_rejects_bad_config(raw, msg):
    with pytest.raises(ValueError, match=msg):
        parse_gateway_config(raw)


def test_load_from_file(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(
        "team: acme\n"
        "routes:\n"
        "  - route: files\n"
        "    transport: stdio\n"
        "    command: npx\n"
        "    isolation_ack: true\n"
    )
    cfg = load_gateway_config(str(p))
    assert cfg.routes["files"]["transport"] == "stdio"


# ── _load_cfg: file source, no Redis ────────────────────────────────────
def test_load_cfg_from_file_not_redis(monkeypatch):
    import storage.mcp_gateway_store as store
    monkeypatch.setattr(store, "get_upstream",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Redis touched")))
    router = FileConfigRouter(_lite(), proxy_factory=lambda cfg, tid: None)
    assert router._load_cfg("acme", "files")["command"] == "x"
    with pytest.raises(GatewayError) as ei:
        router._load_cfg("acme", "nope")
    assert ei.value.status == 404


def test_isolation_ack_false_warns(caplog):
    routes = {"files": {"route": "files", "transport": "stdio", "command": "x",
                        "isolation_ack": False}}
    router = FileConfigRouter(_lite(routes=routes), proxy_factory=lambda c, t: None)
    with caplog.at_level("WARNING"):
        router._load_cfg("acme", "files")
    assert any("isolation_ack=false" in r.message for r in caplog.records)


# ── decision sink ───────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_decision_sink_writes_one_json_line():
    buf = io.StringIO()
    sink = make_decision_sink({"format": "json"}, stream=buf)
    await sink({"phase": "call", "tool": "read_file", "agent_key": "a",
                "allowed": True, "action": "pass"})
    lines = [l for l in buf.getvalue().splitlines() if l]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["tool"] == "read_file" and rec["allowed"] is True and "ts" in rec


# ── RBAC allowlist enforced via the real in-process enforcer ────────────
@pytest.mark.asyncio
async def test_allowlist_blocks_disallowed_tool_and_does_not_forward():
    apply_rbac({"roles": {"reader": {"allowed_tools": ["read_file"]}},
                "agents": {"coding-agent": "reader"}})
    up = FakeUpstream()
    buf = io.StringIO()
    sink = make_decision_sink({"format": "json"}, stream=buf)

    async def factory(cfg, tid):
        return MCPProxy(up, on_decision=sink)

    router = FileConfigRouter(_lite(), on_decision=sink, proxy_factory=factory)

    blocked = await router.call_tool("acme", "files", "delete_file", {"path": "/x"},
                                     agent_key="coding-agent", user_role="reader")
    assert blocked["isError"] is True
    assert ("delete_file", {"path": "/x"}) not in up.calls  # never forwarded

    ok = await router.call_tool("acme", "files", "read_file", {"path": "/x"},
                                agent_key="coding-agent", user_role="reader")
    assert ok["isError"] is False
    assert up.calls == [("read_file", {"path": "/x"})]

    # both decisions were logged
    logged = [json.loads(l) for l in buf.getvalue().splitlines() if l]
    assert {r["tool"] for r in logged} == {"delete_file", "read_file"}
    assert [r["allowed"] for r in logged if r["tool"] == "delete_file"] == [False]
