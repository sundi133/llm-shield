"""AI discovery, task 2: the device agent's collector, its opt-in, and the
server side (policy section, bundle, heartbeat). Spec: docs/specs/ai-discovery.md."""

import json
import os
import plistlib
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages", "votal-device-agent"))

from votal_device_agent import discovery as dc  # noqa: E402
from core.discovery import catalog as cat  # noqa: E402

CATALOG = cat.device_bundle()
SECRET = "ghp_supersecret_token_value"


def _app(root: Path, name: str, bundle_id: str):
    p = root / f"{name}.app" / "Contents"
    p.mkdir(parents=True)
    with open(p / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id}, f)


@pytest.fixture
def mac_home(tmp_path):
    home = tmp_path / "Users" / "ana"
    apps = tmp_path / "Applications"
    _app(apps, "Claude", "com.anthropic.claudefordesktop")
    _app(apps, "Notes", "com.apple.Notes")
    (home / ".vscode" / "extensions" / "github.copilot-1.250.0").mkdir(parents=True)
    (home / ".cursor" / "extensions" / "saoudrizwan.claude-dev-3.1.0").mkdir(parents=True)
    (home / ".vscode" / "extensions" / "ms-python.python-2024.1.0").mkdir(parents=True)
    cfg = home / "Library" / "Application Support" / "Claude"
    cfg.mkdir(parents=True)
    (cfg / "claude_desktop_config.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "/usr/local/bin/npx",
                   "args": ["-y", "@modelcontextprotocol/server-github", "--token", SECRET],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": SECRET}},
        "local": {"command": "node", "args": ["/Users/ana/secret-project/server.js"]}}}))
    (home / ".claude.json").write_text(json.dumps({"projects": {"/Users/ana/repo": {"mcpServers": {
        "linear": {"type": "http", "url": "https://mcp.linear.app/mcp?key=" + SECRET}}}}}))
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers.docs]\ncommand = "uvx"\nargs = ["mcp-server-fetch"]\nenv = { API_KEY = "%s" }\n' % SECRET)
    return SimpleNamespace(home=home, apps=apps)


def run(mac_home, **kw):
    return dc.collect(CATALOG, os_name="macos", homes=[mac_home.home], app_dirs=[mac_home.apps],
                      which=kw.get("which", lambda n: "/opt/homebrew/bin/claude" if n == "claude" else None),
                      port_open=kw.get("port_open", lambda p: p == 11434))


def test_the_collector_finds_each_kind_from_the_catalog(mac_home):
    obs = run(mac_home)
    kinds = {(o["kind"], o.get("app_id") or o.get("extension") or o.get("binary") or o.get("port")
              or o["mcp"]["server_name"]) for o in obs}
    assert ("app", "com.anthropic.claudefordesktop") in kinds
    assert ("extension", "github.copilot") in kinds and ("extension", "saoudrizwan.claude-dev") in kinds
    assert ("binary", "claude") in kinds and ("port", 11434) in kinds
    mcp = {o["mcp"]["server_name"]: o["mcp"] for o in obs if o["kind"] == "mcp_server"}
    assert mcp["github"] == {"server_name": "github", "command": "npx",
                             "package": "@modelcontextprotocol/server-github", "host": "",
                             "client": "claude-desktop"}
    assert mcp["linear"]["host"] == "mcp.linear.app" and mcp["linear"]["client"] == "claude-code"
    assert mcp["docs"]["package"] == "mcp-server-fetch" and mcp["docs"]["client"] == "codex"
    assert mcp["local"]["package"] == ""                       # a script path is not reported


def test_the_collector_never_reports_secrets_paths_or_non_catalog_items(mac_home):
    blob = json.dumps(run(mac_home))
    for leaked in (SECRET, "--token", "secret-project", "com.apple.Notes", "ms-python", "GITHUB_PERSONAL"):
        assert leaked not in blob, leaked


def test_a_url_with_credentials_reports_the_host_not_the_user():
    for url in ("https://user:pw@mcp.linear.app/sse", "https://tok@mcp.linear.app", "http://mcp.linear.app:8080/x"):
        assert dc._host(url) == "mcp.linear.app", url


def test_windows_apps_by_executable(tmp_path):
    (tmp_path / "Programs" / "cursor").mkdir(parents=True)
    (tmp_path / "Programs" / "cursor" / "Cursor.exe").write_bytes(b"")
    (tmp_path / "Programs" / "other" / "Thing.exe").parent.mkdir(parents=True)
    (tmp_path / "Programs" / "other" / "Thing.exe").write_bytes(b"")
    obs = dc.collect(CATALOG, os_name="windows", homes=[], program_dirs=[tmp_path / "Programs"],
                     which=lambda n: None, port_open=lambda p: False)
    # Binaries also come from the host's system bin dirs, so only apps are compared.
    assert [o for o in obs if o["kind"] == "app"] == [{"kind": "app", "app_id": "Cursor.exe"}]


def test_the_collector_never_raises(tmp_path):
    assert dc.collect({"apps": "garbage"}, os_name="macos", homes=[tmp_path], app_dirs=[tmp_path],
                      which=lambda n: None, port_open=lambda p: False) == []


@pytest.mark.parametrize("command,args,expected", [
    ("npx", ["-y", "@scope/server@1.2.0"], "@scope/server"),
    ("docker", ["run", "-i", "-e", "TOKEN=abc", "-e", "OTHER", "ghcr.io/org/mcp-server"], "ghcr.io/org/mcp-server"),
    ("uvx", ["--from", "git+https://example.com/x", "mcp-x"], "mcp-x"),
    ("python3", ["-m", "mcp_server_time"], "mcp_server_time"),
    ("node", ["/abs/path/index.js"], ""), ("npx", ["-y", "some-mcp@latest", "--key", "abc"], "some-mcp"),
])
def test_package_extraction_never_returns_a_flag_value(command, args, expected):
    assert dc._package_from(command, args) == expected


# ── the agent: opt-in, report on change ──────────────────────────────


def fake_agent(enabled=True, status="verified"):
    from votal_device_agent.agent import Agent
    policy = {"discovery": {"enabled": enabled}, "discovery_catalog": CATALOG} if enabled is not None else {}
    a = SimpleNamespace(engine=SimpleNamespace(policy=policy, trust=SimpleNamespace(status=status)),
                        DISCOVERY_EVERY_S=Agent.DISCOVERY_EVERY_S, DISCOVERY_RESEND_S=Agent.DISCOVERY_RESEND_S)
    a.ai_inventory = lambda: Agent.ai_inventory(a)
    return a


def test_the_agent_reports_only_when_enabled_and_changed(monkeypatch):
    obs = [{"kind": "binary", "binary": "claude"}]
    monkeypatch.setattr(dc, "collect", lambda *a, **k: list(obs))
    assert fake_agent(enabled=False).ai_inventory() is None
    assert fake_agent(enabled=None).ai_inventory() is None
    assert fake_agent(status="tampered").ai_inventory() is None
    a = fake_agent()
    assert a.ai_inventory() == obs
    a._disc_sent = (a._disc_pending, time.time())           # the heartbeat reached Shield
    assert a.ai_inventory() is None                           # unchanged
    a._disc_sent = (a._disc_pending, time.time() - 2 * 86400)
    assert a.ai_inventory() == obs                            # a day passed: resend
    obs.append({"kind": "port", "port": 11434})
    a._disc_at = 0                                            # next hourly collection
    a._disc_sent = (a._disc_pending, time.time())
    assert a.ai_inventory() == obs                            # changed


def test_a_failed_heartbeat_resends_the_inventory(monkeypatch):
    monkeypatch.setattr(dc, "collect", lambda *a, **k: [{"kind": "binary", "binary": "codex"}])
    a = fake_agent()
    assert a.ai_inventory() is not None
    assert a.ai_inventory() is not None                       # never confirmed sent


# ── the server side ──────────────────────────────────────────────────


@pytest.fixture
def store(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    yield ts
    ts._fallback_store.clear()


def test_the_policy_section_is_optional_and_validated():
    from core.dlp.device_policy import PolicyError, default_policy, policy_hash, validate_policy
    base = validate_policy({})
    assert "discovery" not in base and policy_hash(base) == policy_hash(validate_policy(default_policy()))
    p = validate_policy({"discovery": {"enabled": True, "blocked_hosts": ["API.DeepSeek.com", "api.deepseek.com"]}})
    assert p["discovery"] == {"enabled": True, "blocked_hosts": ["api.deepseek.com"]}
    for bad in ({"enabled": "yes"}, {"blocked_hosts": ["not a host"]}, {"extra": 1}, "on"):
        with pytest.raises(PolicyError):
            validate_policy({"discovery": bad})


def test_the_bundle_carries_the_catalog_only_when_discovery_is_on(store):
    from api.routes_device_dlp import bundle_policy
    from core.dlp import device_store
    assert "discovery_catalog" not in bundle_policy("t1", "default")
    pol = device_store.get_policy("t1")
    pol["discovery"] = {"enabled": True, "blocked_hosts": []}
    device_store.save_policy("t1", pol)
    b = bundle_policy("t1", "default")
    assert b["discovery"]["enabled"] and b["discovery_catalog"]["version"] == cat.VERSION
    assert any(e["id"] == "claude" for e in b["discovery_catalog"]["apps"])


def test_the_heartbeat_records_the_inventory_for_the_device(store):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_devices as rd
    from core.discovery import inventory as inv
    app = FastAPI()
    app.include_router(rd.router)
    with patch.object(rd.dv, "caller_device", return_value=("t1", "dev-1", {"hostname": "ana-mbp"})), \
            patch.object(rd.dv, "heartbeat", return_value={}):
        c = TestClient(app)
        r = c.post("/v1/devices/heartbeat", json={"state": "ok", "ai_inventory": [
            {"kind": "binary", "binary": "claude"}, {"kind": "app", "app_id": "com.apple.Notes"}]})
        assert r.status_code == 204
        assert c.post("/v1/devices/heartbeat", json={"state": "ok", "ai_inventory": "junk"}).status_code == 204
        with patch.object(inv, "record", side_effect=ConnectionError("down")):
            assert c.post("/v1/devices/heartbeat",
                          json={"ai_inventory": [{"kind": "binary", "binary": "codex"}]}).status_code == 204
    e = inv.get("t1", "catalog:claude-code")
    assert e["sources"] == ["device_agent"] and inv.subjects("t1", "catalog:claude-code").keys() == {"device:ana-mbp"}
    assert all(x["id"] != "catalog:notes" for x in inv.all_entries("t1"))
