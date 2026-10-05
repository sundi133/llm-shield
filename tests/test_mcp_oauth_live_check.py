"""The local live-check harness for OAuth-brokered MCP routes
(scripts/mcp_oauth_live_check.py, docs/specs/mcp-oauth-standard-providers.md
task 4): importing it starts nothing, `check` needs the tenant key, and the
harness never binds beyond localhost.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("live_check", ROOT / "scripts" / "mcp_oauth_live_check.py")
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


def test_importing_it_starts_nothing_and_it_binds_only_to_localhost():
    assert live.HOST == "127.0.0.1"
    assert live.CALLBACK == "http://localhost:8121/v1/tenant/me/mcp/oauth/callback"


def test_check_without_the_tenant_key_stops(monkeypatch, capsys):
    monkeypatch.delenv("SHIELD_TENANT_KEY", raising=False)
    assert live.main(["check"]) == 2
    assert "SHIELD_TENANT_KEY" in capsys.readouterr().out


def test_check_never_prints_a_token(monkeypatch, capsys):
    """Every server reply is reduced to counts and states before printing."""
    monkeypatch.setenv("SHIELD_TENANT_KEY", "k")
    secret = "ya29.SHOULD-NOT-PRINT"

    def fake_http(method, path, key, body=None):
        if path.endswith("/oauth"):
            return 200, {"oauth": {"status": "connected", "profile": "google",
                                   "authorization_header": "brokered", "expires_at": 1,
                                   "access_token": secret}}
        if path.startswith("/_live_check/renew"):
            return 200, {"expires_at": 2}
        if path == "/v1/agents/registry":
            return 200, {}
        if body and body.get("method") == "tools/list":
            return 200, {"result": {"tools": [{"name": "list_recent_files"}]}}
        return 200, {"result": {"isError": False, "content": [{"type": "text", "text": secret}]}}
    monkeypatch.setattr(live, "_http", fake_http)
    assert live.main(["check"]) == 0
    out = capsys.readouterr().out
    assert secret not in out and "PASS" in out
