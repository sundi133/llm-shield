"""AI discovery, task 4: `shield-mcp discover`. Spec: docs/specs/ai-discovery.md.

Planted keys are built at runtime so no key-shaped literal is committed.
"""

import json
import pprint
import secrets
import string

import pytest

from shield_mcp import ai_signals, cli
from shield_mcp import discover as dc


def _rand(n):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


ANT_KEY = "sk-" + "ant-" + "api03-" + _rand(40)
GROQ_KEY = "gsk" + "_" + _rand(52)


@pytest.fixture
def py_repo(tmp_path):
    r = tmp_path / "py-svc"
    (r / "app").mkdir(parents=True)
    (r / "requirements.txt").write_text("fastapi==0.110\nOpenAI>=1.30  # sdk\nllama_index[all]\n-e ./local\n")
    (r / "pyproject.toml").write_text('[project]\nname = "svc"\ndependencies = ["anthropic>=0.40", "requests"]\n'
                                      '[project.optional-dependencies]\nagents = ["langgraph"]\n')
    (r / "app" / "client.py").write_text(
        'import anthropic\nKEY = "%s"\nBASE = "https://api.groq.com/openai/v1"\nx = "docs.python.org"\n' % ANT_KEY)
    (r / ".env.example").write_text("GROQ_API_KEY=%s\n" % GROQ_KEY)
    (r / "node_modules" / "openai").mkdir(parents=True)
    (r / "node_modules" / "openai" / "package.json").write_text('{"dependencies": {"@anthropic-ai/sdk": "1"}}')
    return r


@pytest.fixture
def node_repo(tmp_path):
    r = tmp_path / "web"
    r.mkdir()
    (r / "package.json").write_text(json.dumps({"dependencies": {"ai": "4", "@langchain/core": "0.3", "react": "18"},
                                                "devDependencies": {"@modelcontextprotocol/sdk": "1.0"}}))
    (r / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github", "--token", GROQ_KEY],
                   "env": {"GITHUB_TOKEN": "ghp_" + _rand(36)}},
        "remote": {"url": "https://user:pw@mcp.linear.app/sse?key=abc"}}}))
    (r / "src").mkdir()
    (r / "src" / "ai.ts").write_text('fetch("https://generativelanguage.googleapis.com/v1beta/models")\n')
    return r


def _by(rep, kind):
    return [f for f in rep.findings if f.kind == kind]


def test_python_sdks_frameworks_hosts_and_keys(py_repo):
    rep = dc.scan(str(py_repo), repo="org/py-svc")
    pkgs = {f.detail["package"]: (f.catalog_id, f.path, f.line) for f in _by(rep, "package")}
    assert pkgs["openai"] == ("openai-api", "requirements.txt", 2)
    assert pkgs["llama-index"][0] == "llamaindex" and pkgs["anthropic"][0] == "anthropic-api"
    assert pkgs["langgraph"][0] == "langgraph" and "fastapi" not in pkgs and "requests" not in pkgs
    assert {f.name for f in _by(rep, "domain")} == {"api.groq.com"}
    keys = {(f.catalog_id, f.path) for f in _by(rep, "key")}
    assert keys == {("anthropic-api", "app/client.py"), ("groq", ".env.example")}
    assert not any("node_modules" in f.path for f in rep.findings)


def test_node_packages_and_mcp_definitions(node_repo):
    rep = dc.scan(str(node_repo), repo="org/web")
    pkgs = {f.detail["package"]: f.catalog_id for f in _by(rep, "package")}
    assert pkgs == {"npm:ai": "vercel-ai-sdk", "npm:@langchain/core": "langchain",
                    "npm:@modelcontextprotocol/sdk": "mcp-sdk"}
    mcp = {f.name: f.detail["mcp"] for f in _by(rep, "mcp_server")}
    assert mcp["github"] == {"server_name": "github", "command": "npx", "package": "@modelcontextprotocol/server-github",
                             "host": "", "client": "repo"}
    assert mcp["remote"]["host"] == "mcp.linear.app"
    assert "generativelanguage.googleapis.com" in {f.name for f in _by(rep, "domain")}


def test_keys_and_secrets_never_leave_the_report_or_the_batch(py_repo, node_repo):
    for repo in (py_repo, node_repo):
        rep = dc.scan(str(repo), repo="org/x")
        for blob in (json.dumps(rep.to_dict()), dc.render_human(rep), json.dumps(dc.observations(rep))):
            for secret in (ANT_KEY, GROQ_KEY, "ghp_", "pw@", "key=abc", "--token"):
                assert secret not in blob, secret


def test_the_batch_has_no_paths_and_is_attributed_to_the_repo(py_repo):
    rep = dc.scan(str(py_repo), repo="org/py-svc")
    obs = dc.observations(rep)
    assert all(o["subject"] == {"type": "repo", "id": "org/py-svc"} for o in obs)
    assert {"kind": "catalog", "catalog_id": "anthropic-api", "subject": {"type": "repo", "id": "org/py-svc"}} in obs
    blob = json.dumps(obs)
    assert "client.py" not in blob and "requirements" not in blob and '"line"' not in blob
    assert len(obs) == len({json.dumps(o, sort_keys=True) for o in obs})


def test_the_batch_is_accepted_by_the_inventory(py_repo, node_repo, monkeypatch):
    import storage.tenant_store as ts
    from core.discovery import inventory as inv
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    try:
        obs = dc.observations(dc.scan(str(py_repo), repo="org/py-svc")) + \
            dc.observations(dc.scan(str(node_repo), repo="org/web"))
        out = inv.record("t1", "repo_scan", obs)
        assert out["dropped"] == 0
        ids = {e["id"] for e in inv.all_entries("t1")}
        assert {"catalog:openai-api", "catalog:anthropic-api", "catalog:groq", "catalog:llamaindex",
                "catalog:vercel-ai-sdk", "catalog:mcp-sdk"} <= ids
        assert inv.get("t1", "catalog:groq")["governed"] in (False, "partial")
    finally:
        ts._fallback_store.clear()


def test_repo_name_strips_credentials(tmp_path, monkeypatch):
    import subprocess
    for url, want in (("https://x-access-token:abc@github.com/org/repo.git", "org/repo"),
                      ("git@github.com:org/repo.git", "org/repo"),
                      ("ssh://git@gitlab.example.com/group/sub/repo", "sub/repo")):
        monkeypatch.setattr(subprocess, "run", lambda *a, _u=url, **k: type("R", (), {"stdout": _u})())
        assert dc._repo_name(tmp_path) == want
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ""})())
    assert dc._repo_name(tmp_path) == tmp_path.name


def test_cli_exit_codes_and_json(py_repo, tmp_path, capsys):
    assert cli.main(["discover", str(py_repo), "--repo", "org/py-svc", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["repo"] == "org/py-svc" and out["summary"]["key"] == 2
    assert cli.main(["discover", str(py_repo), "--fail-on-key"]) == 2
    capsys.readouterr()
    assert cli.main(["discover", str(tmp_path / "missing")]) == 4
    assert cli.main(["discover", str(py_repo), "--post"]) == 4          # no url or key


def test_cli_post_sends_only_the_batch(py_repo, monkeypatch, capsys):
    sent = {}

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"accepted": 5, "new_entries": 3}

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.update(url=url, body=json, headers=headers)
        return R()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    assert cli.main(["discover", str(py_repo), "--post", "--shield-url", "https://shield.test/",
                     "--api-key", "local-test-key", "--repo", "org/py-svc"]) == 0
    assert sent["url"] == "https://shield.test/v1/shield/discovery/batch"
    assert sent["body"]["source"] == "repo_scan" and sent["headers"] == {"X-API-Key": "local-test-key"}
    assert "3 new in the AI inventory" in capsys.readouterr().out


def test_signals_match_the_catalog():
    from core.discovery.catalog import shield_mcp_signals
    want = shield_mcp_signals()
    assert ai_signals.SIGNALS == want, (
        "packages/shield-mcp/src/shield_mcp/ai_signals.py is out of date with the AI catalog; "
        "replace its SIGNALS with:\n" + pprint.pformat(want, width=100))


def test_mcp_package_rules_match_the_device_agent():
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "packages", "votal-device-agent"))
    from votal_device_agent import discovery as agent
    cases = [("npx", ["-y", "@scope/server@1.2.0"]), ("docker", ["run", "-e", "T=1", "-e", "X", "ghcr.io/o/m"]),
             ("uvx", ["--from", "git+https://x", "mcp-x"]), ("python3", ["-m", "mcp_server_time"]),
             ("node", ["/abs/index.js"]), ("npx", ["-y", "some-mcp@latest", "--key", "abc"])]
    for command, args in cases:
        assert dc.package_from(command, args) == agent._package_from(command, args), (command, args)


def test_short_key_shaped_test_values_are_not_reported(tmp_path):
    # Shield's own test admin keys look like "sk-admin-" plus a short value;
    # real OpenAI project, service and admin keys are far longer.
    (tmp_path / "t.py").write_text('ADMIN_KEY = "sk-' + 'admin-' + "a" * 14 + '"\n')
    assert _by(dc.scan(str(tmp_path)), "key") == []
    (tmp_path / "t.py").write_text('K = "sk-' + 'proj-' + _rand(60) + '"\n')
    assert [f.catalog_id for f in _by(dc.scan(str(tmp_path)), "key")] == ["openai-api"]
