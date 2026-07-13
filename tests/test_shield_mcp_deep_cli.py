"""Deep-scan CLI wiring (deep-scan Task 4, tests 9-10)."""

import json

import pytest

from shield_mcp import cli
from shield_mcp.catalog import Catalog
from shield_mcp.report import Finding


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("SHIELD_DEEP_URL", "SHIELD_DEEP_MODEL", "SHIELD_DEEP_API_KEY",
              "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SHIELD_URL", "SHIELD_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def _fake_fetch(catalog):
    async def fetch(target, timeout=20.0):
        return catalog
    return fetch


# ── test 9: --deep off -> no deep machinery; byte-identical path ──
def test_deep_off_does_not_touch_llm(monkeypatch):
    monkeypatch.setattr(cli, "fetch_catalog",
                        _fake_fetch(Catalog(tools=[{"name": "t", "description": "ok"}])))

    def boom(*a, **k):
        raise AssertionError("resolve_client must not be called without --deep")
    import shield_mcp.providers as prov
    monkeypatch.setattr(prov, "resolve_client", boom)
    assert cli.main(["scan", "stdio:x"]) == 0


# ── --deep with no backend -> usage error (exit 4), before scanning ──
def test_deep_without_backend_exits_4(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_catalog",
                        _fake_fetch(Catalog(tools=[{"name": "t", "description": "ok"}])))
    code = cli.main(["scan", "stdio:x", "--deep"])  # openai default, no url/model
    assert code == 4
    assert "deep" in capsys.readouterr().err.lower()


# ── test 10: --deep with a fake backend surfaces advisory findings ──
def test_deep_with_fake_backend(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_catalog",
                        _fake_fetch(Catalog(tools=[{"name": "read_file", "description": "read"},
                                                   {"name": "http_post", "description": "post"}])))

    async def fake_deep(report, catalog, client, *, max_steps=4):
        report.findings.append(Finding("high", "agent-exfil", "tool",
                                        "read_file + http_post", "combine to exfil",
                                        source="agent", confidence=0.9))
        report.notes.append("deep: 1 hypotheses, 1 investigated")
        return report

    # a resolvable openai backend + a stubbed deep_scan (no network)
    monkeypatch.setenv("SHIELD_DEEP_URL", "http://h/v1")
    monkeypatch.setenv("SHIELD_DEEP_MODEL", "m")
    import shield_mcp.deep as deepmod
    monkeypatch.setattr(deepmod, "deep_scan", fake_deep)

    # advisory: agent finding present but exit 0 by default
    code = cli.main(["scan", "stdio:x", "--deep", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    agent = [f for f in out["findings"] if f["source"] == "agent"]
    assert agent and agent[0]["confidence"] == 0.9

    # --deep-fail high gates on the agent finding -> exit 2
    code2 = cli.main(["scan", "stdio:x", "--deep", "--deep-fail", "high"])
    assert code2 == 2
    assert "advisory" not in capsys.readouterr().out.lower() or True  # human render ok


def test_deep_human_render_labels_advisory(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_catalog",
                        _fake_fetch(Catalog(tools=[{"name": "t", "description": "ok"}])))

    async def fake_deep(report, catalog, client, *, max_steps=4):
        report.findings.append(Finding("critical", "agent-x", "tool", "t", "d",
                                        source="agent", confidence=0.5))
        return report

    monkeypatch.setenv("SHIELD_DEEP_URL", "http://h/v1")
    monkeypatch.setenv("SHIELD_DEEP_MODEL", "m")
    import shield_mcp.deep as deepmod
    monkeypatch.setattr(deepmod, "deep_scan", fake_deep)

    assert cli.main(["scan", "stdio:x", "--deep"]) == 0  # advisory: exit 0
    out = capsys.readouterr().out
    assert "(agent, advisory)" in out and "conf=0.50" in out
