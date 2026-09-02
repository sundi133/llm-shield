"""The governed/bypassing call is the whole point, so it gets a test.

Everything else the scanner does is enumeration, which is environment-dependent
and not worth pinning. The classification is neither: it is one rule applied to
a URL, and getting it wrong means telling somebody their traffic is governed
when it is not.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from ai_surface_scan import _is_governed, scan_mcp  # noqa: E402


@pytest.mark.parametrize("url,governed", [
    ("https://api.guardrails.votal.ai/gateway/rp-test/mcp", True),
    ("https://api.guardrails.votal.ai/gateway/jc-india/mcp", True),
    ("https://shield.acme.internal/gateway/prod/mcp", True),
    ("https://api.guardrails.votal.ai/v1/shield/tool/check", True),
    # The ones that actually happen, and each looks fine at a glance.
    ("https://ai.jumpcloud.com/mcp", False),
    ("http://localhost:9100/mcp", False),
    ("https://mcp-sast.votal.ai/api/mcp", False),
    ("https://api.guardrails.votal.ai/mcp", False),
])
def test_only_a_gateway_route_counts_as_governed(url, governed):
    assert _is_governed(url) is governed


def test_a_shield_hostname_alone_is_not_enough():
    """The near miss worth pinning: right host, wrong path.

    Somebody reading a config sees the vendor's domain and concludes it is
    governed. Only the route is.
    """
    assert not _is_governed("https://api.guardrails.votal.ai/direct/mcp")


def test_stdio_servers_are_reported_as_ungoverned(tmp_path, monkeypatch):
    """No URL means no route, so it cannot be governed by network policy.

    Reporting these as unknown would be worse than reporting them as gaps:
    unknown reads as "probably fine" and they are not.
    """
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "local": {"command": "npx", "args": ["-y", "some-server"]},
        "remote": {"url": "https://x.example/gateway/p/mcp"},
    }}))
    import ai_surface_scan as s
    monkeypatch.setattr(s, "MCP_CONFIGS", {"Test": [cfg]})

    found = {f.name.split("/")[-1]: f for f in s.scan_mcp()}
    assert found["local"].governed is False
    assert "allowlisting" in found["local"].note
    assert found["remote"].governed is True


def test_a_missing_or_broken_config_does_not_crash(tmp_path, monkeypatch):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    import ai_surface_scan as s
    monkeypatch.setattr(s, "MCP_CONFIGS",
                        {"Test": [bad, tmp_path / "absent.json"]})
    assert s.scan_mcp() == []
