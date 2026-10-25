"""The tenant portal's sidebar groups (static/tenant.html).

The groups are labels only: every page keeps its data-tab, so its loader, its
deep links (_gotoTab) and the buttons that click it keep working. These checks
catch a regrouping that drops a page, lists one twice, or loses a badge.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
SIDEBAR = HTML[HTML.index('<aside class="sidebar">'):HTML.index("</aside>")]

GROUPS = {
    "AI Assets": ["ai-inventory", "agents", "tool-policies", "aibom"],
    "Identity & Access": ["agent-identity", "agent-authentication", "people"],
    "Runtime Protection": ["policies", "mcp-gateway", "model-routing", "runtime-profiles",
                           "device-dlp", "cross-app-flow", "embodied-guard"],
    "Security Operations": ["workflow-controls", "activity", "telemetry", "guardrail-metrics",
                            "kill-switch"],
    "Governance & Reporting": ["governance", "exception-requests", "board-report"],
    "Developer Tools": ["apis", "webhooks", "inbound-webhooks", "siem", "usage"],
    "Votal AI Platform": ["system-health"],
}


def _sections():
    out = {}
    for block in SIDEBAR.split('<div class="nav-section">')[1:]:
        m = re.search(r'<div class="nav-label">([^<]+)</div>', block)
        title = m.group(1).replace("&amp;", "&") if m else None
        out[title] = re.findall(r'data-tab="([^"]+)"', block)
    return out


def test_the_groups_in_order():
    sections = _sections()
    assert list(sections) == [None] + list(GROUPS)
    assert sections[None] == ["overview"]
    for title, tabs in GROUPS.items():
        assert sections[title] == tabs, title


def test_every_page_is_listed_exactly_once_and_has_a_pane():
    tabs = re.findall(r'data-tab="([^"]+)"', SIDEBAR)
    assert len(tabs) == len(set(tabs)) == 29
    for tab in tabs:
        assert f'id="tab-{tab}"' in HTML, tab


def test_playground_stays_in_developer_tools():
    dev = SIDEBAR.split('<div class="nav-label">Developer Tools</div>')[1].split("nav-section")[0]
    assert "window.open('/playground'" in dev


def test_badges_survive():
    for badge in ("nav-badge-agents", "nav-badge-tools", "nav-badge-mcp", "nav-badge-governance",
                  "nav-badge-aibom", "nav-badge-model-routing", "nav-badge-ai-inventory",
                  "nav-badge-authz", "nav-badge-health", "ex-nav-count"):
        assert SIDEBAR.count(f'id="{badge}"') == 1, badge
