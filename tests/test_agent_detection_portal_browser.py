"""AI agent detection rev 8, step R7: the portal page in real Chromium
(docs/specs/agent-impersonation-defense.md section 9).

Everything on the page except Shield's own labels came from visitors'
browsers (renderers, pages, user agents) or from people typing into the
portal (labels). The page is rendered against a stubbed API that answers
with hostile values in every field, every section is opened, and no markup
from those values may become a live element or run.

Skips without Playwright and its Chromium (the `agent tag (browser)` CI job
installs both).
"""

import json
import pathlib

import pytest

pw = pytest.importorskip("playwright.sync_api")

REPO = pathlib.Path(__file__).resolve().parent.parent
X = '<img src=x onerror="window.__xss=1">'
SHS = "0" * 24

API = {
    "/v1/agent-detection/stats": {"days": [{"day": "20261118", "beacons": 5}], "fleets_active": 1,
                                  "indicators_active": 1, "enforcement": {"modes": {"shs": "enforce"}, "paused": False}},
    "/v1/agent-detection/tag": {"version": X, "integrity": X, "configured": False, "site_keys": [{
        "site_key": X, "label": X, "origins": [X], "consent": X, "traps": True, "xff_hops": 1,
        "reporting": {"last_beacon": 1, "kinds": {X: 1}, "traps_shown": True},
        "snippet_first_party": X, "snippet_direct": X}]},
    "/v1/agent-detection/detections": {"detections": [{
        "shs": SHS, "last": 1, "band": X, "score": X, "reasons": [X], "fleet_id": X,
        "decoys": [{"decoy": X, "followed": True, "key_match": True}], "pseudo": True}]},
    "/v1/agent-detection/decoys/edge": {"nginx": X, "forward": [], "robots_txt_line": X},
    "/v1/agent-detection/decoys": {"enabled": True, "key_prefix": X, "stack": X, "stacks": [X],
        "avoid": [X], "scanners": {"cidrs": [X], "uas": [X]}, "decoys": {X: [X], "D1 admin login": X},
        "robots_txt_line": X, "paths": [X]},
    "/v1/agent-detection/sessions/": {"shs": X, "band": "grey", "score": X, "first": 1, "last": 2,
        "beacons": X, "clients": X, "networks": X, "pack": X, "reasons": [X], "pages": [X],
        "renderer": X, "renderer_class": X, "interaction": {"keys": X, "inputs": X},
        "traps": {"shown": [X], "hits": [{"trap": X, "code_from": X}]}, "links": [X]},
    "/v1/agent-detection/fleets": {"fleets": [{"id": X, "member_count": X, "networks": X, "first_seen": 1,
        "last_seen": 2, "traits": {X: X}, "bands": {X: X}, "pages": {X: X},
        "devices": [{"hash": X, "rare": True}], "clients": [{"hash": X, "value": X, "rare": False}]}]},
    "/v1/agent-detection/indicators/preview": {"settings": {"modes": {"shs": X}, "paused": True, "action": X,
        "lifetime_s": X}, "indicators": [{"id": X, "type": "client", "value": X, "reason": X, "mode": X,
        "expires": 1}], "published": X, "would_publish": X},
    "/v1/agent-detection/feed-tokens": {"feed_tokens": [{"id": X, "label": X, "hint": X, "created": 1}]},
    "/v1/agent-detection/enforcement/log": {"events": [{"ts": 1, "event": X, X: X}]},
}


@pytest.fixture(scope="module")
def page():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no Chromium for Playwright: {exc}")
        pg = b.new_page()
        pg.on("dialog", lambda d: d.accept())
        pg.set_content("<!doctype html><div id=root></div>")
        pg.add_script_tag(content=(REPO / "static" / "agent-detection-ui.js").read_text())
        pg.evaluate("""api => {
            window.__toasts = [];
            const answer = path => {
                const key = Object.keys(api).sort((a, b) => b.length - a.length).find(k => path.startsWith(k));
                return key ? JSON.parse(JSON.stringify(api[key])) : {};
            };
            window.UI = window.AgentDetectionUI.mount({ root: document.getElementById('root'),
                api: async (path) => answer(path), apiBase: 'https://shield.example',
                toast: (m) => window.__toasts.push(m) });
        }""", API)
        yield pg
        b.close()


def _settle(page):
    page.wait_for_timeout(150)


@pytest.mark.parametrize("section", ["tag", "detections", "fleets", "enforcement", "decoys"])
def test_hostile_values_never_become_markup(page, section):
    page.click(f"[data-ad-sec={section}]")
    _settle(page)
    if section == "detections":
        page.click("[data-ad-act=open-session]")
        _settle(page)
    if section == "decoys":
        page.click("[data-ad-act=edge-rules]")
        _settle(page)
    assert page.evaluate("window.__xss") is None
    assert page.evaluate("document.querySelectorAll('#root img').length") == 0
    text = page.inner_text("#root")
    assert 'onerror="window.__xss=1"' in text            # shown as text, not run


def test_each_section_renders_its_parts(page):
    page.click("[data-ad-sec=enforcement]")
    _settle(page)
    assert page.locator("text=Publishing is paused").count() == 1
    assert page.locator("[data-ad-act=kill]").count() == 1
    assert page.locator("text=X-Shield-Feed-Token").count() >= 1
    page.click("[data-ad-sec=tag]")
    _settle(page)
    assert page.locator("text=reporting").count() >= 1
