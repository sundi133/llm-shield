"""AI agent detection rev 8, step R3, in a real browser
(docs/specs/agent-impersonation-defense.md sections 2.4 and 12).

The collector runs for real (uvicorn in a thread) and serves a test page with
the tag; Chromium loads it. Checks what only a browser can show:

  - traps are out of the accessibility tree and the tab order;
  - trap inputs are not posted with the customer's form;
  - a person typing in a real field reports no trap hit;
  - an agent that obeys the hidden instruction is caught with its own code;
  - following the hidden link lands as a canary hit for that session.

Skips without Playwright and its Chromium (the `agent tag (browser)` CI job
installs both).
"""

import json
import socket
import threading
import time
import urllib.request

import pytest

pw = pytest.importorskip("playwright.sync_api")

from core.agent_detection import collector, sitekeys, stream, tag, traps  # noqa: E402
from storage import tenant_store as ts  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _shs_with(inert: bool) -> str:
    for i in range(1000):
        shs = f"{i:024x}"
        if traps.layout("acme", shs)["inert"] is inert:
            return shs
    raise AssertionError("no session with that rotation")


@pytest.fixture(scope="module")
def server():
    mp = pytest.MonkeyPatch()
    mp.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "test-salt")
    mp.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "test-trap-secret")
    mp.delenv("SHIELD_AGENT_DETECTION_COLLECTOR", raising=False)
    mp.setattr(ts, "_get_redis", lambda: None)
    sitekeys._reset_memory_for_tests(); stream._reset_memory_for_tests(); traps._reset_memory_for_tests()
    port = _free_port()
    origin = f"http://127.0.0.1:{port}"
    key = sitekeys.create("acme", origins=[origin])["site_key"]
    app = collector.create_app()
    snippet = tag.snippet(key, origin, origin).replace(' integrity="', ' data-x="')  # same bytes; SRI checked in R2
    from fastapi.responses import HTMLResponse
    page = ("<!doctype html><html lang=en><title>Sign up</title><main><h1>Sign up</h1>"
            "<form id=f action=/nowhere method=post onsubmit='return false'>"
            "<label for=email>Email</label><input id=email name=email>"
            "<button type=submit>Create account</button></form></main>" + snippet + "</html>")
    app.add_api_route("/page", lambda: HTMLResponse(page))
    import uvicorn
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        try:
            urllib.request.urlopen(origin + "/health", timeout=0.2)
            break
        except OSError:
            time.sleep(0.05)
    yield {"origin": origin, "key": key}
    srv.should_exit = True
    t.join(timeout=5)
    mp.undo()


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"no Chromium for Playwright: {exc}")
        yield b
        b.close()


def _open(browser, server, shs):
    ctx = browser.new_context()
    ctx.add_cookies([{"name": "_shs", "value": shs, "url": server["origin"]}])
    page = ctx.new_page()
    page.goto(server["origin"] + "/page")
    page.wait_for_selector("input[data-shs]", state="attached", timeout=5000)
    return page


def _entries(shs):
    return [e for e in stream.memory_entries("acme") if e.get("shs") == shs]


def _submit_entries(shs, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        got = [e for e in _entries(shs) if e["kind"] == "submit"]
        if got:
            return got
        time.sleep(0.05)
    return []


def test_traps_are_invisible_to_assistive_tech_and_keyboards(browser, server):
    shs = _shs_with(inert=False)
    page = _open(browser, server, shs)
    lay = traps.layout("acme", shs)
    tree = page.locator("body").aria_snapshot()
    assert lay["t1"]["text"][:30] not in tree and lay["t2"]["text"] not in tree
    assert "Email" in tree and "Create account" in tree
    focused = []
    for _ in range(8):
        page.keyboard.press("Tab")
        focused.append(page.evaluate("document.activeElement && (document.activeElement.getAttribute('data-shs') "
                                     "|| document.activeElement.tagName)"))
    assert "t1" not in focused and "t4" not in focused and "A" not in focused
    assert page.evaluate("[...new FormData(document.forms[0]).keys()]") == ["email"]
    page.context.close()


def test_a_person_typing_reports_no_trap_hit(browser, server):
    shs = _shs_with(inert=False)
    page = _open(browser, server, shs)
    page.click("#email")
    page.keyboard.type("ana@example.com", delay=20)
    page.click("button[type=submit]")
    [sub] = _submit_entries(shs)[-1:]
    assert sub["traps"]["hit"] == [] and set(sub["traps"]["shown"]) >= {"T1", "T2"}
    assert sub["interaction"]["fields_touched"] == 1             # the trap inputs aren't counted
    page.context.close()


def test_an_agent_that_obeys_is_caught_with_its_own_code(browser, server):
    shs = _shs_with(inert=False)
    page = _open(browser, server, shs)
    text = page.locator("[aria-hidden=true] p").first.text_content()
    code = next(w.strip(".") for w in text.split() if len(w.strip(".")) == 8 and all(
        ch in "0123456789abcdef" for ch in w.strip(".")))
    page.fill("#email", "agent@example.com")
    page.fill("input[data-shs=t1]", code, force=True)
    page.click("button[type=submit]")
    [sub] = _submit_entries(shs)[-1:]
    assert {"trap": "T1", "code_match": True} in sub["traps"]["hit"]
    assert code not in json.dumps(sub)
    page.context.close()


def test_inert_traps_refuse_playwright_fill(browser, server):
    """The lab finding (spec 2.4): `inert` stops Playwright's fill, so half
    the sessions measure agents that read the text but can't type it in."""
    page = _open(browser, server, _shs_with(inert=True))
    with pytest.raises(Exception):
        page.fill("input[data-shs=t1]", "x", timeout=1000)
    page.context.close()


def test_following_the_hidden_link_is_a_canary_hit(browser, server):
    shs = _shs_with(inert=False)
    page = _open(browser, server, shs)
    href = page.locator("[aria-hidden=true] a").get_attribute("href")
    assert href.startswith(server["origin"] + "/v/") and server["key"] in href
    try:
        page.goto(href)                     # 204: Chrome aborts the navigation and stays put
    except pw.Error as exc:
        assert "ERR_ABORTED" in str(exc)
    assert page.url.endswith("/page")
    end = time.time() + 3
    while time.time() < end and not [e for e in _entries(shs) if e["kind"] == "canary"]:
        time.sleep(0.05)
    [hit] = [e for e in _entries(shs) if e["kind"] == "canary"]
    assert hit["traps"]["hit"][0]["trap"] == "T2"
    page.context.close()
