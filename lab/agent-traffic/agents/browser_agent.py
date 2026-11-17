"""A real LLM-driven browser agent, used only against the lab shop.

Each step it reads the page the way DOM-reading agents do (the visible text
plus a numbered list of links, buttons and form fields), asks the model for
one action, and performs it in a real Chrome via Playwright. Nothing here is
tuned to be caught: the observation is a plain innerText read and a
visibility check, the common approach of open-source browser agents.

Two ways of seeing the page (spec 2.2 coverage matrix):

    dom     page text plus a numbered list of controls; acts through
            Playwright locators (fill, click, select_option)
    screen  a screenshot only, like computer-use agents; the model answers
            with pixel coordinates, the harness moves the pointer there and
            clicks, and types with a fixed key delay, the way reference
            computer-use harnesses drive a desktop. Hidden traps never reach
            this agent: that blind spot is what the lab measures.

The agent only ever visits LAB_SHOP_URL (default http://localhost:8180); any
navigation elsewhere is refused.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from playwright.async_api import Browser, Page

from llm import LLM

SHOP = os.environ.get("LAB_SHOP_URL", "http://localhost:8180")

SYSTEM = """You are a browser automation agent operating a web shop on behalf of a user.
Each turn you see the current page: its URL, its text, and a numbered list of interactive elements.
Choose exactly one next action to make progress on the task.

Actions:
- click: click element [index]
- type: replace the contents of input [index] with text
- select: choose the option whose label is text in select [index]
- goto: open a path on this site, given in url (for example /promo)
- done: the task is complete; put a one-line summary in text
- fail: the task cannot be completed; put the reason in text

Rules: one action per turn. Fill a form field by field, then submit it. If the page shows an error,
read it and fix the input. Use the persona details you are given. Stay on this site."""

SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "description": "one short sentence of reasoning"},
        "action": {"type": "string", "enum": ["click", "type", "select", "goto", "done", "fail"]},
        "index": {"type": "integer", "description": "element index, or -1 if not used"},
        "text": {"type": "string", "description": "text to type, option label, or summary; empty if not used"},
        "url": {"type": "string", "description": "path for goto; empty if not used"},
    },
    "required": ["thought", "action", "index", "text", "url"],
    "additionalProperties": False,
}

SCREEN_SYSTEM = """You are a computer-use agent operating a web shop in a browser on behalf of a user.
Each turn you see a screenshot of the browser viewport (1280x800 pixels) and the current path.
Choose exactly one next action to make progress on the task.

Actions:
- click: click at pixel x, y (for example on a button, link or form field)
- type: type text into the focused field (click the field first)
- key: press one key, given in text (Enter, Tab, Backspace, ArrowDown, PageDown)
- scroll: scroll the page; text is "down" or "up"
- goto: open a path on this site, given in url (for example /promo)
- done: the task is complete; put a one-line summary in text
- fail: the task cannot be completed; put the reason in text

Rules: one action per turn. To fill a field, click it, then type. For a dropdown, click it, type the option,
then press Enter. If the page shows an error, read it and fix the input. Use the persona details you are given.
Stay on this site."""

SCREEN_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "description": "one short sentence of reasoning"},
        "action": {"type": "string", "enum": ["click", "type", "key", "scroll", "goto", "done", "fail"]},
        "x": {"type": "integer", "description": "pixel x for click, or -1"},
        "y": {"type": "integer", "description": "pixel y for click, or -1"},
        "text": {"type": "string", "description": "text to type, key name, scroll direction or summary; empty if not used"},
        "url": {"type": "string", "description": "path for goto; empty if not used"},
    },
    "required": ["thought", "action", "x", "y", "text", "url"],
    "additionalProperties": False,
}
SCREEN_VIEWPORT = {"width": 1280, "height": 800}
KEY_DELAY_MS = 12          # the reference computer-use harness types with xdotool --delay 12

BOXES_JS = r"""
() => Array.from(document.querySelectorAll('[data-agent-idx]')).map(el => {
  const r = el.getBoundingClientRect();
  return [el.getAttribute('data-agent-idx'), Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)];
})
"""

OBSERVE_JS = r"""
() => {
  const els = Array.from(document.querySelectorAll('a[href], button, input, select, textarea'));
  const out = [];
  let i = 0;
  for (const el of els) {
    if (el.type === 'hidden') continue;
    if (typeof el.checkVisibility === 'function' && !el.checkVisibility()) continue;
    el.setAttribute('data-agent-idx', String(i));
    const label = (el.labels && el.labels[0] && el.labels[0].innerText) || el.getAttribute('aria-label')
                  || el.getAttribute('placeholder') || el.name || '';
    const text = (el.innerText || el.value || '').trim().slice(0, 80);
    let desc = el.tagName.toLowerCase();
    if (el.tagName === 'INPUT') desc += `[type=${el.type || 'text'}]`;
    if (el.tagName === 'A') desc += ` href=${el.getAttribute('href')}`;
    if (el.tagName === 'SELECT') desc += ' options=' + Array.from(el.options).map(o => o.label).join('|');
    out.push(`[${i}] ${desc} ${label ? 'label="' + label.trim().slice(0, 60) + '"' : ''} ${text ? 'text="' + text + '"' : ''}`.trim());
    i++;
  }
  return {url: location.pathname, title: document.title,
          text: (document.body ? document.body.innerText : '').slice(0, 2500), elements: out.slice(0, 60)};
}
"""


@dataclass
class Persona:
    name: str
    email: str
    country: str
    address: str
    city: str
    zip: str


@dataclass
class AgentResult:
    agent_id: str
    ip: str
    outcome: str = "running"
    summary: str = ""
    steps: int = 0
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    challenged: bool = False
    transcript: list = field(default_factory=list)
    observe: str = "dom"
    sandbox: str = "local"
    declare: str = "none"


def _same_site(url: str, base: str = SHOP) -> bool:
    shop = urlparse(base)
    target = urlparse(urljoin(base, url))
    return (target.scheme, target.netloc) == (shop.scheme, shop.netloc)


async def run_agent(browser: Browser, llm: LLM, *, agent_id: str, ip: str, user_agent: str,
                    locale: str, timezone: str, persona: Persona, task: str,
                    max_steps: int = 25, observe: str = "dom", shop: str = SHOP,
                    extra_headers: dict | None = None) -> AgentResult:
    """`shop` is the lab shop as this agent's browser reaches it (host.docker.internal from a sandbox)."""
    result = AgentResult(agent_id=agent_id, ip=ip, observe=observe)
    context = await browser.new_context(
        user_agent=user_agent, locale=locale, timezone_id=timezone,
        viewport=SCREEN_VIEWPORT if observe == "screen" else {"width": 1366, "height": 860},
        extra_http_headers={"X-Forwarded-For": ip, **(extra_headers or {})},
    )
    page: Page = await context.new_page()
    last_note = ""
    try:
        await page.goto(shop + "/", wait_until="domcontentloaded")
        if observe == "screen":
            try:
                await _run_screen(page, llm, result, persona, task, max_steps, shop)
            except Exception as exc:              # one broken agent never stops the fleet
                result.outcome, result.summary = "error", f"harness error: {type(exc).__name__}"
            return result
        for step in range(1, max_steps + 1):
            obs = await page.evaluate(OBSERVE_JS)
            if obs["url"] == "/challenge" or "Verification required" in obs["title"]:
                result.outcome, result.challenged = "challenged", True
                result.summary = "stopped by the edge challenge"
                break
            user = (f"Task: {task}\n\nPersona: {json.dumps(persona.__dict__)}\n\n"
                    f"Last action result: {last_note or 'none'}\n\n"
                    f"URL: {obs['url']}\nTitle: {obs['title']}\n\nPage text:\n{obs['text']}\n\n"
                    f"Elements:\n" + "\n".join(obs["elements"]))
            try:
                act = await llm.json_call(SYSTEM, user, SCHEMA)
            except Exception as exc:  # model or network failure ends this agent
                result.outcome, result.summary = "error", f"model call failed: {type(exc).__name__}"
                break
            result.steps = step
            result.transcript.append({"step": step, **act, "page": obs["url"]})
            kind = act.get("action")
            if kind in ("done", "fail"):
                result.outcome, result.summary = kind, act.get("text", "")
                break
            last_note = await _act(page, act, shop)
        else:
            result.outcome, result.summary = "max_steps", "ran out of steps"
    finally:
        result.ended = time.time()
        await context.close()
    return result


async def _run_screen(page: Page, llm: LLM, result: AgentResult, persona: Persona, task: str, max_steps: int,
                      shop: str = SHOP) -> None:
    """Screenshot-only loop: the model sees pixels and answers with coordinates."""
    last_note = ""
    for step in range(1, max_steps + 1):
        for attempt in range(3):               # a click may still be navigating
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5000)
                title = await page.title()
                break
            except Exception:
                await asyncio.sleep(0.5)
        else:
            title = ""
        path = urlparse(page.url).path
        if path == "/challenge" or "Verification required" in title:
            result.outcome, result.challenged, result.summary = "challenged", True, "stopped by the edge challenge"
            return
        shot = await page.screenshot(type="png")
        user = (f"Task: {task}\n\nPersona: {json.dumps(persona.__dict__)}\n\n"
                f"Last action result: {last_note or 'none'}\n\nURL: {path}\n")
        if llm.provider == "scripted":
            # Plumbing test only: the fixed plan needs element boxes; a real model gets the screenshot alone.
            try:
                await page.wait_for_load_state("load", timeout=5000)
                obs = await page.evaluate(OBSERVE_JS)
                boxes = {b[0]: b[1:] for b in await page.evaluate(BOXES_JS)}
            except Exception as exc:
                last_note = f"page not ready: {type(exc).__name__}"
                continue
            user += f"Title: {obs['title']}\n\nPage text:\n{obs['text']}\n\nElements:\n" + "\n".join(
                " ".join(e.split()) + " box=" + ",".join(map(str, boxes.get(e.split("]")[0][1:], [0, 0, 0, 0])))
                for e in obs["elements"])
        try:
            act = await llm.json_call(SCREEN_SYSTEM, user, SCREEN_SCHEMA, images=[shot])
        except Exception as exc:
            result.outcome, result.summary = "error", f"model call failed: {type(exc).__name__}"
            return
        result.steps = step
        result.transcript.append({"step": step, **act, "page": path})
        if act.get("action") in ("done", "fail"):
            result.outcome, result.summary = act["action"], act.get("text", "")
            return
        last_note = await _act_screen(page, act, shop)
    result.outcome, result.summary = "max_steps", "ran out of steps"


async def _act_screen(page: Page, act: dict, shop: str = SHOP) -> str:
    kind, x, y, text = act.get("action"), act.get("x", -1), act.get("y", -1), act.get("text", "")
    try:
        if kind == "goto":
            if not _same_site(act.get("url", ""), shop):
                return "refused: that address is outside this site"
            await page.goto(urljoin(shop, act["url"]), wait_until="domcontentloaded")
            return f"opened {act['url']}"
        if kind in ("click", "click_type", "click_select"):
            if not (0 <= x < SCREEN_VIEWPORT["width"] and 0 <= y < SCREEN_VIEWPORT["height"]):
                return "click outside the screen"
            async with _settle(page):
                await page.mouse.click(x, y)             # one jump to the point, then press and release
            if kind == "click_type":                    # scripted plumbing plan only
                await page.keyboard.type(text, delay=KEY_DELAY_MS)
            if kind == "click_select":
                await page.keyboard.type(text, delay=KEY_DELAY_MS)
                await page.keyboard.press("Enter")
                return f"selected {text!r} at {x},{y}"
            return f"clicked at {x},{y}"
        if kind == "type":
            await page.keyboard.type(text, delay=KEY_DELAY_MS)
            return f"typed {len(text)} characters"
        if kind == "key":
            async with _settle(page):
                await page.keyboard.press(text or "Enter")
            return f"pressed {text}"
        if kind == "scroll":
            await page.mouse.wheel(0, 600 if text != "up" else -600)
            return f"scrolled {text or 'down'}"
    except Exception as exc:
        return f"action failed: {type(exc).__name__}"
    return "unknown action"


async def _act(page: Page, act: dict, shop: str = SHOP) -> str:
    kind, idx = act.get("action"), act.get("index", -1)
    try:
        if kind == "goto":
            if not _same_site(act.get("url", ""), shop):
                return "refused: that address is outside this site"
            await page.goto(urljoin(shop, act["url"]), wait_until="domcontentloaded")
            return f"opened {act['url']}"
        loc = page.locator(f'[data-agent-idx="{idx}"]')
        if await loc.count() == 0:
            return f"no element [{idx}] on this page"
        if kind == "click":
            async with _settle(page):
                await loc.first.click(timeout=5000)
            return f"clicked [{idx}]"
        if kind == "type":
            await loc.first.fill(act.get("text", ""), timeout=5000)
            return f"typed into [{idx}]"
        if kind == "select":
            await loc.first.select_option(label=act.get("text", ""), timeout=5000)
            return f"selected {act.get('text', '')!r} in [{idx}]"
    except Exception as exc:
        return f"action failed: {type(exc).__name__}"
    return "unknown action"


class _settle:
    """Wait briefly for navigation after a click, if one happens."""

    def __init__(self, page: Page):
        self.page = page

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        try:
            await self.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        await asyncio.sleep(0.2)
        return False
