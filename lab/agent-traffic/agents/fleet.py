"""Run a fleet of real LLM browser agents under one controller, against the lab shop only.

Each agent gets its own browser context, persona and simulated residential IP
(sent as X-Forwarded-For, the way a proxy pool appears in CDN logs). All of
them share one controller, one model and one browser build: the situation the
customer described (one AI, many sandboxes).

Usage:
    python fleet.py --n 10 --concurrency 5 --label fleet10
    python fleet.py --n 1 --label single --ua-mode careful

--ua-mode
    spoofed   every agent claims Chrome on Windows while the real browser runs
              on this Mac (a common, slightly sloppy fleet setup)
    careful   the user agent matches the real browser, with "HeadlessChrome"
              removed (a careful operator)

Writes state/runs/<label>/manifest.json (ground truth: which IPs were agents,
outcomes, steps, timing, tokens) and transcripts.jsonl (each step's thought and
action).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser_agent import Persona, run_agent  # noqa: E402
from llm import LLM  # noqa: E402

LAB = Path(__file__).resolve().parent.parent
TASK = ("Create a new account for the persona, redeem the welcome promo code shown on the Promotions page, "
        "then add the cheapest product to the cart and place the order using the persona's address.")

FIRST = ["Maya", "Liam", "Ava", "Noah", "Zoe", "Ethan", "Ivy", "Lucas", "Nora", "Owen", "Ruby", "Eli",
         "Clara", "Theo", "Lena", "Arjun", "Priya", "Sofia", "Mateo", "Hana", "Omar", "Leah", "Kai", "Mila"]
LAST = ["Patel", "Nguyen", "Garcia", "Kim", "Okafor", "Silva", "Brown", "Rossi", "Haddad", "Novak",
        "Sato", "Fischer", "Murphy", "Costa", "Ali", "Lopez", "Walsh", "Chen", "Ibrahim", "Moreau"]
CITIES = [("Austin", "78701"), ("Denver", "80202"), ("Columbus", "43215"), ("Portland", "97205"),
          ("Raleigh", "27601"), ("Phoenix", "85004"), ("Madison", "53703"), ("Tampa", "33602")]
# First octets seen in US residential ISP space; every agent gets its own /24.
ISP_OCTETS = [24, 50, 67, 68, 69, 71, 72, 73, 75, 76, 97, 98, 99, 107, 108, 174]

SPOOFED_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")


def _ips(n: int, rng: random.Random) -> list[str]:
    seen, out = set(), []
    while len(out) < n:
        net = (rng.choice(ISP_OCTETS), rng.randint(1, 254), rng.randint(0, 255))
        if net in seen:
            continue
        seen.add(net)
        out.append(f"{net[0]}.{net[1]}.{net[2]}.{rng.randint(2, 250)}")
    return out


def _persona(i: int, run: str, rng: random.Random) -> Persona:
    first, last = rng.choice(FIRST), rng.choice(LAST)
    city, zip_ = rng.choice(CITIES)
    return Persona(name=f"{first} {last}", email=f"{first.lower()}.{last.lower()}.{run}{i}@example.com",
                   country="United States", address=f"{rng.randint(100, 9999)} {rng.choice(['Oak', 'Pine', 'Maple', 'Cedar'])} St",
                   city=city, zip=zip_)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--stagger", type=float, default=20.0, help="seconds over which agents start")
    ap.add_argument("--label", required=True)
    ap.add_argument("--ua-mode", choices=["spoofed", "careful"], default="spoofed")
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    llm = LLM.from_env()
    rng = random.Random(args.seed)
    run_dir = LAB / "state" / "runs" / args.label
    run_dir.mkdir(parents=True, exist_ok=True)
    ips = _ips(args.n, rng)
    sem = asyncio.Semaphore(args.concurrency)
    started = time.time()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="chrome", headless=True)
        native_ua = await _native_ua(browser)
        ua = SPOOFED_UA if args.ua_mode == "spoofed" else native_ua.replace("HeadlessChrome", "Chrome")

        async def one(i: int):
            await asyncio.sleep(rng.uniform(0, args.stagger))
            async with sem:
                res = await run_agent(browser, llm, agent_id=f"{args.label}-{i:02d}", ip=ips[i],
                                      user_agent=ua, locale="en-US", timezone="America/Chicago",
                                      persona=_persona(i, args.label, rng), task=TASK, max_steps=args.max_steps)
                print(f"  {res.agent_id} {res.ip:<16} {res.outcome:<10} steps={res.steps:<3} "
                      f"{res.ended - res.started:5.0f}s  {res.summary[:70]}", flush=True)
                return res

        print(f"fleet {args.label}: {args.n} agents, model {llm.describe()}, ua-mode {args.ua_mode}", flush=True)
        results = await asyncio.gather(*(one(i) for i in range(args.n)))
        await browser.close()

    manifest = {
        "label": args.label, "kind": "agent_fleet", "model": llm.describe(), "effort": llm.effort,
        "ua_mode": args.ua_mode, "user_agent": ua, "task": TASK, "started": started, "ended": time.time(),
        "usage": llm.usage.__dict__,
        "agents": [{k: v for k, v in r.__dict__.items() if k != "transcript"} for r in results],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    with (run_dir / "transcripts.jsonl").open("w") as f:
        for r in results:
            for t in r.transcript:
                f.write(json.dumps({"agent_id": r.agent_id, **t}) + "\n")
    outcomes = {}
    for r in results:
        outcomes[r.outcome] = outcomes.get(r.outcome, 0) + 1
    print(f"done in {time.time() - started:.0f}s; outcomes {outcomes}; model calls {llm.usage.calls}, "
          f"input tokens {llm.usage.input_tokens}, output tokens {llm.usage.output_tokens}, "
          f"cache reads {llm.usage.cache_read_tokens}", flush=True)


async def _native_ua(browser) -> str:
    page = await browser.new_page()
    ua = await page.evaluate("navigator.userAgent")
    await page.close()
    return ua


if __name__ == "__main__":
    asyncio.run(main())
