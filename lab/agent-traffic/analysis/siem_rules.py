"""The "before": typical SIEM correlation rules for a web shop.

These are the rules a security team writes in Splunk, Sentinel or Elastic for
sign-up abuse, promo abuse, credential stuffing and scraping. They count
events per IP or per account inside a time window, plus a known-automation
user agent list. Thresholds are deliberately ordinary, not tuned to miss.
"""

from __future__ import annotations

import re
from collections import defaultdict

AUTOMATION_UA = re.compile(r"headless|python|curl|wget|scrapy|selenium|playwright|puppeteer|bot|spider|crawler",
                           re.I)

RULES = [
    # id, description, entity, event filter, window seconds, threshold
    ("R1", "5+ sign-ups from one IP in 10 min", "ip", lambda e: e.get("event") == "signup", 600, 5),
    ("R2", "10+ failed logins from one IP in 5 min", "ip", lambda e: e.get("event") == "login_failed", 300, 10),
    ("R3", "3+ promo redemptions from one IP in 1 h", "ip", lambda e: e.get("event") == "promo", 3600, 3),
    ("R4", "120+ requests from one IP in 1 min", "ip", lambda e: True, 60, 120),
    ("R5", "3+ failed promo codes on one account in 1 h", "acct", lambda e: e.get("event") == "promo_failed", 3600, 3),
    ("R6", "3+ orders from one IP in 1 h", "ip", lambda e: e.get("event") == "order", 3600, 3),
]


def run(events: list[dict]) -> list[dict]:
    """Return alerts: {rule, description, entity_type, entity, count, at}."""
    alerts = []
    for rid, desc, entity, keep, window, threshold in RULES:
        times = defaultdict(list)
        for e in events:
            if keep(e) and e.get(entity):
                times[e[entity]].append(e["msec"])
        for value, ts in times.items():
            ts.sort()
            lo = 0
            for hi, t in enumerate(ts):
                while t - ts[lo] > window:
                    lo += 1
                if hi - lo + 1 >= threshold:
                    alerts.append({"rule": rid, "description": desc, "entity_type": entity,
                                   "entity": value, "count": hi - lo + 1, "at": t})
                    break
    seen_ua = set()
    for e in events:
        ua = e.get("ua", "")
        if AUTOMATION_UA.search(ua) and (e["ip"], ua) not in seen_ua:
            seen_ua.add((e["ip"], ua))
            alerts.append({"rule": "R7", "description": "known automation user agent", "entity_type": "ip",
                           "entity": e["ip"], "count": 1, "at": e["msec"]})
    return alerts
