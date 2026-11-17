"""Turn the shop's access log into per-session summaries.

The input is the JSON access log Nginx writes (one request per line), the same
shape a CDN or WAF log has in a SIEM. A session is keyed by the session cookie
(or the id the app set on the first response). Static assets are kept for the
"page without assets" check but excluded from action timing.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path

STATIC = re.compile(r"^/(static/|favicon)")
TAG = re.compile(r"^/_shs/")       # the tier 2 tag and its beacons: never page actions
CANARY = re.compile(r"^/_shs/v/([0-9a-f]{8})$")   # T2 and T3 canary links (spec 2.4), visible in logs
FORM_FIELDS = {"/signup": 4, "/checkout": 3, "/promo": 1, "/login": 2}
BROWSE = re.compile(r"^/(product/\d+|help|about)$")


@dataclass
class Session:
    key: str
    ip: str = ""
    ua: str = ""
    chua: str = ""
    platform: str = ""
    lang: str = ""
    account: str = ""
    events: list = field(default_factory=list)      # page-level requests only
    assets: int = 0
    start: float = 0.0
    end: float = 0.0
    signups: int = 0
    signup_failed: int = 0
    promos: int = 0
    promo_failed: int = 0
    logins_failed: int = 0
    orders: int = 0
    trap_hits: list = field(default_factory=list)   # T1 | T4 | T1x:<shs> from the app; T2/T3 after resolve
    canary_codes: list = field(default_factory=list)
    enforced_requests: int = 0
    first_request_enforced: bool = False
    shs_ids: set = field(default_factory=set)       # tag session ids seen on this session's log rows
    wba: set = field(default_factory=set)            # edge Web Bot Auth labels seen (spec 2.5)
    wba_agent: str = ""                              # key directory named by Signature-Agent
    tag_requests: int = 0

    # derived
    @property
    def tripwire(self) -> bool:
        """Acted on a hidden instruction with this session's own code (T1, T2 or T3)."""
        return any(h in ("T1", "T2", "T3") for h in self.trap_hits)

    @property
    def reused_codes(self) -> set:
        """Tag session ids whose trap codes this session presented (one controller)."""
        return {h.split(":", 1)[1] for h in self.trap_hits if "x:" in h}

    @property
    def net24(self) -> str:
        parts = self.ip.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else self.ip

    @property
    def fingerprint(self) -> str:
        return f"{self.ua}|{self.platform}|{self.lang}"

    def actions(self) -> list[float]:
        """Start times of page-level actions; a redirect follow (< 0.8 s) joins the previous action."""
        times: list[float] = []
        for e in self.events:
            if times and e["msec"] - times[-1] < 0.8:
                continue
            times.append(e["msec"])
        return times

    def gaps(self) -> list[float]:
        t = self.actions()
        return [b - a for a, b in zip(t, t[1:])]

    def path_sequence(self) -> list[str]:
        seq = []
        for e in self.events:
            p = re.sub(r"/product/\d+", "/product/:id", e["uri"])
            p = re.sub(r"/cart/add/\d+", "/cart/add/:id", p)
            tok = f"{e['method']} {p}"
            if not seq or seq[-1] != tok:
                seq.append(tok)
        return seq

    def form_fill_seconds(self) -> list[tuple[str, float, int]]:
        """(path, seconds from form page load to submit, field count) for each submitted form."""
        out = []
        last_get: dict[str, float] = {}
        for e in self.events:
            path = e["uri"]
            if e["method"] == "GET" and path in FORM_FIELDS:
                last_get[path] = e["msec"]
            elif e["method"] == "POST" and path in FORM_FIELDS and path in last_get:
                out.append((path, e["msec"] - last_get[path], FORM_FIELDS[path]))
                last_get[path] = e["msec"]   # a resubmit after an error starts from here
        return out

    def browsing_pages(self) -> int:
        return sum(1 for e in self.events if e["method"] == "GET" and BROWSE.match(e["uri"]))

    def summary(self) -> dict:
        gaps = self.gaps()
        return {
            "key": self.key, "ip": self.ip, "net24": self.net24, "account": self.account,
            "start": self.start, "end": self.end, "pages": len(self.events), "assets": self.assets,
            "median_gap": round(statistics.median(gaps), 2) if gaps else None,
            "signups": self.signups, "promos": self.promos, "orders": self.orders,
            "tripwire": self.tripwire, "trap_hits": sorted(set(self.trap_hits)),
            "enforced_requests": self.enforced_requests,
        }


def load_events(path: Path, since: float = 0.0, until: float = float("inf")) -> list[dict]:
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if since <= e["msec"] <= until:
                out.append(e)
    out.sort(key=lambda e: e["msec"])
    return out


def build_sessions(events: list[dict]) -> list[Session]:
    sessions: dict[str, Session] = {}
    for e in events:
        key = e.get("sid") or e.get("sid_set") or f"{e['ip']}|{e['ua']}"
        s = sessions.get(key)
        if s is None:
            s = sessions[key] = Session(key=key, ip=e["ip"], ua=e["ua"], chua=e.get("chua", ""),
                                        platform=e.get("chua_platform", ""), lang=e.get("al", ""),
                                        start=e["msec"])
            s.first_request_enforced = e.get("enforced") == "1"
        s.end = e["msec"]
        if e.get("enforced") == "1":
            s.enforced_requests += 1
        if e.get("acct"):
            s.account = e["acct"]
        if e.get("shs"):
            s.shs_ids.add(e["shs"])
        if e.get("wba"):
            s.wba.add(e["wba"])
            s.wba_agent = s.wba_agent or e.get("wba_agent", "")
        ev = e.get("event", "")
        s.signups += ev == "signup"
        s.signup_failed += ev == "signup_failed"
        s.promos += ev == "promo"
        s.promo_failed += ev == "promo_failed"
        s.logins_failed += ev == "login_failed"
        s.orders += ev == "order"
        s.trap_hits += [h for h in (e.get("trip") or "").split(",") if h]
        canary = CANARY.match(e["uri"])
        if canary:
            s.canary_codes.append(canary.group(1))
        elif TAG.match(e["uri"]):
            s.tag_requests += 1
        elif STATIC.match(e["uri"]):
            s.assets += 1
        else:
            s.events.append(e)
    # Drop sessions that never loaded a page (stray asset or favicon requests).
    return [s for s in sessions.values() if s.events]
