"""Fleets from tag sessions (spec sections 3.2 to 3.4, tag-only form of 2.7).
Rev 8 step R5.

Two sessions link when they share at least two independent trait groups and
one of them is behavior, or when one used a trap code shown to the other
(controller: people never see the codes, so that alone is enough):

  behavior     the same page path (shingle overlap >= 0.6) and the same
               bucketed interaction profile, and that profile is RARE among
               human-like sessions (at volume, people on a popular funnel
               share a path, a profile and a 30 s window all the time; the
               rule must never chain them into a fleet)
  time         started, or stopped, within 30 s of each other
  environment  the same device, or the same client (UA + hints), and it is
               RARE among this tenant's human-like sessions in the window
  network      the same /24 or /48 (supporting: never links with time alone)
  controller   a trap-code link either way

Groups of linked sessions become fleets when they reach the pack's minimum
size across enough networks. Prevalence: a device, client or interaction
profile is rare when fewer than max(1, human_like / 1000) human-like sessions
in the window carry it (0.1%), so a popular phone, browser build or ordinary
way of typing never links real customers. Agents that score human-like and
behave like people therefore link only through a controller (trap code)
link: the rule chooses no false fleets over catching perfect mimics.

Pairs are only compared inside blocks that a link needs anyway (the same
interaction profile plus the same 30 s slot, device, client or network), so
the work stays near-linear in the number of sessions.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from itertools import combinations
from typing import Iterable, Optional

from core.agent_detection import scoring

TIME_S = 30.0
JACCARD_MIN = 0.6
PREVALENCE_MAX = 0.001
PREVALENCE_FLOOR = 1000
MAX_BLOCK = 2000          # a block larger than this is split by time slot only
MAX_MEMBERS_KEPT = 5000


def _fleet_cfg() -> dict:
    return scoring.pack().get("fleets", {"min_size": 10, "min_networks": 3})


def interaction_profile(sess: dict) -> Optional[tuple]:
    """A7 features bucketed, or None without enough interaction to compare."""
    if not sess.get("views"):
        return None
    it = scoring.interaction(sess)
    if it["clicks"] < 2 and it["inputs"] < 2:
        return None
    ratio = lambda n, d: round(n / d, 1) if d else -1  # noqa: E731
    return (min(it["inputs_without_keys"], 5), ratio(it["centre_clicks"], it["clicks"]),
            ratio(it["clicks_without_move"], it["clicks"]), it["keys"] > 0)


def _shingles(pages: list, k: int = 3) -> set:
    seq = list(pages or [])
    return {tuple(seq[i:i + k]) for i in range(max(1, len(seq) - k + 1))}


def _client(sess: dict) -> Optional[str]:
    return sess["clients"][0] if len(sess.get("clients") or []) == 1 else None


def _net(sess: dict) -> Optional[str]:
    return sess["nets"][0] if len(sess.get("nets") or []) == 1 else None


class Prevalence:
    """How common a device or client is among the window's human-like sessions."""

    def __init__(self, sessions: Iterable[dict]):
        self.humans = 0
        self.devices: Counter = Counter()
        self.clients: Counter = Counter()
        self.profiles: Counter = Counter()
        for s in sessions:
            if (s.get("verdict") or {}).get("band") != "human_like":
                continue
            self.humans += 1
            d, c, p = scoring.device_of(s), _client(s), interaction_profile(s)
            if d:
                self.devices[d] += 1
            if c:
                self.clients[c] += 1
            if p is not None:
                self.profiles[p] += 1

    def _limit(self) -> float:
        return max(1.0, max(self.humans, PREVALENCE_FLOOR) * PREVALENCE_MAX)

    def rare_device(self, d: Optional[str]) -> bool:
        return bool(d) and self.devices[d] < self._limit()

    def rare_client(self, c: Optional[str]) -> bool:
        return bool(c) and self.clients[c] < self._limit()

    def rare_profile(self, p: Optional[tuple]) -> bool:
        return p is not None and self.profiles[p] < self._limit()

    def share(self, kind: str, value: str) -> float:
        counts = self.devices if kind == "device" else self.clients
        return counts[value] / self.humans if self.humans else 0.0


def link_traits(a: dict, b: dict, ctx: dict, prev: Prevalence) -> set:
    groups = set()
    sa, sb = ctx["shingles"][a["shs"]], ctx["shingles"][b["shs"]]
    jacc = len(sa & sb) / max(1, len(sa | sb))
    pa, pb = ctx["profile"][a["shs"]], ctx["profile"][b["shs"]]
    if jacc >= JACCARD_MIN and pa is not None and pa == pb and prev.rare_profile(pa):
        groups.add("behavior")
    if abs(a["first"] - b["first"]) <= TIME_S or abs(a["last"] - b["last"]) <= TIME_S:
        groups.add("time")
    da, db = scoring.device_of(a), scoring.device_of(b)
    ca, cb = _client(a), _client(b)
    if (da and da == db and prev.rare_device(da)) or (ca and ca == cb and prev.rare_client(ca)):
        groups.add("environment")
    na, nb = _net(a), _net(b)
    if na and na == nb:
        groups.add("network")
    if b["shs"] in (a.get("links") or []) or a["shs"] in (b.get("links") or []):
        groups.add("controller")
    return groups


def _candidate_pairs(sessions: list[dict], ctx: dict, prev: "Prevalence") -> set:
    """Pairs worth comparing: those a link could exist between. A common
    profile can't make a behavior link, so it opens no blocks at all."""
    blocks: dict[tuple, list[str]] = defaultdict(list)
    for s in sessions:
        p = ctx["profile"][s["shs"]]
        if p is None or not prev.rare_profile(p):
            continue
        slot_f, slot_l = int(s["first"] // TIME_S), int(s["last"] // TIME_S)
        for slot in {slot_f, slot_f + 1, slot_l, slot_l + 1}:   # neighbours cover the 30 s window
            blocks[("t", p, slot)].append(s["shs"])
        for kind, value in (("d", scoring.device_of(s)), ("c", _client(s)), ("n", _net(s))):
            if value:
                blocks[(kind, p, value)].append(s["shs"])
    pairs = set()
    for key, members in blocks.items():
        members = sorted(set(members))
        if len(members) > MAX_BLOCK and key[0] != "t":
            continue                     # a huge shared device/client/net block: the time blocks cover it
        for x, y in combinations(members, 2):
            pairs.add((x, y))
    by_shs = {s["shs"] for s in sessions}
    for s in sessions:                   # controller links, whatever the blocks say
        for o in s.get("links") or []:
            if o in by_shs and o != s["shs"]:
                pairs.add(tuple(sorted((s["shs"], o))))
    return pairs


def fleet_id(earliest_shs: str) -> str:
    return "fl_" + hashlib.sha256(earliest_shs.encode()).hexdigest()[:12]


def find_fleets(sessions: list[dict], *, min_size: Optional[int] = None,
                min_networks: Optional[int] = None) -> list[dict]:
    cfg = _fleet_cfg()
    min_size = cfg["min_size"] if min_size is None else min_size
    min_networks = cfg["min_networks"] if min_networks is None else min_networks
    by = {s["shs"]: s for s in sessions}
    ctx = {"shingles": {k: _shingles(s.get("pages")) for k, s in by.items()},
           "profile": {k: interaction_profile(s) for k, s in by.items()}}
    prev = Prevalence(sessions)
    parent = {k: k for k in by}

    def root(k):
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    link_groups: dict[tuple, set] = {}
    for x, y in _candidate_pairs(sessions, ctx, prev):
        g = link_traits(by[x], by[y], ctx, prev)
        if (len(g) >= 2 and "behavior" in g) or "controller" in g:
            parent[root(x)] = root(y)
            link_groups[(x, y)] = g

    groups: dict[str, list[dict]] = defaultdict(list)
    for k in by:
        groups[root(k)].append(by[k])
    fleets = []
    for members in groups.values():
        nets = {n for m in members for n in (m.get("nets") or [])[:1]}
        if len(members) < min_size or len(nets) < min_networks:
            continue
        keys = {m["shs"] for m in members}
        traits: Counter = Counter()
        for (x, y), g in link_groups.items():
            if x in keys:
                traits.update(g)
        members.sort(key=lambda m: (m["first"], m["shs"]))
        devices = Counter(d for m in members if (d := scoring.device_of(m)))
        clients = Counter(c for m in members if (c := _client(m)))
        bands = Counter((m.get("verdict") or {}).get("band", "human_like") for m in members)
        fleets.append({
            "id": fleet_id(members[0]["shs"]),
            "size": len(members), "networks": len(nets),
            "members": [m["shs"] for m in members][:MAX_MEMBERS_KEPT],
            "traits": dict(traits),
            "first_seen": members[0]["first"], "last_seen": max(m["last"] for m in members),
            "bands": dict(bands),
            # what the edge could match, each with its prevalence (R6 publishes only rare ones)
            "devices": [{"hash": d, "sessions": n, "rare": prev.rare_device(d),
                         "share": round(prev.share("device", d), 5)} for d, n in devices.most_common(5)],
            "clients": [{"hash": c, "sessions": n, "rare": prev.rare_client(c),
                         "share": round(prev.share("client", c), 5)} for c, n in clients.most_common(5)],
            "nets": sorted(nets)[:200],
            "pack": scoring.pack()["version"],
        })
    fleets.sort(key=lambda f: -f["size"])
    return fleets
