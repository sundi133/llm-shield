"""Join tier 2 tag beacons to log sessions (spec section 2.3, "Session join").

Every log row carries the tag's `_shs` cookie once the tag has run, so a
session's beacons are the ones whose `shs` appears on its rows. Beacons whose
id never appears in the log (cookie not logged, or the first page only) fall
back to IP, user agent and time window, and that join is marked weak.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

COUNTS = ("keys", "inputs", "inputs_without_keys", "fields_touched", "corrections", "clicks", "centre_clicks",
          "clicks_without_move", "pointer_moves", "untrusted_events")
DEVICE_KEYS = ("renderer", "cores", "memory", "screen", "dpr", "canvas_hash", "fonts_hash", "tz")


@dataclass
class TagData:
    join: str = "missing"                  # shs | fallback | missing
    loads: int = 0
    submits: int = 0
    pages: set = field(default_factory=set)
    device: dict = field(default_factory=dict)
    device_hashes: set = field(default_factory=set)
    automation: dict = field(default_factory=dict)
    counts: dict = field(default_factory=lambda: dict.fromkeys(COUNTS, 0))
    _offset_w: float = 0.0                 # click-weighted sums for the means
    _straight_w: float = 0.0
    _gap_w: float = 0.0
    _cv_w: float = 0.0
    _gap_n: int = 0
    trap_shown: set = field(default_factory=set)
    trap_hits: list = field(default_factory=list)
    beacon_uas: set = field(default_factory=set)
    beacon_ips: set = field(default_factory=set)

    @property
    def joined(self) -> bool:
        return self.join != "missing"

    @property
    def device_hash(self) -> str:
        return next(iter(self.device_hashes), "") if len(self.device_hashes) == 1 else ""

    def interaction(self) -> dict:
        c = dict(self.counts)
        clicks = max(1, c["clicks"])
        c["click_centre_offset_px"] = round(self._offset_w / clicks, 1) if c["clicks"] else None
        c["pointer_straightness"] = round(self._straight_w / clicks, 3) if c["clicks"] else None
        c["key_gap_mean_ms"] = round(self._gap_w / self._gap_n) if self._gap_n else None
        c["key_gap_cv"] = round(self._cv_w / self._gap_n, 3) if self._gap_n else None
        return c

    def add(self, b: dict) -> None:
        self.beacon_uas.add(b.get("ua", ""))
        self.beacon_ips.add(b.get("ip", ""))
        kind = b.get("kind")
        if kind == "load":
            self.loads += 1
            self.pages.add(b.get("page", ""))
            dev = b.get("device") or {}
            if dev:
                self.device = self.device or dev
                self.device_hashes.add(device_hash(dev))
            for k, v in (b.get("automation") or {}).items():
                if isinstance(v, bool):
                    self.automation[k] = self.automation.get(k, False) or v
                elif v:
                    self.automation[k] = v
        if kind == "submit":
            self.submits += 1
        it = b.get("interaction")
        if it:
            for k in COUNTS:
                self.counts[k] += int(it.get(k, 0) or 0)
            n = int(it.get("clicks", 0) or 0)
            self._offset_w += float(it.get("click_centre_offset_px", 0) or 0) * n
            self._straight_w += float(it.get("pointer_straightness", 0) or 0) * n
            keys = int(it.get("keys", 0) or 0)
            if keys >= 3:
                self._gap_w += float(it.get("key_gap_mean_ms", 0) or 0) * keys
                self._cv_w += float(it.get("key_gap_cv", 0) or 0) * keys
                self._gap_n += keys
        tr = b.get("traps") or {}
        self.trap_shown |= set(tr.get("shown", []))
        self.trap_hits += tr.get("hit", [])


def device_hash(dev: dict) -> str:
    raw = "|".join(str(dev.get(k, "")) for k in DEVICE_KEYS)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def load_beacons(path: Path, since: float = 0.0, until: float = float("inf")) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open() as f:
        for line in f:
            try:
                b = json.loads(line)
            except ValueError:
                continue
            if since <= b.get("recv", 0) <= until:
                out.append(b)
    out.sort(key=lambda b: b["recv"])
    return out


def attach(sessions, beacons: list[dict], *, slack_s: float = 60.0) -> dict:
    """Session key -> TagData (join state included) for every session."""
    by_shs = {}
    for s in sessions:
        for sid in s.shs_ids:
            by_shs.setdefault(sid, s.key)
    tags = {s.key: TagData() for s in sessions}
    leftovers: dict[str, list[dict]] = {}
    for b in beacons:
        key = by_shs.get(b.get("shs", ""))
        if key:
            tags[key].join = "shs"
            tags[key].add(b)
        else:
            leftovers.setdefault(b.get("shs", ""), []).append(b)
    # Fallback join: a tag session never seen in the log joins a log session on IP, user agent and time.
    for group in leftovers.values():
        first = group[0]
        cands = [s for s in sessions if s.ip == first.get("ip") and s.ua == first.get("ua")
                 and s.start - slack_s <= first["recv"] <= s.end + slack_s and tags[s.key].join != "shs"]
        if len(cands) == 1:
            t = tags[cands[0].key]
            t.join = "fallback"
            for b in group:
                t.add(b)
    return tags
