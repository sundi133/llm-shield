"""Tier 2 session summaries and scoring from beacons (spec sections 2.3, 2.4,
2.7 and 6). Rev 8 step R4.

A session is everything the collector queued under one `_shs`. Its summary is
plain JSON (stored by the worker in `agd:{tenant}:sess:{shs}`, 24 h):

  first, last, n            time span and beacon count (capped)
  pages                     path templates seen
  views                     page view -> that view's LAST interaction report
                            (the tag's counters are cumulative per view, so
                            summing every report would double count)
  device, device_hashes     first load's device, and every distinct device
  automation                flags OR-ed across loads
  clients, nets             distinct request clients (UA + hints) and networks
  traps                     shown, hits (server verdicts), canaries
  links                     other sessions tied by a trap code (controller)

Detectors, each returning (value 0..1, reason or None):

  A5   traps: own code or another session's code 1.0; a bare honeypot value weak
  A7   interaction like a program
  A8   automation traces
  A10  contradictions inside the session (tag-only form, spec 2.7)
  A9   software or VM graphics: supporting only, never alone

score = 1 - prod(1 - weight * value), banded by the detector pack.
"""

from __future__ import annotations

import functools
import hashlib
import json
import pathlib
from typing import Optional

PACK_PATH = pathlib.Path(__file__).with_name("pack.json")
COUNTS = ("keys", "inputs", "inputs_without_keys", "fields_touched", "corrections", "clicks",
          "centre_clicks", "clicks_without_move", "pointer_moves", "untrusted_events")
DEVICE_KEYS = ("renderer", "cores", "memory", "screen", "dpr", "canvas_hash", "fonts_hash", "tz")


@functools.lru_cache(maxsize=1)
def pack() -> dict:
    return json.loads(PACK_PATH.read_text())


def device_hash(dev: dict) -> str:
    raw = "|".join(str(dev.get(k, "")) for k in DEVICE_KEYS)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def client_hash(req: dict) -> str:
    h = req.get("hints") or {}
    raw = "|".join((req.get("ua", ""), h.get("ua", ""), h.get("platform", ""), h.get("mobile", "")))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def new_session(shs: str) -> dict:
    return {"shs": shs, "first": 0.0, "last": 0.0, "n": 0, "dropped": 0, "pages": [], "views": {},
            "loads": 0, "submits": 0, "device": {}, "device_hashes": [], "automation": {},
            "clients": [], "nets": [], "traps": {"shown": [], "hits": [], "canaries": 0},
            "links": []}


def _add_unique(lst: list, value, cap: int = 20) -> None:
    if value and value not in lst and len(lst) < cap:
        lst.append(value)


def add(sess: dict, e: dict) -> dict:
    """Fold one queued entry (beacon or canary) into the summary."""
    p = pack()["session"]
    if sess["n"] >= p["max_beacons"]:
        sess["dropped"] += 1
        return sess
    req = e.get("req") or {}
    ts = float(req.get("ts") or 0.0)
    sess["n"] += 1
    sess["first"] = ts if not sess["first"] else min(sess["first"], ts)
    sess["last"] = max(sess["last"], ts)
    _add_unique(sess["nets"], req.get("net_hash"))
    if req:
        _add_unique(sess["clients"], client_hash(req))
    kind = e.get("kind")
    tr = e.get("traps") or {}
    for t in tr.get("shown", []):
        _add_unique(sess["traps"]["shown"], t, 8)
    for h in tr.get("hit", []):
        if len(sess["traps"]["hits"]) < 20:
            sess["traps"]["hits"].append(h)
        other = h.get("code_from") or h.get("cookie_shs")
        if other and other != sess["shs"]:
            _add_unique(sess["links"], other, 50)
    if kind == "canary":
        sess["traps"]["canaries"] += 1
        return sess
    page = e.get("page") or ""
    if len(sess["pages"]) < p["max_pages"]:
        _add_unique(sess["pages"], page, p["max_pages"])
    if kind == "load":
        sess["loads"] += 1
        dev = e.get("device") or {}
        if dev:
            sess["device"] = sess["device"] or dev
            _add_unique(sess["device_hashes"], device_hash(dev), 10)
        for k, v in (e.get("automation") or {}).items():
            if isinstance(v, bool):
                sess["automation"][k] = sess["automation"].get(k, False) or v
            elif v:
                sess["automation"][k] = v
    if kind == "submit":
        sess["submits"] += 1
    it = e.get("interaction")
    if it:
        # One page view = path + the moment it started (server time minus the
        # tag's ms-since-navigation), so a view's later report replaces its earlier.
        view = f"{page}|{round(ts - float(e.get('t') or 0) / 1000.0)}"
        views = sess["views"]
        prev = views.get(view)
        if prev is None and len(views) >= p["max_views"]:
            return sess
        if prev is None or int(e.get("t") or 0) >= prev.get("_t", 0):
            views[view] = {**{k: it.get(k) for k in it}, "_t": int(e.get("t") or 0)}
    return sess


def interaction(sess: dict) -> dict:
    """Sums over page views, click- and key-weighted means for the rates."""
    c = dict.fromkeys(COUNTS, 0)
    off_w = straight_w = gap_w = cv_w = 0.0
    gap_n = 0
    for it in sess["views"].values():
        for k in COUNTS:
            c[k] += int(it.get(k) or 0)
        n = int(it.get("clicks") or 0)
        off_w += float(it.get("click_centre_offset_px") or 0) * n
        straight_w += float(it.get("pointer_straightness") or 0) * n
        keys = int(it.get("keys") or 0)
        if keys >= 3:
            gap_w += float(it.get("key_gap_mean_ms") or 0) * keys
            cv_w += float(it.get("key_gap_cv") or 0) * keys
            gap_n += keys
    clicks = c["clicks"]
    c["click_centre_offset_px"] = round(off_w / clicks, 1) if clicks else None
    c["pointer_straightness"] = round(straight_w / clicks, 3) if clicks else None
    c["key_gap_mean_ms"] = round(gap_w / gap_n) if gap_n else None
    c["key_gap_cv"] = round(cv_w / gap_n, 3) if gap_n else None
    return c


# ── detectors ────────────────────────────────────────────────────────


def a5_traps(sess: dict, _signals: dict):
    hits = sess["traps"]["hits"]
    reused = [h for h in hits if h.get("code_from") or h.get("cookie_shs")]
    own = sorted({h["trap"] for h in hits if h.get("code_match") and not h.get("cookie_shs")})
    if reused:
        return 1.0, f"used a hidden-trap code shown to {len(sess['links'])} other session(s): one controller"
    if own:
        return 1.0, f"followed a hidden instruction with this session's own code ({', '.join(own)})"
    if any(h.get("trap") == "T4" for h in hits):
        return pack()["a5"]["t4_value"], "filled a hidden field that carries no instruction (autofill can do this too)"
    return 0.0, None


def a7_interaction(sess: dict, _signals: dict):
    t = pack()["a7"]
    if not sess["views"]:
        return 0.0, None
    it = interaction(sess)
    touch = int((sess["device"] or {}).get("touch") or 0) > 0
    found = []
    if it["inputs_without_keys"] >= t["inputs_without_keys_min"]:
        found.append(f"{it['inputs_without_keys']} fields changed with no key presses")
    if it["untrusted_events"] > 0:
        found.append(f"{it['untrusted_events']} synthetic (untrusted) events")
    if not touch and it["clicks"] >= t["clicks_min"]:
        if it["centre_clicks"] / it["clicks"] >= t["centre_ratio_min"]:
            found.append(f"{it['centre_clicks']} of {it['clicks']} clicks within 2 px of the element centre")
        if it["clicks_without_move"] / it["clicks"] >= t["no_move_ratio_min"]:
            found.append(f"{it['clicks_without_move']} of {it['clicks']} clicks with no pointer path before them")
    if it["keys"] >= t["steady_keys_min"] and it["key_gap_cv"] is not None and it["key_gap_cv"] < t["steady_cv_max"]:
        found.append(f"steady typing (key gap variation {it['key_gap_cv']:.2f})")
    if it["keys"] >= t["no_corrections_keys_min"] and it["corrections"] == 0:
        found.append(f"{it['keys']} key presses and no corrections")
    if not found:
        return 0.0, None
    return (1.0 if len(found) >= 2 else 0.5), "; ".join(found)


def a8_automation(sess: dict, _signals: dict):
    a = sess["automation"]
    if not a:
        return 0.0, None
    found = []
    if a.get("webdriver"):
        found.append("navigator.webdriver is set")
    if a.get("cdp"):
        found.append("a browser-control (CDP) client is attached")
    weak = []
    if a.get("headless_shape"):
        weak.append("headless window shape")
    if a.get("hints_mismatch"):
        weak.append(f"client hints contradict the user agent ({a['hints_mismatch']})")
    if found:
        return 1.0, "; ".join(found + weak)
    return (0.5, "; ".join(weak)) if weak else (0.0, None)


def a10_contradictions(sess: dict, _signals: dict):
    found = []
    if len(sess["clients"]) > 1:
        found.append(f"beacons came from {len(sess['clients'])} different clients in one session")
    if len(sess["device_hashes"]) > 1:
        found.append(f"device changed {len(sess['device_hashes']) - 1} time(s) mid-session")
    return (1.0, "; ".join(found)) if found else (0.0, None)


def a9_environment(sess: dict, signals: dict):
    """Supporting only: counts when another detector already fired."""
    dev = sess["device"] or {}
    cls = dev.get("renderer_class", "")
    if cls in ("software", "vm"):
        why = f"{'software' if cls == 'software' else 'virtual machine'} graphics ({str(dev.get('renderer', ''))[:60]})"
    elif cls == "none":
        why = "no WebGL at all"
    else:
        return 0.0, None
    if not any(v for k, v in signals.items() if k != "A9"):
        return 0.0, None
    return 1.0, why


DETECTORS = [("A5", a5_traps), ("A7", a7_interaction), ("A8", a8_automation),
             ("A10", a10_contradictions), ("A9", a9_environment)]     # A9 last: it reads the others


def score(sess: dict) -> dict:
    pk = pack()
    keep, reasons, signals = 1.0, [], {}
    for did, fn in DETECTORS:
        value, why = fn(sess, signals)
        signals[did] = value
        if value:
            keep *= 1 - pk["weights"][did] * value
            reasons.append(f"{did}: {why}")
    s = round(1 - keep, 3)
    bands = pk["bands"]
    band = "clear_agent" if s >= bands["clear_agent"] else "grey" if s >= bands["grey"] else "human_like"
    return {"score": s, "band": band, "signals": signals, "reasons": reasons, "pack": pk["version"]}


def device_of(sess: dict) -> Optional[str]:
    """The session's single device hash, or None when it changed mid-session."""
    return sess["device_hashes"][0] if len(sess["device_hashes"]) == 1 else None
