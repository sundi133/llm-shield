"""Beacon schema v1 (spec section 8) and the request block the collector adds.

Beacons are attacker-controlled. Everything here drops unknown fields, cuts
strings, clamps numbers, and never trusts a verdict the browser claims (a
trap's `code_match` is decided server-side, never read from the beacon).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import time
from typing import Optional

MAX_BYTES = 16 * 1024
KINDS = ("load", "submit", "leave")
TRAP_IDS = ("T1", "T2", "T3", "T4")
_SHS_RE = re.compile(r"^[0-9a-f]{24}$")
_CODE_RE = re.compile(r"^[0-9a-z]{4,16}$")

# ("str", max_len) | ("int", lo, hi) | ("float", lo, hi) | ("bool",) | nested dict
SCHEMA: dict = {
    "v": ("int", 1, 1),
    "site_key": ("str", 64),
    "shs": ("str", 32),
    "page": ("str", 120),
    "t": ("int", 0, 86_400_000),
    "kind": ("str", 8),
    "device": {
        "renderer": ("str", 120), "renderer_class": ("str", 12), "cores": ("int", 0, 512),
        "memory": ("float", 0, 1024), "screen": ("str", 16), "dpr": ("float", 0, 10),
        "tz": ("str", 48), "langs": ("str", 64), "touch": ("int", 0, 32),
        "canvas_hash": ("str", 16), "fonts_hash": ("str", 16),
    },
    "automation": {
        "webdriver": ("bool",), "cdp": ("bool",), "headless_shape": ("bool",),
        "hints_mismatch": ("str", 40),
    },
    "interaction": {
        "keys": ("int", 0, 100_000), "inputs": ("int", 0, 100_000),
        "inputs_without_keys": ("int", 0, 1000), "fields_touched": ("int", 0, 1000),
        "corrections": ("int", 0, 100_000), "clicks": ("int", 0, 100_000),
        "centre_clicks": ("int", 0, 100_000), "clicks_without_move": ("int", 0, 100_000),
        "click_centre_offset_px": ("float", 0, 10_000), "pointer_moves": ("int", 0, 10_000_000),
        "pointer_straightness": ("float", 0, 1), "untrusted_events": ("int", 0, 100_000),
        "key_gap_mean_ms": ("int", 0, 60_000), "key_gap_cv": ("float", 0, 100),
        "first_input_ms": ("int", 0, 86_400_000),
    },
    "traps": "traps",
}


def _clean_value(spec, value):
    kind = spec[0]
    if kind == "str":
        return value[: spec[1]] if isinstance(value, str) else None
    if kind == "bool":
        return value if isinstance(value, bool) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value:                      # NaN
        return None
    lo, hi = spec[1], spec[2]
    value = min(max(value, lo), hi)
    return int(value) if kind == "int" else round(float(value), 3)


def _clean_traps(value) -> Optional[dict]:
    if not isinstance(value, dict):
        return None
    shown_raw = value.get("shown")
    shown = [t for t in (shown_raw if isinstance(shown_raw, list) else [])[:8]
             if isinstance(t, str) and t in TRAP_IDS]
    hits = []
    hit_raw = value.get("hit")
    for h in (hit_raw if isinstance(hit_raw, list) else [])[:8]:
        if not isinstance(h, dict) or h.get("trap") not in TRAP_IDS:
            continue
        hit = {"trap": h["trap"]}
        code = h.get("code")
        if isinstance(code, str) and _CODE_RE.match(code):
            hit["code"] = code          # checked against this session's codes server-side
        hits.append(hit)
    return {"shown": shown, "hit": hits}


def clean(raw: dict, schema: dict = SCHEMA) -> dict:
    out = {}
    for key, spec in schema.items():
        if key not in raw:
            continue
        if spec == "traps":
            v = _clean_traps(raw[key])
        elif isinstance(spec, dict):
            v = clean(raw[key], spec) if isinstance(raw[key], dict) else None
        else:
            v = _clean_value(spec, raw[key])
        if v is not None:
            out[key] = v
    if isinstance(out.get("page"), str):
        out["page"] = re.split(r"[?#]", out["page"], maxsplit=1)[0]   # path only
    return out


def parse(body: bytes) -> Optional[dict]:
    """The cleaned beacon, or None when it must be dropped. The site key is
    only checked for shape here; the collector looks it up."""
    if not body or len(body) > MAX_BYTES:
        return None
    try:
        raw = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(raw, dict) or raw.get("v") != 1 or isinstance(raw.get("v"), bool):
        return None                         # checked raw: clamping would turn v=2 into 1
    b = clean(raw)
    if b.get("v") != 1 or b.get("kind") not in KINDS:
        return None
    if not _SHS_RE.match(b.get("shs", "")) or not isinstance(b.get("site_key"), str):
        return None
    return b


def net_of(ip: str) -> str:
    """The /24 (IPv4) or /48 (IPv6) network, or '' for something that isn't an IP."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    if addr.ipv4_mapped:
        return str(ipaddress.ip_network(f"{addr.ipv4_mapped}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/48", strict=False))


def net_hash(ip: str, salt: str) -> str:
    """Salted hash of the client's network: IPs are never stored (spec section 8)."""
    net = net_of(ip)
    if not net or not salt:
        return ""
    return hmac.new(salt.encode(), net.encode(), hashlib.sha256).hexdigest()[:16]


def request_block(headers, client_ip: str, salt: str, now: Optional[float] = None) -> dict:
    """What the collector saw of the request that carried the beacon. The
    browser can't set any of this; tag-only A10 compares it with the beacon."""
    def h(name: str, cap: int) -> str:
        v = headers.get(name) or ""
        return v[:cap]
    return {
        "ts": round(time.time() if now is None else now, 3),
        "net_hash": net_hash(client_ip, salt),
        "ua": h("user-agent", 300),
        "hints": {"ua": h("sec-ch-ua", 200), "platform": h("sec-ch-ua-platform", 40),
                  "mobile": h("sec-ch-ua-mobile", 4)},
        "origin": h("origin", 200),
    }
