"""Lab beacon collector: the prototype of the spec's collector (section 7, 9).

Serves the tag and accepts beacons. Behind Nginx at the first-party path
/_shs/ (the routing the spec recommends customers use), so the shop's access
log holds the beacon requests too.

    GET  /_shs/shs.js?k=SITE_KEY   the tag
    POST /_shs/b                   one beacon; always 204, no body
    GET  /_shs/health              liveness

Every beacon is validated against schema v1: unknown fields dropped, strings
cut, numbers clamped, at most 16 KB, origin checked against the site key,
rate-limited per IP. Valid beacons are appended to state/logs/beacons.jsonl
with the receive time, client IP and user agent of the request that carried
them (A10 compares those with what the beacon claims).

Run:  python -m uvicorn app:app --port 8201   (from this directory)
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response

HERE = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("LAB_STATE_DIR", HERE.parent / "state"))
BEACONS = STATE_DIR / "logs" / "beacons.jsonl"
TAG = HERE.parent / "tag" / "shs.js"

MAX_BYTES = 16 * 1024
RATE_PER_MIN = 240
SITE_KEYS = {
    "lab-site": {"origins": {"http://localhost:8180", "http://127.0.0.1:8180"}},
}

# Schema v1. ("str", max_len) | ("int", lo, hi) | ("float", lo, hi) | ("bool",) | nested dict
SCHEMA: dict = {
    "v": ("int", 1, 1),
    "site_key": ("str", 64),
    "shs": ("str", 32),
    "page": ("str", 120),
    "t": ("int", 0, 86_400_000),
    "kind": ("str", 8),
    "device": {
        "renderer": ("str", 120), "renderer_class": ("str", 12), "cores": ("int", 0, 512),
        "memory": ("float", 0, 1024), "screen": ("str", 16), "dpr": ("float", 0, 10), "tz": ("str", 48),
        "langs": ("str", 64), "touch": ("int", 0, 32), "canvas_hash": ("str", 16), "fonts_hash": ("str", 16),
    },
    "automation": {
        "webdriver": ("bool",), "cdp": ("bool",), "headless_shape": ("bool",), "hints_mismatch": ("str", 40),
    },
    "interaction": {
        "keys": ("int", 0, 100_000), "inputs": ("int", 0, 100_000), "inputs_without_keys": ("int", 0, 1000),
        "fields_touched": ("int", 0, 1000), "corrections": ("int", 0, 100_000), "clicks": ("int", 0, 100_000),
        "centre_clicks": ("int", 0, 100_000), "clicks_without_move": ("int", 0, 100_000),
        "click_centre_offset_px": ("float", 0, 10_000), "pointer_moves": ("int", 0, 10_000_000),
        "pointer_straightness": ("float", 0, 1), "untrusted_events": ("int", 0, 100_000),
        "key_gap_mean_ms": ("int", 0, 60_000), "key_gap_cv": ("float", 0, 100),
        "first_input_ms": ("int", 0, 86_400_000),
    },
    "traps": "traps",
}
KINDS = {"load", "submit", "leave"}
TRAP_IDS = {"T1", "T2", "T3", "T4"}


def _clean_value(spec, value):
    kind = spec[0]
    if kind == "str":
        return value[: spec[1]] if isinstance(value, str) else None
    if kind == "bool":
        return value if isinstance(value, bool) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    lo, hi = spec[1], spec[2]
    value = min(max(value, lo), hi)
    return int(value) if kind == "int" else round(float(value), 3)


def _clean_traps(value) -> dict | None:
    if not isinstance(value, dict):
        return None
    shown = [t for t in value.get("shown", []) if isinstance(t, str) and t in TRAP_IDS][:8]
    hits = []
    for h in value.get("hit", [])[:8]:
        if isinstance(h, dict) and h.get("trap") in TRAP_IDS:
            hits.append({"trap": h["trap"], "code_match": h.get("code_match") is True})
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
    return out


def validate(body: bytes, origin: str) -> dict | None:
    """The cleaned beacon, or None when it must be dropped."""
    if len(body) > MAX_BYTES:
        return None
    try:
        raw = json.loads(body)
    except ValueError:
        return None
    if not isinstance(raw, dict):
        return None
    b = clean(raw)
    site = SITE_KEYS.get(b.get("site_key", ""))
    if b.get("v") != 1 or not site or origin not in site["origins"]:
        return None
    if b.get("kind") not in KINDS or len(b.get("shs", "")) != 24:
        return None
    return b


class RateLimit:
    def __init__(self, per_min: int):
        self.per_min = per_min
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_min:
            return False
        q.append(now)
        return True


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
limiter = RateLimit(RATE_PER_MIN)


def _client_ip(request: Request) -> str:
    return (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()


@app.get("/_shs/shs.js")
def tag():
    return Response(TAG.read_text(), media_type="application/javascript",
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.post("/_shs/b")
async def beacon(request: Request):
    ip = _client_ip(request)
    if not limiter.allow(ip):
        return Response(status_code=204)
    body = await request.body()
    b = validate(body, request.headers.get("origin", ""))
    if b is not None:
        b = {"recv": time.time(), "ip": ip, "ua": request.headers.get("user-agent", "")[:300], **b}
        BEACONS.parent.mkdir(parents=True, exist_ok=True)
        with BEACONS.open("a") as f:
            f.write(json.dumps(b) + "\n")
    return Response(status_code=204)


@app.get("/_shs/health")
def health():
    return {"ok": True}
