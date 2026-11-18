"""The tier 2 collector: public, its own process (spec sections 7 and 9).

    python -m core.agent_detection.collector        (PORT, default 8090)

    GET  /shs.js           the tag (also /shs-{version}.js, immutable)
    POST /b                one beacon; always 204, no body
    GET  /t?k=&s=          this session's trap layout (JSON, no-store)
    GET  /v/{code}?k=      a canary link (trap T2); always 204, no body
    GET|POST /decoy/{path} a decoy (rev 9), forwarded by the customer's edge
                           with X-Shield-Site; 404 for anything not a decoy
    GET  /health           liveness

Every route also answers under `/_shs/`, the first-party path customers map
on their CDN. It is neither plane's web app: it never touches the guard path
and never loads the portal. No verdict ever goes back to the browser, and the
collector sets no cookies.

A beacon is dropped silently (still 204) when it is over 16 KB, malformed,
for an unknown site key, from an Origin the key doesn't allow, over a rate
limit, or when SHIELD_AGENT_DETECTION_COLLECTOR=off. A valid one gets the
request block (spec section 8) and goes to the tenant's beacon stream. The
tenant comes from the site key record, never from the browser.

Client IP: with SHIELD_TRUST_PROXY_HEADERS on, the entry of X-Forwarded-For
that the nearest trusted proxy appended, counted `xff_hops` from the end
(1 when browsers reach the collector directly, 2 when the customer's CDN
forwards `/_shs/`), as set on the site key. Otherwise the TCP peer. The IP is
only used for rate limits and the salted network hash; it is never stored.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from core import agent_detection as _agd
from core.agent_detection import beacons, decoys, sitekeys, stream, tag, traps

log = logging.getLogger("shield.agent_detection.collector")

RATE_PER_IP_MIN = 240
RATE_LAYOUT_PER_IP_MIN = 120
RATE_PER_KEY_MIN = 6000          # per replica
SITEKEY_CACHE_S = 30.0
_TRUTHY = ("1", "true", "yes", "on")


class _Window:
    """Fixed one-minute counters. Bounded: cleared whenever the minute turns."""

    def __init__(self, limit: int):
        self.limit = limit
        self.minute = -1
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()

    def allow(self, k: str, now: Optional[float] = None) -> bool:
        minute = int((time.time() if now is None else now) // 60)
        with self.lock:
            if minute != self.minute:
                self.minute, self.counts = minute, {}
            n = self.counts.get(k, 0)
            if n >= self.limit:
                return False
            self.counts[k] = n + 1
            return True


class _KeyCache:
    def __init__(self, ttl: float):
        self.ttl = ttl
        self.items: dict[str, tuple[float, Optional[dict]]] = {}
        self.lock = threading.Lock()

    def get(self, site_key: str) -> Optional[dict]:
        now = time.monotonic()
        with self.lock:
            hit = self.items.get(site_key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
        rec = sitekeys.get(site_key)
        with self.lock:
            if len(self.items) > 10_000:
                self.items.clear()
            self.items[site_key] = (now, rec)
        return rec


def client_ip(request: Request, xff_hops: int = 1) -> str:
    peer = request.client.host if request.client else ""
    if (os.environ.get("SHIELD_TRUST_PROXY_HEADERS", "") or "").strip().lower() not in _TRUTHY:
        return peer
    parts = [p.strip() for p in (request.headers.get("x-forwarded-for") or "").split(",") if p.strip()]
    if len(parts) >= xff_hops:
        return parts[-xff_hops]
    return parts[0] if parts else peer


async def _read_capped(request: Request, cap: int) -> Optional[bytes]:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > cap:
        return None
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > cap:
            return None
    return bytes(buf)


def _no_content() -> Response:
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


def request_origin(request: Request) -> str:
    """Origin, or the origin of the Referer: a same-origin GET (the tag's
    `/t` through the customer's /_shs/ route) carries no Origin header."""
    o = (request.headers.get("origin") or "").strip().lower()
    if o and o != "null":
        return o
    ref = request.headers.get("referer") or ""
    m = re.match(r"^(https?://[^/?#]+)", ref.strip(), re.I)
    return m.group(1).lower() if m else ""


class _Issued:
    """Sessions whose codes were recorded recently, so a page view doesn't
    rewrite them. Bounded; cleared when full."""

    def __init__(self, cap: int = 50_000):
        self.cap, self.seen, self.lock = cap, set(), threading.Lock()

    def first(self, k: str) -> bool:
        with self.lock:
            if k in self.seen:
                return False
            if len(self.seen) >= self.cap:
                self.seen.clear()
            self.seen.add(k)
            return True


def create_app() -> FastAPI:
    if _agd.collector_enabled():
        for name, value in (("SHIELD_AGENT_DETECTION_HASH_SALT", _agd.hash_salt()),
                            ("SHIELD_AGENT_DETECTION_TRAP_SECRET", traps.secret())):
            if not value:
                raise RuntimeError(f"{name} is required when the collector is on "
                                   "(or set SHIELD_AGENT_DETECTION_COLLECTOR=off)")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    per_ip, per_key, cache = _Window(RATE_PER_IP_MIN), _Window(RATE_PER_KEY_MIN), _KeyCache(SITEKEY_CACHE_S)
    per_ip_layout, issued = _Window(RATE_LAYOUT_PER_IP_MIN), _Issued()
    app.state.limits = (per_ip, per_key)
    app.state.sitekey_cache = cache

    async def beacon(request: Request):
        if not _agd.collector_enabled():
            return _no_content()
        body = await _read_capped(request, beacons.MAX_BYTES)
        b = beacons.parse(body) if body is not None else None
        if b is None:
            return _no_content()
        site = cache.get(b["site_key"])
        if not site or site.get("platform") != "web":
            return _no_content()
        origin = (request.headers.get("origin") or "").strip().lower()
        if origin not in site.get("origins", []):
            return _no_content()
        if site.get("consent") == "required" and b.get("consent") != "given":
            return _no_content()          # a stale snippet without data-consent: keep nothing
        ip = client_ip(request, int(site.get("xff_hops") or 1))
        if not per_key.allow(b["site_key"]) or not per_ip.allow(ip):
            return _no_content()
        entry = {**b, "req": beacons.request_block(request.headers, ip, _agd.hash_salt())}
        try:
            if b.get("traps", {}).get("hit"):
                tenant = site["tenant"]
                entry["traps"] = {"shown": b["traps"].get("shown", []),
                                  "hit": traps.check_hits(tenant, b["shs"], b["traps"]["hit"],
                                                          lambda c: traps.owner_of(tenant, c))}
            stream.append(site["tenant"], entry)
        except Exception as exc:          # noqa: BLE001 - fire and forget; the page is never affected
            log.warning("beacon not queued: %s", type(exc).__name__)
        return _no_content()

    _EMPTY = {"v": 1, "t1": None, "t2": None, "t4": None}

    def layout(request: Request, k: str = "", s: str = ""):
        origin = request_origin(request)
        out, headers = _EMPTY, {"Cache-Control": "no-store", "Vary": "Origin, Referer"}
        site = cache.get(k) if _agd.collector_enabled() and sitekeys.looks_like_key(k) else None
        if site and origin in site.get("origins", []):
            headers["Access-Control-Allow-Origin"] = origin
            ip = client_ip(request, int(site.get("xff_hops") or 1))
            if site.get("traps", True) and re.fullmatch(r"[0-9a-f]{24}", s or "") \
                    and per_ip_layout.allow(ip):
                tenant = site["tenant"]
                out = traps.layout(tenant, s)
                if issued.first(f"{tenant}|{s}|{traps.day()}"):
                    try:
                        traps.record(tenant, traps.issued_codes(tenant, s), s)
                    except Exception as exc:  # noqa: BLE001 - the layout still works for T1
                        log.warning("trap codes not recorded: %s", type(exc).__name__)
        return JSONResponse(out, headers=headers)

    def canary(request: Request, code: str, k: str = ""):
        if not _agd.collector_enabled() or not traps.CODE_RE.match(code or ""):
            return _no_content()
        site = cache.get(k) if sitekeys.looks_like_key(k) else None
        if not site:
            return _no_content()
        ip = client_ip(request, int(site.get("xff_hops") or 1))
        if not per_ip.allow(ip):
            return _no_content()
        tenant = site["tenant"]
        try:
            owner = traps.owner_of(tenant, code)
            if owner:
                entry = {"v": 1, "site_key": k, "shs": owner, "kind": "canary",
                         "traps": {"shown": [], "hit": [{"trap": "T2", "code_match": True}]},
                         "req": beacons.request_block(request.headers, ip, _agd.hash_salt())}
                cookie = (request.cookies.get("_shs") or "").strip()
                if re.fullmatch(r"[0-9a-f]{24}", cookie) and cookie != owner:
                    entry["traps"]["hit"][0]["cookie_shs"] = cookie   # another session followed it
                stream.append(tenant, entry)
        except Exception as exc:            # noqa: BLE001 - fire and forget
            log.warning("canary not queued: %s", type(exc).__name__)
        return _no_content()

    js, js_name, js_sri = tag.source(), tag.filename(), tag.sri()
    js_headers = {"X-Content-Type-Options": "nosniff", "Access-Control-Allow-Origin": "*",
                  "Cross-Origin-Resource-Policy": "cross-origin"}

    def tag_latest():
        # Short cache: this name moves to the next release. Pages that pin an
        # SRI hash load the versioned name instead.
        return Response(js, media_type="application/javascript",
                        headers={**js_headers, "Cache-Control": "public, max-age=300",
                                 "X-Shs-Version": tag.version(js), "X-Shs-Integrity": js_sri})

    def tag_versioned():
        return Response(js, media_type="application/javascript",
                        headers={**js_headers, "Cache-Control": "public, max-age=31536000, immutable"})

    decoy_cache: dict[str, tuple[float, Optional[dict]]] = {}

    def decoy_settings(tenant: str) -> Optional[dict]:
        hit = decoy_cache.get(tenant)
        if hit and time.monotonic() - hit[0] < SITEKEY_CACHE_S:
            return hit[1]
        st = decoys.load(tenant)
        if len(decoy_cache) > 10_000:
            decoy_cache.clear()
        decoy_cache[tenant] = (time.monotonic(), st)
        return st

    _NOT_FOUND = Response(status_code=404, headers={"Cache-Control": "no-store"})
    _DECOY_HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow",
                      "X-Content-Type-Options": "nosniff"}

    async def decoy(request: Request, path: str):
        """Spec 2.6 and 14.3. One code per visitor per day across the decoys:
        the tag's `_shs` session, or, without the tag (scanners, raw HTTP
        agents), a pseudo-session from network, client and day."""
        if not _agd.collector_enabled():
            return _NOT_FOUND
        k = (request.headers.get("x-shield-site") or "").strip()
        site = cache.get(k) if sitekeys.looks_like_key(k) else None
        if not site:
            return _NOT_FOUND
        tenant = site["tenant"]
        st = decoy_settings(tenant)
        if not st or not st.get("enabled"):
            return _NOT_FOUND
        p = decoys.plan(tenant, st)
        path = "/" + path.lstrip("/")
        kind = decoys.kind_of(p, path)
        if not kind:
            return _NOT_FOUND
        ip = client_ip(request, int(site.get("xff_hops") or 1))
        req = beacons.request_block(request.headers, ip, _agd.hash_salt())
        cookie = (request.cookies.get("_shs") or "").strip()
        pseudo = not re.fullmatch(r"[0-9a-f]{24}", cookie)
        if pseudo:
            from core.agent_detection import scoring
            seed_ = f"pseudo|{req['net_hash']}|{scoring.client_hash(req)}|{traps.day()}"
            who = hashlib.sha256(traps.tenant_key(tenant) + seed_.encode()).hexdigest()[:24]
        else:
            who = cookie
        tkey = traps.tenant_key(tenant)
        code = traps.code(tkey, who, "D", traps.day())
        own = {traps.code(tkey, who, "D", d) for d in traps.days()}
        own_d3 = {traps.code(tkey, who, "D3", d) for d in traps.days()}

        presented = (request.headers.get(p["header"].lower()) or request.query_params.get("token") or "")
        presented = presented.strip().lower()[:32]
        followed, code_from = False, None
        if presented:
            if presented in own:
                followed = True
            elif traps.CODE_RE.match(presented):
                owner = traps.owner_of(tenant, presented)
                if owner and owner != who:
                    followed, code_from = True, owner
        key_seen = decoys.key_code(p, " ".join((request.headers.get("authorization") or "",
                                                request.headers.get("x-api-key") or "",
                                                request.query_params.get("key") or "")))
        key_presented, key_match = key_seen is not None, False
        if key_seen:
            if key_seen in own_d3:
                key_match = True
            else:
                owner = traps.owner_of(tenant, key_seen)
                if owner and owner != who:
                    key_match, code_from = True, owner

        # Answer first; the hit is queued unless it is the customer's own scanner.
        d3_code = traps.code(tkey, who, "D3", traps.day())
        if kind == "D1":
            if followed:
                body, status, media = decoys.admin_page("Session accepted. Staff tools are temporarily unavailable."), 200, "text/html"
            elif request.method == "POST":
                body, status, media = decoys.admin_page("Staff sign-in is only available from the internal network. "
                                                        + decoys.instruction(p, code)), 401, "text/html"
            else:
                body, status, media = decoys.admin_page(), 200, "text/html"
        elif kind == "D2":
            body, status, media = decoys.config_body(p, path, code, decoys.session_key(p, d3_code)), 200, "text/plain"
        else:
            if followed or key_match:
                body, status = json.dumps({"ok": True, "data": [], "note": "debug mode: no records in this environment"}), 200
            else:
                body, status = json.dumps({"error": "unauthorized", "message": decoys.instruction(p, code)}), 401
            media = "application/json"

        if not decoys.is_scanner(st, ip, request.headers.get("user-agent") or "") and per_ip.allow(ip):
            try:
                if issued.first(f"{tenant}|{who}|D|{traps.day()}"):
                    traps.record(tenant, [code, d3_code], who)
                hit = {"decoy": kind, "followed": followed, "key_presented": key_presented,
                       "key_match": key_match, "pseudo": pseudo, "method": request.method}
                if code_from:
                    hit["code_from"] = code_from
                stream.append(tenant, {"v": 1, "site_key": k, "shs": who, "kind": "decoy",
                                       "page": path[:120], "decoy": hit, "req": req})
            except Exception as exc:        # noqa: BLE001 - the response never depends on queuing
                log.warning("decoy hit not queued: %s", type(exc).__name__)
        if request.method == "HEAD":
            body = ""
        return Response(body, status_code=status, media_type=media, headers=_DECOY_HEADERS)

    def health():
        return JSONResponse({"ok": True, "collector": "on" if _agd.collector_enabled() else "off"})

    for prefix in ("", "/_shs"):
        app.add_api_route(f"{prefix}/shs.js", tag_latest, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/{js_name}", tag_versioned, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/b", beacon, methods=["POST"], include_in_schema=False)
        app.add_api_route(f"{prefix}/t", layout, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/v/{{code}}", canary, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/decoy/{{path:path}}", decoy, methods=["GET", "POST", "HEAD"],
                          include_in_schema=False)
        app.add_api_route(f"{prefix}/health", health, methods=["GET"], include_in_schema=False)
    return app


def main() -> None:
    import uvicorn
    port = int(os.environ.get("PORT", "8090"))
    uvicorn.run(create_app(), host="0.0.0.0", port=port, log_level="warning",
                proxy_headers=False, server_header=False, date_header=False)


if __name__ == "__main__":
    main()
