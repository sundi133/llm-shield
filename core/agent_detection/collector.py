"""The tier 2 collector: public, its own process (spec sections 7 and 9).

    python -m core.agent_detection.collector        (PORT, default 8090)

    GET  /shs.js           the tag (also /shs-{version}.js, immutable)
    POST /b                one beacon; always 204, no body
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

import logging
import os
import threading
import time
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from core import agent_detection as _agd
from core.agent_detection import beacons, sitekeys, stream, tag

log = logging.getLogger("shield.agent_detection.collector")

RATE_PER_IP_MIN = 240
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


def create_app() -> FastAPI:
    if _agd.collector_enabled() and not _agd.hash_salt():
        raise RuntimeError("SHIELD_AGENT_DETECTION_HASH_SALT is required when the collector is on "
                           "(or set SHIELD_AGENT_DETECTION_COLLECTOR=off)")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    per_ip, per_key, cache = _Window(RATE_PER_IP_MIN), _Window(RATE_PER_KEY_MIN), _KeyCache(SITEKEY_CACHE_S)
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
            stream.append(site["tenant"], entry)
        except Exception as exc:          # noqa: BLE001 - fire and forget; the page is never affected
            log.warning("beacon not queued: %s", type(exc).__name__)
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

    def health():
        return JSONResponse({"ok": True, "collector": "on" if _agd.collector_enabled() else "off"})

    for prefix in ("", "/_shs"):
        app.add_api_route(f"{prefix}/shs.js", tag_latest, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/{js_name}", tag_versioned, methods=["GET"], include_in_schema=False)
        app.add_api_route(f"{prefix}/b", beacon, methods=["POST"], include_in_schema=False)
        app.add_api_route(f"{prefix}/health", health, methods=["GET"], include_in_schema=False)
    return app


def main() -> None:
    import uvicorn
    port = int(os.environ.get("PORT", "8090"))
    uvicorn.run(create_app(), host="0.0.0.0", port=port, log_level="warning",
                proxy_headers=False, server_header=False, date_header=False)


if __name__ == "__main__":
    main()
