"""Site keys for the tag (spec sections 8 and 9).

A site key is public: it sits in the customer's page, like a CAPTCHA site
key. It names the tenant and lets a browser write beacons for it, nothing
else. The collector checks the request's Origin against the key's origins.

Keys (Redis, or an in-memory fallback when there is none):

  agd:sitekey:{site_key}   JSON {site_key, tenant, origins, platform, consent,
                                 xff_hops, traps, decoys, label, created, created_by}
  agd:{tenant}:sitekeys    set of the tenant's site keys
  agd:tag_tenants          set of tenants with at least one site key (the
                           worker reads only these tenants' beacon streams)
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

PREFIX = "shs_pk_"
MAX_PER_TENANT = 20
MAX_ORIGINS = 20
PLATFORMS = ("web",)                # android and ios arrive with the SDKs (task 11)
CONSENT = ("none", "required")
XFF_HOPS = (1, 2)                   # 1: browser to collector; 2: through the customer's CDN
_KEY_RE = re.compile(r"^shs_pk_[0-9a-f]{24}$")

_lock = threading.Lock()
_mem: dict = {}
_mem_set: dict = {}


class SiteKeyError(ValueError):
    """Bad input; the message is safe to show."""


class LimitReached(Exception):
    pass


def _r():
    from storage import tenant_store
    return tenant_store._get_redis()


def _decode(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def looks_like_key(value: str) -> bool:
    return isinstance(value, str) and bool(_KEY_RE.match(value))


def normalize_origin(value: str) -> str:
    """`scheme://host[:port]`, lower case, no path; raises SiteKeyError."""
    if not isinstance(value, str) or not value.strip():
        raise SiteKeyError("an origin is required")
    raw = value.strip()
    parts = urlsplit(raw)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise SiteKeyError(f"not an origin: {raw!r} (use https://shop.example.com)")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise SiteKeyError(f"an origin has no path, query or credentials: {raw!r}")
    host = parts.hostname.lower()
    if parts.scheme == "http" and host not in ("localhost", "127.0.0.1", "host.docker.internal") \
            and not host.endswith(".localhost"):
        raise SiteKeyError(f"use https for {host} (http is accepted for local development hosts only)")
    try:
        port = parts.port
    except ValueError:
        raise SiteKeyError(f"bad port in {raw!r}") from None
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")


def _clean_origins(origins) -> list[str]:
    if not isinstance(origins, list) or not origins:
        raise SiteKeyError("origins must be a non-empty list")
    if len(origins) > MAX_ORIGINS:
        raise SiteKeyError(f"at most {MAX_ORIGINS} origins per site key")
    out: list[str] = []
    for o in origins:
        n = normalize_origin(o)
        if n not in out:
            out.append(n)
    return out


def get(site_key: str) -> Optional[dict]:
    if not looks_like_key(site_key):
        return None
    r = _r()
    k = f"agd:sitekey:{site_key}"
    raw = _decode(_mem.get(k) if r is None else r.get(k))
    try:
        rec = json.loads(raw) if raw else None
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def keys_of(tenant: str) -> list[str]:
    r = _r()
    k = f"agd:{tenant}:sitekeys"
    members = _mem_set.get(k, set()) if r is None else (r.smembers(k) or set())
    return sorted(_decode(m) for m in members)


def list_for(tenant: str) -> list[dict]:
    out = [rec for rec in (get(k) for k in keys_of(tenant)) if rec and rec.get("tenant") == tenant]
    return sorted(out, key=lambda rec: rec.get("created") or 0)


def tag_tenants() -> list[str]:
    r = _r()
    members = _mem_set.get("agd:tag_tenants", set()) if r is None else (r.smembers("agd:tag_tenants") or set())
    return sorted(_decode(m) for m in members)


def create(tenant: str, *, origins, platform: str = "web", consent: str = "none",
           xff_hops: int = 1, traps: bool = True, decoys: bool = False, label: str = "",
           created_by: str = "") -> dict:
    if not tenant:
        raise SiteKeyError("no tenant")
    if platform not in PLATFORMS:
        raise SiteKeyError(f"platform must be one of {', '.join(PLATFORMS)}")
    if consent not in CONSENT:
        raise SiteKeyError(f"consent must be one of {', '.join(CONSENT)}")
    if xff_hops not in XFF_HOPS or isinstance(xff_hops, bool):
        raise SiteKeyError("xff_hops must be 1 (browser to collector) or 2 (through your CDN)")
    clean = _clean_origins(origins)
    if len(keys_of(tenant)) >= MAX_PER_TENANT:
        raise LimitReached(f"at most {MAX_PER_TENANT} site keys; delete one first")
    rec = {
        "site_key": PREFIX + secrets.token_hex(12),
        "tenant": tenant,
        "origins": clean,
        "platform": platform,
        "consent": consent,
        "xff_hops": xff_hops,
        "traps": bool(traps),          # rev 8: per site key (tenant config later)
        "decoys": bool(decoys),        # rev 9: the tag places D3 on this site's pages
        "label": (label or "")[:80],
        "created": int(time.time()),
        "created_by": (created_by or "")[:120],
    }
    data = json.dumps(rec)
    r = _r()
    if r is None:
        with _lock:
            _mem[f"agd:sitekey:{rec['site_key']}"] = data
            _mem_set.setdefault(f"agd:{tenant}:sitekeys", set()).add(rec["site_key"])
            _mem_set.setdefault("agd:tag_tenants", set()).add(tenant)
        return rec
    r.set(f"agd:sitekey:{rec['site_key']}", data)
    r.sadd(f"agd:{tenant}:sitekeys", rec["site_key"])
    r.sadd("agd:tag_tenants", tenant)
    return rec


def delete(tenant: str, site_key: str) -> bool:
    """False when the key doesn't exist or belongs to another tenant."""
    rec = get(site_key)
    if not rec or rec.get("tenant") != tenant:
        return False
    r = _r()
    if r is None:
        with _lock:
            _mem.pop(f"agd:sitekey:{site_key}", None)
            s = _mem_set.get(f"agd:{tenant}:sitekeys", set())
            s.discard(site_key)
            if not s:
                _mem_set.get("agd:tag_tenants", set()).discard(tenant)
        return True
    r.delete(f"agd:sitekey:{site_key}")
    r.srem(f"agd:{tenant}:sitekeys", site_key)
    if not keys_of(tenant):
        r.srem("agd:tag_tenants", tenant)
    return True


def _reset_memory_for_tests() -> None:
    with _lock:
        _mem.clear()
        _mem_set.clear()
