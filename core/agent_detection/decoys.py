"""Decoys in the product (spec sections 2.6 and 14; rev 9 step R9).

Things that look valuable to an attacker and are useless: a staff login (D1),
config files (D2), a key in the page code (D3, inserted by the tag in R11), an
internal API route listed under Disallow in robots.txt (D4). The customer's
edge forwards the decoy paths to the collector (R10), which answers each with
a short instruction only an AI agent acts on.

Per tenant, never in source code: the paths, the instruction header and the
fake values come from a random seed kept in `agd:{tenant}:decoys`, so reading
this file says nothing about any customer's decoys.

  agd:{tenant}:decoys   JSON {enabled, seed, key_prefix, stack, avoid,
                              scanners {cidrs, uas}, created, updated}

Off by default. A decoy path must never be a real route on the customer's
site: they review the paths in the portal, add any that exist to `avoid`, or
draw a new set.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import re
import secrets
import threading
import time
from typing import Optional

STACKS = {
    "generic": ["/admin", "/staff/login", "/admin/login", "/manage/login"],
    "wordpress": ["/wp-admin/admin-login.php", "/wp-login-staff.php"],
    "django": ["/admin/login/", "/staff/admin/login/"],
    "laravel": ["/admin/login", "/nova/staff-login"],
    "node": ["/admin", "/dashboard/login"],
}
CONFIG_PATHS = ["/.env", "/.git/config", "/config.json.bak", "/backup.sql", "/.env.production",
                "/app.config.old", "/database.yml.bak"]
API_BASES = ["/internal/api/v2", "/api/internal", "/_internal/v1", "/api/private/v1"]
HEADERS = ["X-Debug-Token", "X-Internal-Auth", "X-Staff-Session", "X-Ops-Token"]
# Formats real providers issue. A decoy key must never look like one (spec 2.6,
# 14.6), or secret scanners and the providers themselves would react to it.
PROVIDER_KEY_FORMATS = [r"^AKIA", r"^ASIA", r"^sk[-_]", r"^pk_", r"^rk_", r"^whsec_",
                        r"^gh[pousr]_", r"^github_pat_", r"^xox[abeprs][-_]", r"^AIza", r"^glpat-",
                        r"^SG\.", r"^ya29\.", r"^EAA", r"^npm_", r"^hf_", r"^shs_", r"^sq0", r"^AC[0-9a-f]{32}",
                        r"^-----BEGIN"]
_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}_(?:[A-Za-z0-9]{1,8}_)?$")
MAX_AVOID = 50
MAX_SCANNERS = 50

_lock = threading.Lock()
_mem: dict[str, str] = {}


class DecoyError(ValueError):
    """Bad input; the message is safe to show."""


def _r():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant: str) -> str:
    return f"agd:{tenant}:decoys"


def default_settings() -> dict:
    return {"enabled": False, "seed": "", "key_prefix": "site_pk_", "stack": "generic", "avoid": [],
            "scanners": {"cidrs": [], "uas": []}, "created": 0, "updated": 0}


def settings(tenant: str) -> dict:
    """The tenant's settings, with a seed created on first use."""
    r = _r()
    raw = _mem.get(_key(tenant)) if r is None else r.get(_key(tenant))
    raw = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
    out = default_settings()
    try:
        out.update(json.loads(raw) if raw else {})
    except ValueError:
        pass
    if not out["seed"]:
        out["seed"] = secrets.token_hex(16)
        out["created"] = out["updated"] = int(time.time())
        _write(tenant, out)
    return out


def _write(tenant: str, value: dict) -> None:
    data = json.dumps(value)
    r = _r()
    if r is None:
        with _lock:
            _mem[_key(tenant)] = data
    else:
        r.set(_key(tenant), data)


def looks_like_provider_key(value: str) -> bool:
    return any(re.match(p, value or "") for p in PROVIDER_KEY_FORMATS)


def _clean_prefix(v) -> str:
    if not isinstance(v, str) or not _PREFIX_RE.match(v):
        raise DecoyError("key_prefix must look like your own keys, for example acme_pk_ "
                         "(letters and digits, ending with _)")
    if looks_like_provider_key(v + "0" * 32):
        raise DecoyError(f"{v} looks like a cloud or SaaS provider's key format; use your own")
    return v


def _clean_path(v) -> str:
    if not isinstance(v, str) or not v.startswith("/") or len(v) > 200 or re.search(r"[\s?#*{};\"']", v):
        raise DecoyError(f"not a path: {v!r}")
    return v


def _clean_scanners(v) -> dict:
    if not isinstance(v, dict):
        raise DecoyError("scanners must be {cidrs: [...], uas: [...]}")
    cidrs, uas = v.get("cidrs") or [], v.get("uas") or []
    if not isinstance(cidrs, list) or not isinstance(uas, list) or len(cidrs) + len(uas) > MAX_SCANNERS:
        raise DecoyError(f"at most {MAX_SCANNERS} scanner entries")
    out_c = []
    for c in cidrs:
        try:
            out_c.append(str(ipaddress.ip_network(str(c).strip(), strict=False)))
        except ValueError:
            raise DecoyError(f"not an IP range: {c!r}") from None
    out_u = []
    for u in uas:
        u = str(u).strip()
        if not 3 <= len(u) <= 100:
            raise DecoyError("a scanner user agent match is 3 to 100 characters")
        out_u.append(u)
    return {"cidrs": out_c, "uas": out_u}


def save(tenant: str, change: dict) -> dict:
    cur = settings(tenant)
    if "enabled" in change:
        cur["enabled"] = bool(change["enabled"])
    if "key_prefix" in change:
        cur["key_prefix"] = _clean_prefix(change["key_prefix"])
    if "stack" in change:
        if change["stack"] not in STACKS:
            raise DecoyError(f"stack must be one of {', '.join(STACKS)}")
        cur["stack"] = change["stack"]
    if "avoid" in change:
        avoid = change["avoid"] or []
        if not isinstance(avoid, list) or len(avoid) > MAX_AVOID:
            raise DecoyError(f"avoid is a list of at most {MAX_AVOID} paths")
        cur["avoid"] = sorted({_clean_path(p) for p in avoid})
    if "scanners" in change:
        cur["scanners"] = _clean_scanners(change["scanners"])
    p = plan(tenant, cur)
    if not p["configs"] or not p["admin"] or not p["api"]:
        raise DecoyError("the avoid list leaves no path for one of the decoys; remove some entries")
    cur["updated"] = int(time.time())
    _write(tenant, cur)
    return cur


def reroll(tenant: str) -> dict:
    """A new seed: new paths, header and values. Edge rules must be re-downloaded."""
    cur = settings(tenant)
    cur["seed"] = secrets.token_hex(16)
    cur["updated"] = int(time.time())
    _write(tenant, cur)
    return cur


def plan(tenant: str, st: Optional[dict] = None) -> dict:
    """This tenant's decoys. Deterministic for a seed, different per tenant."""
    st = st or settings(tenant)
    rng = random.Random(f"{tenant}|{st['seed']}")
    avoid = set(st.get("avoid") or [])
    admin_pool = [p for p in STACKS.get(st["stack"], STACKS["generic"]) if p not in avoid]
    config_pool = [p for p in CONFIG_PATHS if p not in avoid]
    api_pool = [p for p in API_BASES if p not in avoid and p + "/" not in avoid]
    digest = hashlib.sha256(f"decoy|{tenant}|{st['seed']}".encode()).hexdigest()
    return {
        "admin": rng.choice(admin_pool) if admin_pool else "",
        "configs": sorted(rng.sample(config_pool, min(3, len(config_pool)))),
        "api": rng.choice(api_pool) if api_pool else "",
        "header": rng.choice(HEADERS),
        "key_prefix": st["key_prefix"],
        "key_tail": digest[:24],                     # D3 key = prefix + session code + tail (R11)
        "db_password": hashlib.sha256(f"db|{digest}".encode()).hexdigest()[:20],
    }


def paths(p: dict) -> list[str]:
    """Every path the edge forwards, admin and configs exact, the API as a prefix."""
    return [x for x in [p["admin"], *p["configs"]] if x] + ([p["api"] + "/"] if p["api"] else [])


def robots_line(p: dict) -> str:
    return f"Disallow: {p['api']}/"


def is_scanner(st: dict, ip: str, ua: str) -> bool:
    """The customer's own scanners (spec 2.6): dropped before anything is queued."""
    sc = st.get("scanners") or {}
    try:
        addr = ipaddress.ip_address((ip or "").strip())
        if any(addr in ipaddress.ip_network(c, strict=False) for c in sc.get("cidrs") or []):
            return True
    except ValueError:
        pass
    ua_l = (ua or "").lower()
    return any(u.lower() in ua_l for u in sc.get("uas") or [])


# ── edge rules ───────────────────────────────────────────────────────


def edge_nginx(p: dict, site_key: str, collector: str) -> str:
    """Location blocks for the customer's server block. No variables in
    proxy_pass (so no resolver is needed), and a collector error answers 404,
    so a decoy can't break anything a person uses."""
    base = (collector or "https://YOUR-COLLECTOR").rstrip("/") + "/decoy"
    common = ("        proxy_set_header X-Shield-Site \"{key}\";\n"
              "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
              "        proxy_ssl_server_name on;\n"
              "        proxy_intercept_errors on;\n"
              "        error_page 500 502 503 504 =404 @shield_decoy_missing;\n").format(key=site_key)
    out = ["# Shield decoys: forward these paths to the collector. Generated from your",
           "# decoy settings; download again after changing them. Paste inside your",
           "# site's server { } block. Real visitors never request these paths.",
           "location @shield_decoy_missing { return 404; }"]
    for path in [x for x in [p["admin"], *p["configs"]] if x]:
        out.append(f"location = {path} {{\n        proxy_pass {base}{path};\n{common}}}")
    if p["api"]:
        out.append(f"location ^~ {p['api']}/ {{\n        proxy_pass {base}{p['api']}/;\n{common}}}")
    return "\n".join(out) + "\n"


def edge_json(p: dict, site_key: str, collector: str) -> dict:
    """For CDNs configured by hand: what to forward where, and the header to add."""
    base = (collector or "https://YOUR-COLLECTOR").rstrip("/") + "/decoy"
    return {"forward": [{"match": ("prefix" if x.endswith("/") else "exact"), "path": x,
                         "to": base + x} for x in paths(p)],
            "add_headers": {"X-Shield-Site": site_key},
            "keep_headers": ["Cookie", "User-Agent", "Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile",
                             "X-Forwarded-For", "Authorization", p["header"]],
            "on_error": "answer 404",
            "robots_txt_line": robots_line(p)}


def _reset_memory_for_tests() -> None:
    with _lock:
        _mem.clear()
