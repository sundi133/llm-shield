"""The tool catalog: one row per tool, for the portal's Tool Registry list.

Spec: docs/specs/tool-registry-scale.md (task 1).

The portal used to download every agent (to learn which tools exist) and every
tool policy, then render a row and a hidden role table per tool. This builds
the same rows on the server, from the same three values, and hands the portal
one page and a summary:

  agents:{tenant_id}          agent id -> {tools: [...], role_permissions: {...}}
  data_policies:{tenant_id}   tool name -> its policy; "__global__" -> the default
  policies:{tenant_id}        tool name -> {role_restrictions: {...}} (legacy:
                              sometimes stored as a list of {tool_name, ...})

No new keys, and nothing here is on the guard path: it runs for portal
requests only. A built catalog is cached per tenant for SHIELD_TOOL_CATALOG_TTL_S
(10 s), so paging through a list reads the three values once, not per page.
Writes this process handles drop the tenant's entry (invalidate()); a write on
another worker shows up within the TTL, or at once with fresh=1.
"""

from __future__ import annotations

import base64
import bisect
import json
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Optional

#: The default policy's slot in data_policies:{tenant}. Not a tool. Must equal
#: api/routes_data_policies.GLOBAL_POLICY_KEY (a test checks).
GLOBAL_POLICY_KEY = "__global__"

SOURCES = ("registered", "policy_only", "all")
POLICY_FILTERS = ("any", "none", "custom")
AUDIT_FILTERS = ("on", "off")
PAGE_MAX = 500
PAGE_DEFAULT = 50
Q_MAX = 128
NAME_MAX = 256
CURSOR_MAX = 2048
AGENTS_PER_ROW = 5
TOP_AGENTS = 50


class CatalogError(ValueError):
    """A bad request (400)."""


class CatalogUnavailable(RuntimeError):
    """The stored values could not be read (503)."""


def ttl_s() -> float:
    try:
        return max(0.0, float(os.environ.get("SHIELD_TOOL_CATALOG_TTL_S", "10")))
    except ValueError:
        return 10.0


def cache_tenants() -> int:
    try:
        return max(1, int(os.environ.get("SHIELD_TOOL_CATALOG_TENANTS", "200")))
    except ValueError:
        return 200


# ── reading the three values ─────────────────────────────────────────


def _read(key: str) -> tuple[Any, bool]:
    """(value, readable). Absent is (None, True); a value that is not JSON
    (kv_get hands back the raw string) is (None, False)."""
    from storage.tenant_store import kv_get
    try:
        v = kv_get(key)
    except Exception as e:
        raise CatalogUnavailable(str(e)) from e
    if v is None:
        return None, True
    if isinstance(v, (dict, list)):
        return v, True
    return None, False


def _tool_policies(raw: Any) -> dict:
    """policies:{tenant} as a dict, normalized exactly as
    GET /v1/agents/tools/policies does (a legacy list is keyed by tool_name)."""
    if isinstance(raw, list):
        return {p.get("tool_name", f"tool_{i}"): p for i, p in enumerate(raw) if isinstance(p, dict)}
    return raw if isinstance(raw, dict) else {}


# ── building the rows ────────────────────────────────────────────────


def _role_actions(own: Optional[dict], restriction: Any) -> dict[str, str]:
    """Each role's action, as the portal has always shown it: the tool's data
    policy (role_policies[].action) where it names the role, else the legacy
    role restriction (a string, or {input: ...}).

    The old page listed only roles some agent declares; this lists every role
    either source names, so a policy for a role no agent declares any more is
    visible instead of silently hidden."""
    by_role = {rp["role"]: rp for rp in ((own or {}).get("role_policies") or [])
               if isinstance(rp, dict) and isinstance(rp.get("role"), str) and rp["role"]}
    restr = restriction if isinstance(restriction, dict) else {}
    out = {}
    for role in set(by_role) | {r for r in restr if isinstance(r, str) and r}:
        if role in by_role:
            action = by_role[role].get("action")
        else:
            tp = restr.get(role)
            action = tp if isinstance(tp, str) else (tp.get("input") if isinstance(tp, dict) else None)
        if isinstance(action, str) and action:
            out[role] = action
    return dict(sorted(out.items()))


def build(agents: Any, data_policies: Any, tool_policies: Any,
          warnings: Optional[list[str]] = None) -> tuple[list[dict], dict]:
    """(rows sorted by name, summary). Pure: the three stored values in, the
    catalog out. Rows carry an internal `_agents` (every agent) for the agent
    filter; page() strips it."""
    agents = agents if isinstance(agents, dict) else {}
    data_policies = data_policies if isinstance(data_policies, dict) else {}
    restrictions = _tool_policies(tool_policies)

    tool_agents: dict[str, list[str]] = {}
    declared_roles: set[str] = set()
    for agent_id in sorted(agents):
        agent = agents[agent_id] if isinstance(agents[agent_id], dict) else {}
        for t in agent.get("tools") or []:
            if isinstance(t, str) and t:
                lst = tool_agents.setdefault(t, [])
                if not lst or lst[-1] != agent_id:
                    lst.append(agent_id)
        perms = agent.get("role_permissions")
        if isinstance(perms, dict):
            declared_roles |= {r for r in perms if isinstance(r, str) and r}

    own_policies = {k: v for k, v in data_policies.items()
                    if k != GLOBAL_POLICY_KEY and isinstance(k, str) and k and isinstance(v, dict)}

    rows = []
    for name in set(tool_agents) | set(own_policies):
        own = own_policies.get(name)
        ags = tool_agents.get(name, [])
        restriction = (restrictions.get(name) or {}).get("role_restrictions") \
            if isinstance(restrictions.get(name), dict) else None
        rows.append({
            "tool": name,
            "source": "registered" if ags else "policy_only",
            "agents": ags[:AGENTS_PER_ROW],
            "agent_count": len(ags),
            "has_policy": own is not None,
            "role_actions": _role_actions(own, restriction),
            "role_count": len((own or {}).get("role_policies") or []),
            "sanitization_count": len((own or {}).get("sanitization_rules") or []),
            "audit_required": bool((own or {}).get("audit_required")),
            "compliance_framework": (own or {}).get("compliance_framework") or None,
            "_agents": frozenset(ags),
        })
    rows.sort(key=_key)

    g = data_policies.get(GLOBAL_POLICY_KEY)
    g = g if isinstance(g, dict) else None
    per_agent = sorted(((sum(1 for _ in ts), a) for a, ts in
                        _invert(tool_agents).items()), key=lambda na: (-na[0], na[1]))
    summary = {
        "tools": len(rows),
        "registered": sum(r["source"] == "registered" for r in rows),
        "policy_only": sum(r["source"] == "policy_only" for r in rows),
        "with_policy": sum(r["has_policy"] for r in rows),
        "without_policy": sum(not r["has_policy"] for r in rows),
        "with_sanitization": sum(r["sanitization_count"] > 0 for r in rows),
        "audit_on": sum(r["audit_required"] for r in rows),
        "default_policy": {"exists": g is not None,
                           "enabled": bool(g) and g.get("enabled") is not False,
                           "role_rules": len((g or {}).get("role_policies") or []),
                           "sanitization_rules": len((g or {}).get("sanitization_rules") or [])},
        "agents": len(agents),
        "top_agents": [{"agent": a, "tools": n} for n, a in per_agent[:TOP_AGENTS]],
        "roles": sorted(declared_roles | {role for r in rows for role in r["role_actions"]}),
    }
    if warnings:
        summary["warnings"] = list(warnings)
    return rows, summary


def _invert(tool_agents: dict[str, list[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for tool, ags in tool_agents.items():
        for a in ags:
            out.setdefault(a, []).append(tool)
    return out


def _key(row: dict) -> tuple[str, str]:
    return (row["tool"].lower(), row["tool"])


# ── the per-tenant cache ─────────────────────────────────────────────

_cache: "OrderedDict[str, tuple[float, list[dict], list[tuple[str, str]], dict]]" = OrderedDict()
_lock = threading.Lock()


def _load(tenant_id: str):
    warnings = []
    values = {}
    for name in ("agents", "data_policies", "policies"):
        v, ok = _read(f"{name}:{tenant_id}")
        if not ok:
            warnings.append(f"{name} unreadable")
        values[name] = v
    rows, summary = build(values["agents"], values["data_policies"], values["policies"], warnings)
    return rows, [_key(r) for r in rows], summary


def catalog(tenant_id: str, fresh: bool = False):
    """(built_at, rows, keys, summary) for the tenant, from the cache when it
    is younger than the TTL."""
    ttl = ttl_s()
    now = time.time()
    if not fresh and ttl > 0:
        with _lock:
            hit = _cache.get(tenant_id)
            if hit and now - hit[0] < ttl:
                _cache.move_to_end(tenant_id)
                return hit
    rows, keys, summary = _load(tenant_id)
    entry = (now, rows, keys, summary)
    if ttl > 0:
        with _lock:
            _cache[tenant_id] = entry
            _cache.move_to_end(tenant_id)
            while len(_cache) > cache_tenants():
                _cache.popitem(last=False)
    return entry


def invalidate(tenant_id: str) -> None:
    """Drop the tenant's cached catalog. Called by the writes this process
    handles to agents, data policies or tool policies."""
    with _lock:
        _cache.pop(tenant_id, None)


def reset_cache() -> None:
    with _lock:
        _cache.clear()


# ── one page ─────────────────────────────────────────────────────────


def parse_params(params) -> dict:
    """Validate the query of GET /v1/tenant/me/tool-catalog. Raises CatalogError."""
    raw = params.get("limit")
    if raw in (None, ""):
        limit = PAGE_DEFAULT
    else:
        try:
            limit = int(raw)
        except (TypeError, ValueError):
            limit = 0
    if not 1 <= limit <= PAGE_MAX:
        raise CatalogError(f"limit: 1 to {PAGE_MAX}")
    source = params.get("source") or "registered"
    if source not in SOURCES:
        raise CatalogError(f"source: one of {', '.join(SOURCES)}")
    policy = params.get("policy") or "any"
    if policy not in POLICY_FILTERS:
        raise CatalogError(f"policy: one of {', '.join(POLICY_FILTERS)}")
    audit = params.get("audit") or ""
    if audit and audit not in AUDIT_FILTERS:
        raise CatalogError("audit: on or off")
    san = (params.get("sanitization") or "false").lower()
    if san not in ("true", "false", "1", "0"):
        raise CatalogError("sanitization: true or false")
    q = (params.get("q") or "").strip().lower()
    if len(q) > Q_MAX:
        raise CatalogError(f"q: at most {Q_MAX} characters")
    agent = params.get("agent") or ""
    role = params.get("role") or ""
    if len(agent) > NAME_MAX or len(role) > NAME_MAX:
        raise CatalogError(f"agent and role: at most {NAME_MAX} characters")
    cursor = params.get("cursor") or ""
    if len(cursor) > CURSOR_MAX:
        raise CatalogError("cursor: not one this listing issued")
    fresh = (params.get("fresh") or "") in ("1", "true")
    return {"limit": limit, "cursor": cursor, "q": q, "agent": agent, "source": source,
            "policy": policy, "sanitization": san in ("true", "1"), "audit": audit,
            "role": role, "fresh": fresh}


def _walk(f: dict) -> str:
    """What a cursor is a position in: every filter, so a cursor is only
    accepted back with the filters it was issued for."""
    return json.dumps([f["q"], f["agent"], f["source"], f["policy"], f["sanitization"],
                       f["audit"], f["role"]], separators=(",", ":"))


def _encode_cursor(walk: str, anchor: tuple[str, str]) -> str:
    raw = json.dumps({"w": walk, "a": list(anchor)}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, walk: str) -> tuple[str, str]:
    bad = CatalogError("cursor: not one this listing issued for these filters")
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (ValueError, TypeError):
        raise bad from None
    a = d.get("a") if isinstance(d, dict) else None
    if (not isinstance(d, dict) or d.get("w") != walk or not isinstance(a, list) or len(a) != 2
            or not all(isinstance(x, str) for x in a)):
        raise bad
    return a[0], a[1]


def _matches(row: dict, f: dict) -> bool:
    return ((f["source"] == "all" or row["source"] == f["source"])
            and (not f["q"] or f["q"] in row["tool"].lower())
            and (not f["agent"] or f["agent"] in row["_agents"])
            and (f["policy"] == "any" or row["has_policy"] == (f["policy"] == "custom"))
            and (not f["sanitization"] or row["sanitization_count"] > 0)
            and (not f["audit"] or row["audit_required"] == (f["audit"] == "on"))
            and (not f["role"] or f["role"] in row["role_actions"]))


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def page(tenant_id: str, *, limit: int = PAGE_DEFAULT, cursor: str = "", q: str = "",
         agent: str = "", source: str = "registered", policy: str = "any",
         sanitization: bool = False, audit: str = "", role: str = "", fresh: bool = False) -> dict:
    """One page of the catalog in name order, and the tenant-wide summary.
    next_cursor is null when no further row matches."""
    f = {"q": q, "agent": agent, "source": source, "policy": policy,
         "sanitization": sanitization, "audit": audit, "role": role}
    walk = _walk(f)
    anchor = _decode_cursor(cursor, walk) if cursor else None
    built_at, rows, keys, summary = catalog(tenant_id, fresh=fresh)
    i = bisect.bisect_right(keys, anchor) if anchor else 0
    out: list[dict] = []
    nxt = None
    while i < len(rows):
        row = rows[i]
        i += 1
        if not _matches(row, f):
            continue
        if len(out) == limit:
            nxt = _encode_cursor(walk, _key(out[-1]))    # another row matches: more to come
            break
        out.append(row)
    filtered = {k: v for k, v in f.items()
                if v and not (k == "source" and v == "registered") and not (k == "policy" and v == "any")}
    return {"summary": summary, "tools": [_public(r) for r in out], "next_cursor": nxt,
            "filtered": filtered, "as_of": int(built_at)}
