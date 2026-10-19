"""Whether an inventory entry's traffic passes through Shield.

Spec: docs/specs/ai-discovery.md, section 3.3. Computed from Shield's own
evidence on every update, never taken from a source:

* agent: registered, and Shield saw it on the guard path in the last 30 days
  (the policy-learning observations). A shadow agent is not governed.
* mcp_server: its host, command or package matches an MCP gateway route, and
  the gateway carried calls on that route.
* ai_service / app (with domains): a domain of the entry is inspected (on the
  device policy's ai_hosts) and Shield received guard calls naming it as the
  destination.
* agent from the catalog (Claude Code and the like): governed on devices whose
  agent reports the Shield hook installed.
* framework, model_runtime: never governed by traffic.

`partial`: governed, and also reported by a source that sees traffic Shield
may not (DNS or firewall logs, code scans).
"""

from __future__ import annotations

from typing import Optional

from core.discovery import catalog as cat


def evidence(tenant_id: str) -> dict:
    """Everything the rules read, gathered once per update."""
    from core.discovery import guarded
    ev = {"registered": set(), "seen_agents": set(), "routes": [], "ai_hosts": [],
          "guarded": {}, "hooked": False}
    try:
        from storage.tenant_store import kv_get
        agents = kv_get(f"agents:{tenant_id}") or {}
        ev["registered"] = set(agents) if isinstance(agents, dict) else set()
    except Exception:
        pass
    try:
        from core.policy_learning import observe
        ev["seen_agents"] = {a for a in ev["registered"] if observe.read(tenant_id, a, 30)}
    except Exception:
        pass
    try:
        from storage.mcp_gateway_store import list_upstreams
        ev["routes"] = list_upstreams(tenant_id) or []
    except Exception:
        pass
    try:
        from core.dlp import device_store
        ev["ai_hosts"] = list(device_store.get_policy(tenant_id).get("ai_hosts") or [])
    except Exception:
        pass
    try:
        ev["guarded"] = guarded.read(tenant_id)
    except Exception:
        pass
    try:
        from core.dlp import devices
        for s in (devices._hgetall(devices._seen_key(tenant_id)) or {}).values():
            hooks = (s or {}).get("agent_hooks") or {}
            if any(isinstance(v, dict) and v.get("state") == "active" for v in hooks.values()):
                ev["hooked"] = True
                break
    except Exception:
        pass
    return ev


def _route_for(mcp: dict, routes: list) -> Optional[dict]:
    host = cat.normalize_host(mcp.get("host") or "")
    command, package = (mcp.get("command") or ""), (mcp.get("package") or "")
    for r in routes:
        url_host = cat.normalize_host(r.get("url") or "")
        if host and url_host and host == url_host:
            return r
        r_cmd = str(r.get("command") or "")
        r_args = " ".join(str(a) for a in (r.get("args") or []))
        if package and package in r_args:
            return r
        if command and not package and r_cmd and command == r_cmd.rsplit("/", 1)[-1]:
            return r
    return None


def compute(entry: dict, ev: dict, catalog_entry: Optional[dict] = None) -> tuple:
    """(governed: True | False | "partial", governed_by: [...])."""
    kind = entry.get("kind")
    by: list = []
    if kind == "agent" and entry["id"].startswith("agent:"):
        agent = entry["id"].split(":", 1)[1]
        if agent in ev["registered"] and agent in ev["seen_agents"]:
            by.append("guard_path")
    elif kind == "agent":
        if ev.get("hooked") and (catalog_entry or {}).get("id") in ("claude-code", "codex"):
            by.append("agent_hook")
    elif kind == "mcp_server":
        route = _route_for((entry.get("signals") or {}).get("mcp") or {}, ev["routes"])
        if route and ("mcp_route", str(route.get("route"))) in ev["guarded"]:
            by.append(f"mcp_gateway:{route.get('route')}")
    elif kind in ("ai_service", "app"):
        patterns = list((catalog_entry or {}).get("domains") or [])
        patterns += list((entry.get("signals") or {}).get("domains") or [])
        inspected = [h for h in ev["ai_hosts"]
                     if any(cat._domain_matches(p, h) for p in patterns)]
        seen = [n for (k, n) in ev["guarded"] if k == "destination"
                and any(cat._domain_matches(p, n) for p in patterns)]
        if inspected and seen:
            by.append("inspected:" + ",".join(sorted(set(inspected))[:5]))
    if not by:
        return False, []
    if set(entry.get("sources") or []) & {"dns_log", "repo_scan"}:
        return "partial", by
    return True, by
