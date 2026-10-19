"""Bring an AI inventory entry under Shield. Spec: docs/specs/ai-discovery.md,
section 4.3 (task 5).

Nothing changes from discovery alone: each action is a person's, and each one
works through a path Shield already has.

  inspect                 add its hosts to the device policy's ai_hosts (laptops
                          inspect them; the proxy shipper picks them up for Squid)
  block / unblock         add or remove its hosts in discovery.blocked_hosts (the
                          device agent and Squid deny them)
  route_through_gateway   an MCP server: the gateway registration, prefilled
  register                an agent: the Agent Registry form, prefilled
  sanction / unsanction / ignore   review status only
"""

from __future__ import annotations

import re
import time
from typing import Optional

from core.discovery import catalog as cat
from core.discovery import inventory

ACTIONS = ("inspect", "block", "unblock", "route_through_gateway", "register",
           "sanction", "unsanction", "ignore")
#: Actions that change the device policy (and through it, every laptop and proxy).
POLICY_ACTIONS = ("inspect", "block", "unblock")
HOSTS_PER_ENTRY = 20
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ActionError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def hosts_for(entry: dict, catalog_entry: Optional[dict]) -> list[str]:
    """The hostnames an entry stands for: the ones a source saw, then the
    catalog's (a leading "*." becomes the parent, which device and proxy
    lists match with its subdomains; patterns with a wildcard inside are
    skipped). Shield's own hosts are never included."""
    out: list[str] = []
    candidates = list((entry.get("signals") or {}).get("domains") or [])
    for d in (catalog_entry or {}).get("domains") or []:
        d = d.split("/")[0].lower()
        if d.startswith("*."):
            d = d[2:]
        candidates.append(d)
    for h in candidates:
        h = cat.normalize_host(h)
        if "*" in h or not _HOST.match(h) or cat.is_shield_host(h) or h in out:
            continue
        out.append(h)
    return out[:HOSTS_PER_ENTRY]


def _slug(v: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", (v or "").lower()).strip("_")[:64] or "server"


def apply(tenant_id: str, entry_id: str, action: str, *, actor: str = "") -> dict:
    """Run one action. Returns {action, entry, ...what changed or the prefill}."""
    if action not in ACTIONS:
        raise ActionError(f"action: one of {', '.join(ACTIONS)}", 404)
    entry = inventory.get(tenant_id, entry_id)
    if entry is None:
        raise ActionError(f"no entry '{entry_id}'", 404)
    if action in ("sanction", "unsanction", "ignore"):
        status = {"sanction": "sanctioned", "unsanction": "unsanctioned", "ignore": "ignored"}[action]
        return {"action": action, "entry": inventory.review(tenant_id, entry_id, status=status, actor=actor)}
    if action == "route_through_gateway":
        return _route(entry)
    if action == "register":
        return _register(tenant_id, entry)
    return _policy(tenant_id, entry, action, actor)


def _policy(tenant_id: str, entry: dict, action: str, actor: str) -> dict:
    from core.dlp import device_store
    from core.dlp.device_policy import MAX_HOSTS, PolicyError
    from core.discovery.policy import MAX_BLOCKED

    hosts = hosts_for(entry, cat.by_id(tenant_id).get(entry.get("catalog_id") or ""))
    if not hosts:
        raise ActionError(f"'{entry['name']}' has no hostname to {action}; "
                          f"only AI services and apps seen by their hosts can be")
    policy = device_store.get_policy(tenant_id)
    ai_hosts = list(policy.get("ai_hosts") or [])
    disc = dict(policy.get("discovery") or {"enabled": False, "blocked_hosts": []})
    blocked = list(disc.get("blocked_hosts") or [])
    if action == "inspect":
        added = [h for h in hosts if h not in ai_hosts]
        if len(ai_hosts) + len(added) > MAX_HOSTS:
            raise ActionError(f"the device policy inspects at most {MAX_HOSTS} hosts; "
                              f"{len(ai_hosts)} are listed", 409)
        ai_hosts += added
        removed = [h for h in hosts if h in blocked]        # inspecting it means allowing it
        blocked = [h for h in blocked if h not in hosts]
    elif action == "block":
        added = [h for h in hosts if h not in blocked]
        if len(blocked) + len(added) > MAX_BLOCKED:
            raise ActionError(f"at most {MAX_BLOCKED} blocked hosts; {len(blocked)} are listed", 409)
        blocked += added
        removed = []
    else:
        added, removed = [], [h for h in hosts if h in blocked]
        blocked = [h for h in blocked if h not in hosts]
    policy["ai_hosts"] = ai_hosts
    if blocked or "discovery" in policy:
        policy["discovery"] = {**disc, "blocked_hosts": blocked}
    try:
        device_store.save_policy(tenant_id, policy, actor=actor)
    except PolicyError as e:
        raise ActionError("; ".join(e.errors), 422)

    if action == "inspect":
        entry["inspected"], entry["blocked"] = True, False
    elif action == "block":
        entry["blocked"] = True
        if entry.get("status") in ("unreviewed", "sanctioned"):
            entry["status"] = "unsanctioned"            # blocking it is a decision against it
    else:
        entry["blocked"] = False
    entry["actioned_by"], entry["actioned_at"] = actor, int(time.time())
    inventory._put(tenant_id, entry)
    inventory._event(tenant_id, {"type": "action", "action": action, "entry_id": entry["id"],
                                 "name": entry["name"], "hosts": hosts, "by": actor, "at": int(time.time())})
    return {"action": action, "entry": entry, "hosts": hosts, "added": added, "removed": removed}


def _route(entry: dict) -> dict:
    if entry.get("kind") != "mcp_server":
        raise ActionError("route_through_gateway is for MCP servers")
    mcp = (entry.get("signals") or {}).get("mcp") or {}
    if mcp.get("host"):
        prefill = {"route": _slug(mcp.get("server_name") or mcp["host"]), "transport": "http",
                   "url": f"https://{mcp['host']}/",
                   "note": "Only the host was discovered; add the server's path to the URL."}
    else:
        cmd = " ".join(x for x in (mcp.get("command"), mcp.get("package")) if x)
        if not cmd:
            raise ActionError("this MCP server has no host or command to register")
        prefill = {"route": _slug(mcp.get("server_name") or mcp.get("package") or "server"),
                   "transport": "stdio", "command": cmd,
                   "note": "Arguments and environment were not collected; add what the server needs."}
    return {"action": "route_through_gateway", "entry": entry, "form": "mcp_server", "prefill": prefill}


def _register(tenant_id: str, entry: dict) -> dict:
    if entry.get("kind") != "agent":
        raise ActionError("register is for agents")
    from core.discovery import governed
    name = entry.get("name") or ""
    agent_id = entry["id"].split(":", 1)[1] if entry["id"].startswith("agent:") else ""
    if agent_id and agent_id in governed.evidence(tenant_id)["registered"]:
        raise ActionError(f"'{name}' is already in the Agent Registry", 409)
    return {"action": "register", "entry": entry, "form": "agent",
            "prefill": {"agent_id": agent_id or re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-").lower()[:128],
                        "name": name}}
