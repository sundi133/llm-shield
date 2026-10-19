"""The device policy's optional `discovery` section.

Spec: docs/specs/ai-discovery.md, sections 4.1 and 4.3. Stored only when set,
like agent_hooks, so tenants that never use it keep their policy hash:

  "discovery": {"enabled": false,      # the device agent's AI inventory collector (opt-in)
                "blocked_hosts": []}   # AI destinations the agent and proxy deny
"""

from __future__ import annotations

import re
from typing import Any

MAX_BLOCKED = 200
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def validate(raw: Any, errors: list) -> dict:
    if not isinstance(raw, dict):
        errors.append("discovery: an object")
        return {"enabled": False, "blocked_hosts": []}
    unknown = set(raw) - {"enabled", "blocked_hosts"}
    if unknown:
        errors.append(f"discovery: unknown field(s) {', '.join(sorted(unknown))}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        errors.append("discovery.enabled: true or false")
        enabled = False
    hosts = raw.get("blocked_hosts") or []
    if not isinstance(hosts, list) or len(hosts) > MAX_BLOCKED:
        errors.append(f"discovery.blocked_hosts: a list of at most {MAX_BLOCKED} hostnames")
        hosts = []
    clean = set()
    for i, h in enumerate(hosts):
        h = str(h or "").strip().lower().rstrip(".")
        if not _HOST.match(h):
            errors.append(f"discovery.blocked_hosts[{i}]: a hostname")
            continue
        clean.add(h)
    return {"enabled": enabled, "blocked_hosts": sorted(clean)}
