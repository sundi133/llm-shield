"""Coding-agent hooks per device fleet: the `agent_hooks` block of the device
DLP policy. Spec: docs/specs/claude-code-fleet-rollout.md sections 3 and 4.1.

    "agent_hooks": {
      "agents":  {"claude_code": "claude-code"},
      "default": {"mode": "off", "on_unreachable": "allow"},
      "fleets":  {"eng": {"mode": "enforce", "on_unreachable": "deny"}}
    }

`agents` names the coding agents a tenant covers (only those with a hook the
Votal device agent can install; CODING_AGENTS) and, for each, the registered
agent whose runtime profile decides. A fleet's mode and on_unreachable apply
to every covered coding agent on its laptops.

Stored only when set, so a tenant that never uses it keeps its policy hash
and its laptops keep their bundles. Each fleet's bundle carries only its own
resolved setting; the hook route reads the same resolution through
setting_for(), cached briefly because it runs on every tool call.

SHIELD_DEVICE_AGENT_HOOKS=off resolves every fleet to off, so device agents
remove what they installed and the hook route answers {} for device callers.
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Optional

#: Coding agents whose hooks the device agent can install. A new one is a new
#: entry here, an input mapping on the hook route and a settings writer in
#: the device agent.
CODING_AGENTS = ("claude_code",)
MODES = ("off", "monitor", "enforce")
ON_UNREACHABLE = ("allow", "deny")
DEFAULT_SETTING = {"mode": "off", "on_unreachable": "allow"}
DEFAULT_AGENTS = {"claude_code": "claude-code"}
_KEYS = {"agents", "default", "fleets"}
_SETTING_KEYS = {"mode", "on_unreachable"}
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.@:-]{1,200}$")
CACHE_S = 30


def disabled() -> bool:
    return os.getenv("SHIELD_DEVICE_AGENT_HOOKS", "on").strip().lower() in (
        "0", "off", "false", "no")


def _setting(v: Any, where: str, errors: list[str]) -> dict:
    if not isinstance(v, dict):
        errors.append(f"{where}: an object with mode and on_unreachable")
        return dict(DEFAULT_SETTING)
    for k in v:
        if k not in _SETTING_KEYS:
            errors.append(f"{where}: unknown field '{k}' (allowed: mode, on_unreachable)")
    out = {**DEFAULT_SETTING, **{k: v[k] for k in _SETTING_KEYS if k in v}}
    if out["mode"] not in MODES:
        errors.append(f"{where}.mode: one of {', '.join(MODES)}")
    if out["on_unreachable"] not in ON_UNREACHABLE:
        errors.append(f"{where}.on_unreachable: one of {', '.join(ON_UNREACHABLE)}")
    return out


def validate(raw: Any, errors: list[str], *, valid_fleet, max_fleets: int) -> dict:
    """The normalized block. Appends to errors (the device policy's list)."""
    if not isinstance(raw, dict):
        errors.append("agent_hooks: an object with agents, default and fleets")
        return {}
    for k in raw:
        if k not in _KEYS:
            errors.append(f"agent_hooks: unknown field '{k}' (allowed: agents, default, fleets)")
    agents_raw = raw.get("agents", DEFAULT_AGENTS)
    agents = {}
    if not isinstance(agents_raw, dict) or not agents_raw:
        errors.append(f"agent_hooks.agents: an object mapping one or more of "
                      f"{', '.join(CODING_AGENTS)} to a registered agent id")
        agents_raw = {}
    for coding_agent, agent_id in sorted(agents_raw.items()):
        if coding_agent not in CODING_AGENTS:
            errors.append(f"agent_hooks.agents.{coding_agent}: not a supported coding agent "
                          f"({', '.join(CODING_AGENTS)})")
        elif not isinstance(agent_id, str) or not _AGENT_ID.match(agent_id):
            errors.append(f"agent_hooks.agents.{coding_agent}: the registered agent id, for "
                          f"example claude-code")
        else:
            agents[coding_agent] = agent_id
    default = _setting(raw.get("default", DEFAULT_SETTING), "agent_hooks.default", errors)
    fleets_raw = raw.get("fleets", {})
    if not isinstance(fleets_raw, dict) or len(fleets_raw) > max_fleets:
        errors.append(f"agent_hooks.fleets: an object of at most {max_fleets} fleets")
        fleets_raw = {}
    fleets = {}
    for fleet, s in sorted(fleets_raw.items()):
        if not isinstance(fleet, str) or not valid_fleet(fleet):
            errors.append(f"agent_hooks.fleets.{fleet}: fleet id is lowercase letters, digits, . _ -")
            continue
        fleets[fleet] = _setting(s, f"agent_hooks.fleets.{fleet}", errors)
    return {"agents": agents, "default": default, "fleets": fleets}


def resolve(policy: dict, fleet: str) -> Optional[dict]:
    """One fleet's {"agents", "mode", "on_unreachable"}, or None when the
    tenant has never set agent_hooks (the bundle then carries nothing)."""
    block = policy.get("agent_hooks")
    if not block:
        return None
    s = block["fleets"].get(fleet, block["default"])
    out = {"agents": dict(block["agents"]), "mode": s["mode"],
           "on_unreachable": s["on_unreachable"]}
    if disabled():
        out["mode"] = "off"
    return out


# ── for the hook route: one fleet's setting for one coding agent, cached ──

_lock = threading.Lock()
_cache: dict[str, tuple[float, Optional[dict]]] = {}     # tenant -> (expires, policy block)


def setting_for(tenant_id: str, fleet: str, coding_agent: str,
                now: Optional[float] = None) -> dict:
    """{"agent", "mode", "on_unreachable"} the hook route applies to this
    coding agent on a device in this fleet. Off when the tenant has no
    agent_hooks block, does not cover this coding agent, or its policy cannot
    be read."""
    from core.dlp import device_store
    now = time.monotonic() if now is None else now
    with _lock:
        hit = _cache.get(tenant_id)
    if hit is None or hit[0] <= now:
        try:
            block = device_store.get_policy(tenant_id).get("agent_hooks")
        except Exception:
            block = None
        hit = (now + CACHE_S, block)
        with _lock:
            _cache[tenant_id] = hit
    resolved = resolve({"agent_hooks": hit[1]}, fleet) if hit[1] else None
    if not resolved or coding_agent not in resolved["agents"]:
        return {"agent": "", **DEFAULT_SETTING}
    return {"agent": resolved["agents"][coding_agent], "mode": resolved["mode"],
            "on_unreachable": resolved["on_unreachable"]}


def invalidate(tenant_id: Optional[str] = None) -> None:
    with _lock:
        if tenant_id is None:
            _cache.clear()
        else:
            _cache.pop(tenant_id, None)


__all__ = ["CACHE_S", "CODING_AGENTS", "MODES", "ON_UNREACHABLE", "disabled", "invalidate",
           "resolve", "setting_for", "validate"]
