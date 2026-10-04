"""Agent OS events per device fleet: the `agent_os_events` block of the device
DLP policy. Spec: docs/specs/agent-os-events.md section 3.

    "agent_os_events": {
      "agents":     {"claude_code": "claude-code", "codex": "codex", ...},
      "signatures": [{"label": "build-bot", "match": "(^|/)build-bot($|\\\\s)"}],
      "default":    {"mode": "off"},
      "fleets":     {"eng": {"mode": "on"}}
    }

`agents` maps an agent label (what the device agent attributes a process tree
to) to the registered agent whose runtime profile gives the verdict.
`signatures` adds custom agents to the built-in ones. Stored only when set, so
a tenant that never uses it keeps its policy hash and its laptops keep their
bundles; each fleet's bundle carries only its own resolved setting.

SHIELD_DEVICE_AGENT_OS_EVENTS=off resolves every fleet to off, and the ingest
drops osquery and sysmon events.
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Optional

#: Agents the device agent recognises without a signature.
BUILTIN_LABELS = ("claude_code", "codex", "gemini_cli", "cursor_agent", "aider")
DEFAULT_AGENTS = {"claude_code": "claude-code", "codex": "codex", "gemini_cli": "gemini-cli",
                  "cursor_agent": "cursor-agent", "aider": "aider"}
MODES = ("off", "on")
MAX_SIGNATURES = 50
MAX_PATTERN = 200
_KEYS = {"agents", "signatures", "default", "fleets"}
_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.@:-]{1,200}$")
#: Nested repetition, e.g. (a+)+ or (a*)*: can backtrack for a very long time.
_NESTED = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
CACHE_S = 30


def disabled() -> bool:
    return os.getenv("SHIELD_DEVICE_AGENT_OS_EVENTS", "on").strip().lower() in (
        "0", "off", "false", "no")


def _pattern_ok(p: Any) -> Optional[str]:
    if not isinstance(p, str) or not p or len(p) > MAX_PATTERN:
        return f"a regular expression of 1 to {MAX_PATTERN} characters"
    if _NESTED.search(p):
        return "nested repetition such as (a+)+ is not allowed: it can make matching hang"
    try:
        re.compile(p)
    except re.error as e:
        return f"does not compile: {e}"
    return None


def validate(raw: Any, errors: list[str], *, valid_fleet, max_fleets: int) -> dict:
    """The normalized block. Appends to errors (the device policy's list)."""
    if not isinstance(raw, dict):
        errors.append("agent_os_events: an object with agents, signatures, default and fleets")
        return {}
    for k in raw:
        if k not in _KEYS:
            errors.append(f"agent_os_events: unknown field '{k}' "
                          f"(allowed: agents, default, fleets, signatures)")
    sigs_raw = raw.get("signatures", [])
    sigs = []
    if not isinstance(sigs_raw, list) or len(sigs_raw) > MAX_SIGNATURES:
        errors.append(f"agent_os_events.signatures: a list of at most {MAX_SIGNATURES}")
        sigs_raw = []
    for i, s in enumerate(sigs_raw):
        where = f"agent_os_events.signatures[{i}]"
        if not isinstance(s, dict) or set(s) != {"label", "match"}:
            errors.append(f"{where}: an object with label and match")
            continue
        if not isinstance(s["label"], str) or not _LABEL.match(s["label"]) \
                or s["label"] in BUILTIN_LABELS:
            errors.append(f"{where}.label: lowercase letters, digits and _ (up to 40), "
                          f"not a built-in agent")
            continue
        why = _pattern_ok(s["match"])
        if why:
            errors.append(f"{where}.match: {why}")
            continue
        sigs.append({"label": s["label"], "match": s["match"]})
    labels = set(BUILTIN_LABELS) | {s["label"] for s in sigs}
    agents_raw = raw.get("agents", DEFAULT_AGENTS)
    agents = {}
    if not isinstance(agents_raw, dict):
        errors.append("agent_os_events.agents: an object mapping agent labels to registered "
                      "agent ids")
        agents_raw = {}
    for label, agent_id in sorted(agents_raw.items()):
        if label not in labels:
            errors.append(f"agent_os_events.agents.{label}: not a built-in agent or a "
                          f"signature label")
        elif not isinstance(agent_id, str) or not _AGENT_ID.match(agent_id):
            errors.append(f"agent_os_events.agents.{label}: a registered agent id")
        else:
            agents[label] = agent_id
    default = _mode(raw.get("default", {"mode": "off"}), "agent_os_events.default", errors)
    fleets_raw = raw.get("fleets", {})
    if not isinstance(fleets_raw, dict) or len(fleets_raw) > max_fleets:
        errors.append(f"agent_os_events.fleets: an object of at most {max_fleets} fleets")
        fleets_raw = {}
    fleets = {}
    for fleet, s in sorted(fleets_raw.items()):
        if not isinstance(fleet, str) or not valid_fleet(fleet):
            errors.append(f"agent_os_events.fleets.{fleet}: fleet id is lowercase letters, "
                          f"digits, . _ -")
            continue
        fleets[fleet] = _mode(s, f"agent_os_events.fleets.{fleet}", errors)
    return {"agents": agents, "signatures": sigs, "default": default, "fleets": fleets}


def _mode(v: Any, where: str, errors: list[str]) -> dict:
    if not isinstance(v, dict) or set(v) - {"mode"} or v.get("mode", "off") not in MODES:
        errors.append(f"{where}: {{\"mode\": \"off\" or \"on\"}}")
        return {"mode": "off"}
    return {"mode": v.get("mode", "off")}


def resolve(policy: dict, fleet: str) -> Optional[dict]:
    """One fleet's {"agents", "signatures", "mode"}, or None when the tenant
    has never set agent_os_events (the bundle then carries nothing)."""
    block = policy.get("agent_os_events")
    if not block:
        return None
    mode = block["fleets"].get(fleet, block["default"])["mode"]
    return {"agents": dict(block["agents"]), "signatures": list(block["signatures"]),
            "mode": "off" if disabled() else mode}


# ── for the ingest: the tenant's block, cached ───────────────────────

_lock = threading.Lock()
_cache: dict[str, tuple[float, Optional[dict]]] = {}


def block_for(tenant_id: str, now: Optional[float] = None) -> Optional[dict]:
    """The tenant's agent_os_events block, or None. Cached CACHE_S."""
    from core.dlp import device_store
    now = time.monotonic() if now is None else now
    with _lock:
        hit = _cache.get(tenant_id)
    if hit is None or hit[0] <= now:
        try:
            block = device_store.get_policy(tenant_id).get("agent_os_events")
        except Exception:
            block = None
        hit = (now + CACHE_S, block)
        with _lock:
            _cache[tenant_id] = hit
    return hit[1]


def invalidate(tenant_id: Optional[str] = None) -> None:
    with _lock:
        if tenant_id is None:
            _cache.clear()
        else:
            _cache.pop(tenant_id, None)


__all__ = ["BUILTIN_LABELS", "DEFAULT_AGENTS", "MODES", "block_for", "disabled", "invalidate",
           "resolve", "validate"]
