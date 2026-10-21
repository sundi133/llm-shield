"""Portal side of coding-agent hooks (both planes).

GET  /v1/tenant/me/hooks/claude-code       laptops' last hook calls, the URL to use,
                                           what is set up
GET  /v1/tenant/me/hooks/coverage          every laptop's last call, which are managed
                                           and on which version, which went quiet
POST /v1/tenant/me/hooks/claude-code/kit   rollout files for laptops WITHOUT the
                                           Votal agent (managed settings,
                                           .mobileconfig, install script, hook)
POST /v1/tenant/me/hooks/enable            profile + agent binding + coverage, once
GET  /v1/tenant/me/hooks/fleets            each fleet's mode, laptops and hook states
PUT  /v1/tenant/me/hooks/fleets            set the modes (device policy agent_hooks,
                                           and agent_os_events per fleet)
GET  /v1/tenant/me/hooks/os-events         what agents did: outside-profile events
                                           and per-laptop counts (agent-os-events)

Specs: docs/specs/agent-hook-adapter.md task 3, and
docs/specs/claude-code-fleet-rollout.md task 2, and
docs/specs/hooks-plugin-production.md task 3. Not on any guard path: the
hook route itself is api/routes_hooks.py (data plane only). The hook key
posted to /kit builds the files and is never stored or logged.
"""

from __future__ import annotations

import copy
import time
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Request

from core.auth import get_tenant_from_request, require_registry_write
from core.runtime_policy import hook_kit, hook_seen

router = APIRouter(prefix="/v1/tenant/me/hooks", tags=["runtime"])

TEMPLATE = "coding-agent-baseline"


def _hooks_block(tenant_id: str):
    from core.dlp import device_store
    try:
        return device_store.get_policy(tenant_id).get("agent_hooks")
    except Exception:
        return None


def _status(tenant_id: str) -> dict:
    """What is set up: for each supported coding agent, the agent it maps to,
    that agent's runtime profile, and whether laptops are covered."""
    from api.routes_agents_registry import get_redis_data
    from core.dlp.agent_hooks import CODING_AGENTS, DEFAULT_AGENTS
    block = _hooks_block(tenant_id) or {}
    agents = get_redis_data(f"agents:{tenant_id}") or {}
    out = {}
    for ca in CODING_AGENTS:
        agent_id = (block.get("agents") or {}).get(ca) or DEFAULT_AGENTS[ca]
        rec = agents.get(agent_id) or {}
        out[ca] = {"agent": agent_id, "agent_exists": bool(rec),
                   "profile": rec.get("runtime_profile") or "",
                   "covered": ca in (block.get("agents") or {})}
    return out


@router.get("/claude-code")
async def claude_code_overview(request: Request):
    tenant_id = get_tenant_from_request(request)
    from core.dlp import devices as dv
    url, source = hook_kit.public_url_and_source(str(request.base_url))
    laptops = hook_seen.list_seen(tenant_id)
    try:
        enrolled = dv.records_for(tenant_id, [row.get("device") or "" for row in laptops])
    except Exception:
        enrolled = {}
    for row in laptops:
        rec = enrolled.get(row.get("device") or "")
        if rec:          # an agent-managed laptop: show its name, not its id
            row["hostname"] = rec.get("hostname") or ""
    return {"shield_url": url, "shield_url_source": source,
            "status": _status(tenant_id),
            "laptops": laptops,
            "variants": list(hook_kit.VARIANTS), "oses": list(hook_kit.OSES)}


def _hook_key_problems(tenant_id: str, key: str, agent: str) -> tuple[list, list]:
    """(errors, warnings) for the key the kit bakes into laptops' files
    (docs/specs/hooks-plugin-production.md section 5). The hook route refuses
    an admin-scoped key and a key bound to another agent, so a kit carrying one
    would deny every call on every laptop; better to say so now."""
    from storage.tenant_store import (SCOPE_ADMIN, SCOPE_RUNTIME, _hash_key,
                                      key_bound_agent_by_hash, key_scope,
                                      resolve_tenant_by_api_key)
    if not key or not hook_kit.valid_key(key):
        return [], []           # build() reports a missing or malformed key
    try:
        owner = resolve_tenant_by_api_key(key)
        scope = key_scope(key)
        bound = key_bound_agent_by_hash(_hash_key(key))
    except Exception:           # noqa: BLE001 - store down: build, but say it was not checked
        return [], ["hook_key: could not be checked (key store unavailable)"]
    if owner != tenant_id:
        return ["hook_key: not a key of this tenant"], []
    if scope == SCOPE_ADMIN:
        return ["hook_key: an admin-scoped key, which the hook route refuses (on a laptop it "
                "could change your policy). Mint a runtime key bound to the agent: POST "
                "/v1/tenant/me/api-keys with {\"agent\": \"" + agent + "\"}"], []
    if bound and bound != agent:
        return [f"hook_key: bound to agent '{bound}', not '{agent}'"], []
    warnings = []
    if scope != SCOPE_RUNTIME:
        warnings.append("hook_key: unscoped. It works, but whoever reads it off a laptop can "
                        "do anything a tenant key can; prefer a runtime key bound to the agent")
    elif not bound:
        warnings.append(f"hook_key: not bound to an agent, so a laptop could name another one; "
                        f"mint one bound to '{agent}'")
    return [], warnings


@router.post("/claude-code/kit")
async def claude_code_kit(request: Request, body: dict = Body(...)):
    """Body: {variant: http|command, os: macos|linux|windows, tier:
    standard|regulated, shield_url, hook_key, agent}. Returns {files: {name:
    {content, path, mime}}, warnings: [...]}."""
    tenant_id = get_tenant_from_request(request)
    key = str(body.get("hook_key") or "").strip()
    agent = str(body.get("agent") or "claude-code").strip()
    key_errors, warnings = _hook_key_problems(tenant_id, key, agent)
    try:
        files = hook_kit.build(
            str(body.get("variant") or ""), str(body.get("os") or ""),
            shield_url=str(body.get("shield_url") or "").strip(),
            key=key, agent=agent, tenant_id=tenant_id,
            tier=str(body.get("tier") or "standard"))
    except hook_kit.KitError as e:
        raise HTTPException(status_code=422, detail={"message": "The files could not be built.",
                                                     "errors": e.errors + key_errors})
    if key_errors:
        raise HTTPException(status_code=422, detail={"message": "The files could not be built.",
                                                     "errors": key_errors})
    return {"files": files, "warnings": warnings}


# ── coverage ────────────────────────────────────────────────────────

COVERAGE_MAX = 5000
EXPIRE_AFTER_S = 90 * 86400
_STALE_DEFAULT_H = 24


def _stale_hours(request: Request, tenant_id: str, asked: Optional[int]) -> int:
    if asked is not None:
        if not 1 <= asked <= 720:
            raise HTTPException(status_code=422, detail="stale_after_hours: 1 to 720")
        return asked
    from storage.tenant_store import get_tenant
    try:
        hooks_cfg = (get_tenant(tenant_id) or {}).get("hooks") or {}
        configured = hooks_cfg.get("stale_after_hours")
    except Exception:       # noqa: BLE001
        configured = None
    return configured if isinstance(configured, int) and 1 <= configured <= 720 \
        else _STALE_DEFAULT_H


@router.get("/coverage")
async def coverage(request: Request, stale_after_hours: Optional[int] = None,
                   limit: int = 200, cursor: str = ""):
    """Every laptop's last hook call: managed or not, which version, which OS,
    and which went quiet. A laptop that stops calling Shield (hooks removed,
    switched off, no route to Shield) looks like one with nothing to block;
    `stale` is how an admin tells them apart. Stale laptops first, oldest
    first; then the rest, newest first. Rows older than 90 days are dropped."""
    from core.dlp import devices as dv

    tenant_id = get_tenant_from_request(request)
    if not 1 <= limit <= 1000:
        raise HTTPException(status_code=422, detail="limit: 1 to 1000")
    try:
        offset = int(cursor) if cursor else 0
    except ValueError:
        raise HTTPException(status_code=422, detail="cursor: the next_cursor of a previous page")
    hours = _stale_hours(request, tenant_id, stale_after_hours)
    now = time.time()
    rows, expired = hook_seen.list_all(tenant_id, older_than=now - EXPIRE_AFTER_S)
    for field in expired:
        hook_seen.forget(tenant_id, field)
    truncated = len(rows) > COVERAGE_MAX
    rows = rows[:COVERAGE_MAX]
    stale_before = now - hours * 3600
    out = []
    for r in rows:
        at = r.get("at") or 0
        out.append({"agent": r.get("agent") or "", "device": r.get("device") or "",
                    "user": r.get("user") or "", "fleet": r.get("fleet") or "",
                    "profile": r.get("profile") or "", "decision": r.get("decision") or "",
                    "tool": r.get("tool") or "", "monitor": bool(r.get("monitor")),
                    "last_seen": at, "stale": at < stale_before,
                    "version": r.get("hook_version") or "unknown",
                    "mode": r.get("hook_mode") or "unknown",
                    "os": r.get("hook_os") or "unknown"})
    out.sort(key=lambda r: (not r["stale"], r["last_seen"] if r["stale"] else -r["last_seen"]))
    page = out[offset:offset + limit]
    try:
        enrolled = dv.records_for(tenant_id, [r["device"] for r in page])
    except Exception:       # noqa: BLE001
        enrolled = {}
    for r in page:
        rec = enrolled.get(r["device"])
        r["hostname"] = (rec or {}).get("hostname") or ""
    count = lambda key: {v: sum(1 for r in out if r[key] == v)   # noqa: E731
                         for v in sorted({r[key] for r in out})}
    return {"devices": page, "total": len(out), "stale_count": sum(r["stale"] for r in out),
            "stale_after_hours": hours, "by_mode": count("mode"), "by_version": count("version"),
            "by_os": count("os"),
            "next_cursor": str(offset + limit) if offset + limit < len(out) else "",
            "truncated": truncated}


# ── turn on, once ───────────────────────────────────────────────────


@router.post("/enable")
async def enable(request: Request, body: dict = Body(default={})):
    """Body: {coding_agent: "claude_code", profile, agent, replace_binding}.
    Creates the profile from the coding-agent-baseline template if it does not
    exist (an existing one is used as it is), creates or binds the agent, and
    adds the coding agent to the device policy's agent_hooks. Fleets stay at
    their mode (off until set). Idempotent."""
    from api.routes_agents_registry import (_save_agents, _validate_new_agent_id,
                                            get_redis_data, new_agent_record)
    from core.dlp import agent_hooks, device_store
    from core.dlp.device_policy import PolicyError
    from core.runtime_policy import check as runtime_check
    from core.runtime_policy import store as rt_store
    from core.runtime_policy.model import templates, valid_name

    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "turn on coding-agent guardrails")
    coding_agent = str(body.get("coding_agent") or "claude_code")
    profile = str(body.get("profile") or TEMPLATE)
    agent_id = str(body.get("agent") or agent_hooks.DEFAULT_AGENTS.get(coding_agent, "")).strip()
    replace = body.get("replace_binding") is True
    errors = []
    if coding_agent not in agent_hooks.CODING_AGENTS:
        errors.append(f"coding_agent: one of {', '.join(agent_hooks.CODING_AGENTS)}")
    if not valid_name(profile):
        errors.append("profile: lowercase letters, digits, . _ - (up to 64)")
    if not agent_id:
        errors.append("agent: the agent id laptops are checked as, for example claude-code")
    if errors:
        raise HTTPException(status_code=422, detail={"message": "Could not turn on.",
                                                     "errors": errors})

    # The binding is checked before anything is written, so a refusal changes nothing.
    agents = get_redis_data(f"agents:{tenant_id}") or {}
    current = (agents.get(agent_id) or {}).get("runtime_profile") or ""
    if current and current != profile and not replace:
        raise HTTPException(status_code=409, detail={
            "message": f"Agent '{agent_id}' already uses runtime profile '{current}'.",
            "current_profile": current})

    profile_created = False
    if rt_store.get_profile(tenant_id, profile) is None:
        rt_store.save_profile(tenant_id, profile, copy.deepcopy(templates()[TEMPLATE]),
                              actor=f"tenant:{tenant_id}", reason="enable coding-agent hooks")
        runtime_check.invalidate(tenant_id)
        profile_created = True

    agent_created = agent_id not in agents
    if agent_created:
        _validate_new_agent_id(agent_id, tenant_id)
        agents[agent_id] = new_agent_record(request, tenant_id, agent_id, {
            "name": "Claude Code (laptops)" if coding_agent == "claude_code" else agent_id,
            "description": "Checked by Votal Shield's coding-agent hook",
            "runtime_profile": profile})
    if agents[agent_id].get("runtime_profile") != profile:
        agents[agent_id]["runtime_profile"] = profile
    if agent_created or current != profile:
        _save_agents(tenant_id, agents)

    policy = device_store.get_policy(tenant_id)
    block = copy.deepcopy(policy.get("agent_hooks") or {"agents": {}})
    block.setdefault("agents", {})[coding_agent] = agent_id
    try:
        device_store.save_policy(tenant_id, {**policy, "agent_hooks": block},
                                 actor=f"tenant:{tenant_id}")
    except PolicyError as e:
        raise HTTPException(status_code=422, detail={"message": "Could not turn on.",
                                                     "errors": e.errors})
    return {"coding_agent": coding_agent, "profile": profile, "profile_created": profile_created,
            "agent": agent_id, "agent_created": agent_created, "bound": True,
            "status": _status(tenant_id)}


# ── per-fleet modes ──────────────────────────────────────────────────


def _fleet_rows(tenant_id: str, block: dict, os_block: Optional[dict] = None) -> list[dict]:
    """Every fleet that has laptops or a setting: its hook setting and OS
    events mode, its laptop count, and laptops by hook state (per coding
    agent) and by OS event collector state."""
    from core.dlp import devices as dv
    from core.dlp.agent_hooks import CODING_AGENTS, DEFAULT_SETTING
    rows = dv.list_devices(tenant_id)["devices"]
    block, os_block = block or {}, os_block or {}
    fleets = sorted({r.get("fleet") or "" for r in rows} | set(block.get("fleets", {}))
                    | set(os_block.get("fleets", {})))
    out = []
    for fleet in fleets:
        if not fleet:
            continue
        setting = (block.get("fleets") or {}).get(fleet) or block.get("default") or DEFAULT_SETTING
        os_mode = ((os_block.get("fleets") or {}).get(fleet)
                   or os_block.get("default") or {"mode": "off"})["mode"]
        mine = [r for r in rows if r.get("fleet") == fleet]
        states = {ca: {} for ca in CODING_AGENTS}
        os_states: dict = {}
        for r in mine:
            for ca in CODING_AGENTS:
                st = ((r.get("agent_hooks") or {}).get(ca) or {}).get("state") or "not_reported"
                states[ca][st] = states[ca].get(st, 0) + 1
            st = (r.get("os_events") or {}).get("state") or "not_reported"
            os_states[st] = os_states.get(st, 0) + 1
        out.append({"fleet": fleet, "mode": setting["mode"],
                    "on_unreachable": setting["on_unreachable"],
                    "explicit": fleet in (block.get("fleets") or {}),
                    "laptops": len(mine), "states": states,
                    "os_events": os_mode, "os_states": os_states})
    return out


def _os_block(tenant_id: str):
    from core.dlp import device_store
    try:
        return device_store.get_policy(tenant_id).get("agent_os_events")
    except Exception:
        return None


@router.get("/fleets")
async def get_fleets(request: Request):
    from core.dlp import agent_os_events
    from core.dlp.agent_hooks import DEFAULT_SETTING, disabled
    tenant_id = get_tenant_from_request(request)
    block = _hooks_block(tenant_id)
    os_block = _os_block(tenant_id)
    return {"configured": block is not None,
            "agents": (block or {}).get("agents", {}),
            "default": (block or {}).get("default", DEFAULT_SETTING),
            "fleets": _fleet_rows(tenant_id, block or {}, os_block),
            "disabled_by_server": disabled(),
            "os_events_configured": os_block is not None,
            "os_events_disabled_by_server": agent_os_events.disabled()}


@router.put("/fleets")
async def put_fleets(request: Request, body: dict = Body(...)):
    """Body: {default?: {mode, on_unreachable}, fleets?: {fleet: {mode,
    on_unreachable}}, os_events?: {fleet: "on" | "off"}}. Replaces what is
    sent and keeps the rest: hook fleets only when `fleets` is sent, OS event
    fleets only when `os_events` is sent. Which coding agents the hooks cover
    is kept (set by /enable)."""
    from core.dlp import device_store
    from core.dlp.device_policy import PolicyError
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "change coding-agent hook modes")
    for k in body:
        if k not in ("default", "fleets", "os_events"):
            raise HTTPException(status_code=422, detail={
                "message": "Could not save.",
                "errors": [f"unknown field '{k}' (default, fleets, os_events)"]})
    policy = copy.deepcopy(device_store.get_policy(tenant_id))
    if "default" in body or "fleets" in body:
        block = copy.deepcopy(policy.get("agent_hooks") or {})
        if "default" in body:
            block["default"] = body["default"]
        if "fleets" in body:
            block["fleets"] = body["fleets"]
        policy["agent_hooks"] = block
    if "os_events" in body:
        os_events = body["os_events"]
        if not isinstance(os_events, dict):
            raise HTTPException(status_code=422, detail={
                "message": "Could not save.",
                "errors": ["os_events: an object of fleet -> \"on\" or \"off\""]})
        os_block = copy.deepcopy(policy.get("agent_os_events") or {})
        os_block["fleets"] = {f: {"mode": m} for f, m in os_events.items()}
        policy["agent_os_events"] = os_block
    try:
        saved = device_store.save_policy(tenant_id, policy, actor=f"tenant:{tenant_id}")
    except PolicyError as e:
        raise HTTPException(status_code=422, detail={"message": "Could not save.",
                                                     "errors": e.errors})
    hooks_block = saved.get("agent_hooks") or {}
    from core.dlp.agent_hooks import DEFAULT_SETTING
    return {"agents": hooks_block.get("agents", {}),
            "default": hooks_block.get("default", DEFAULT_SETTING),
            "fleets": _fleet_rows(tenant_id, hooks_block, saved.get("agent_os_events"))}


# ── what agents did (agent OS events, docs/specs/agent-os-events.md) ──


@router.get("/os-events")
async def os_events_overview(request: Request, since: float = 0):
    """Recent outside_profile events, and per-laptop, per-agent counts for the
    last 24 hours."""
    from core.runtime_policy import os_events
    tenant_id = get_tenant_from_request(request)
    out = os_events.summary(tenant_id, since=since)
    # Name agent-managed laptops, as the hook overview does.
    try:
        from core.dlp import devices as dv
        enrolled = dv.records_for(tenant_id, [row.get("device") or ""
                                              for row in out["laptops"] + out["alerts"]])
    except Exception:
        enrolled = {}
    for row in out["laptops"] + out["alerts"]:
        rec = enrolled.get(row.get("device") or "")
        if rec:
            row["hostname"] = rec.get("hostname") or ""
            row["fleet"] = rec.get("fleet") or ""
    return out
