"""The guard-path face of cross-app flow control.

Three call sites use this module, and only these two coroutines:

  check_call   before a tool call is allowed: /v1/shield/tool/check, MCP
               tools/call (core/mcp/enforcement.py) and cap/mint.
  record_call  after a call is allowed (evidence "authorized") or its result
               came back (evidence "observed", with DLP-detected tags).

Cost contract (docs/specs/cross-app-flow-control.md §2):
  * no policy for the tenant -> one dict lookup, returns None, no I/O;
  * a call that matches no rule's destination -> CPU only, returns None;
  * only a destination-matched call reads state, only a source call writes it.

Nothing here raises into the guard path. An internal error behaves like an
unreadable store: allow with an advisory result, or block when the tenant set
fail_closed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Optional

from core.xflow import state
from core.xflow.policy import (
    CompiledPolicy,
    PolicyError,
    apps_for,
    compile_policy,
    destination_rules,
    evaluate,
    exposure_for,
    make_record,
    source_classification,
    validate_policy,
)

logger = logging.getLogger("votal.xflow")

GUARDRAIL = "cross_app_flow"
_OFF = ("0", "off", "false", "no")


def enabled() -> bool:
    """SHIELD_XFLOW=off disables every hook for every tenant (escape hatch)."""
    return os.getenv("SHIELD_XFLOW", "on").strip().lower() not in _OFF


def _cache_ttl() -> float:
    try:
        return max(0.0, float(os.getenv("SHIELD_XFLOW_POLICY_CACHE_S", "5")))
    except ValueError:
        return 5.0


# ── policy cache ─────────────────────────────────────────────────────

_cache: dict[str, tuple[float, Optional[CompiledPolicy]]] = {}


def invalidate(tenant_id: Optional[str] = None) -> None:
    """Drop the cached policy (all tenants when None). Other replicas pick up
    a change within SHIELD_XFLOW_POLICY_CACHE_S."""
    if tenant_id is None:
        _cache.clear()
    else:
        _cache.pop(tenant_id, None)


def load_policy(tenant_id: str) -> Optional[dict]:
    """The tenant's stored, normalized policy, or None. Raises on a store error."""
    raw = state.load_policy_json(tenant_id)
    if not raw:
        return None
    return validate_policy(json.loads(raw))


def save_policy(tenant_id: str, policy: Any) -> dict:
    """Validate (raises PolicyError) and store a policy; returns the normalized form."""
    normalized = validate_policy(policy)
    state.save_policy_json(tenant_id, json.dumps(normalized, separators=(",", ":")))
    invalidate(tenant_id)
    return normalized


def delete_policy(tenant_id: str) -> bool:
    deleted = state.delete_policy_json(tenant_id)
    invalidate(tenant_id)
    return deleted


def get_policy(tenant_id: Optional[str]) -> Optional[CompiledPolicy]:
    """The compiled, ENABLED policy for enforcement, or None.

    Caches misses too, so a tenant without a policy costs a dict lookup. A
    corrupt or unreadable stored policy is treated as no policy (logged) and
    never raises into the guard path.
    """
    if not tenant_id or not enabled():
        return None
    now = time.monotonic()
    hit = _cache.get(tenant_id)
    if hit is not None and hit[0] > now:
        return hit[1]
    cp: Optional[CompiledPolicy] = None
    try:
        policy = load_policy(tenant_id)
        if policy is not None:
            cp = compile_policy(policy)
            if not cp.enabled:
                cp = None
    except PolicyError as e:
        logger.warning("xflow: stored policy for tenant %s is invalid, not enforced: %s",
                       tenant_id, e)
    except Exception as e:
        logger.warning("xflow: could not load policy for tenant %s: %s", tenant_id, e)
    _cache[tenant_id] = (now + _cache_ttl(), cp)
    return cp


# ── scopes ───────────────────────────────────────────────────────────


def principal_for(cp: CompiledPolicy, agent: Optional[str], user: Optional[str]) -> Optional[str]:
    agent = (agent or "").strip()
    user = (user or "").strip()
    if cp.principal_scope == "off" or not agent:
        return None
    if cp.principal_scope == "agent":
        return agent
    return f"{agent}|{user}" if user else None


def _read_scopes(cp, tenant_id, session_id, principal) -> list[tuple[str, str]]:
    out = []
    if session_id:
        out.append((state.session_key(tenant_id, session_id), "session"))
    if principal:
        out.append((state.principal_key(tenant_id, principal), "principal"))
    return out


def _write_scopes(cp, tenant_id, session_id, principal) -> list[tuple[str, int]]:
    out = []
    if session_id:
        out.append((state.session_key(tenant_id, session_id), cp.session_ttl))
    if principal:
        out.append((state.principal_key(tenant_id, principal), cp.principal_window))
    return out


# ── results ──────────────────────────────────────────────────────────

_VERB = {"block": "block", "require_approval": "require approval", "warn": "flag"}


def _result(cp: CompiledPolicy, decision: dict, latency_ms: float) -> dict:
    """A guardrail-result dict in the shape every tool path already carries,
    so monitor mode, decision audit, telemetry and webhooks see it unchanged."""
    action = decision["action"]
    details = {
        "xflow_action": action,
        "mode": cp.mode,
        "destination": decision["destination"],
        "flow_violations": decision["violations"],
        "lineage": decision["lineage"],
    }
    base = {"guardrail": GUARDRAIL, "details": details, "latency_ms": round(latency_ms, 2)}
    if action == "allow":
        return {**base, "passed": True, "action": "pass",
                "message": "No cross-app flow rule violated"}
    if cp.mode == "monitor":
        return {**base, "passed": True, "action": "log",
                "message": f"[monitor] would {_VERB[action]}: {decision['message']}"}
    return {**base, "passed": False, "action": action, "message": decision["message"]}


def _advisory(cp: CompiledPolicy, reason: str, destination: dict, latency_ms: float,
              *, block: bool = False) -> dict:
    details = {"xflow_action": "block" if block else "allow", "mode": cp.mode,
               "destination": destination, "flow_violations": [], "lineage": [],
               "advisory": not block, "reason": reason}
    if block and cp.mode != "monitor":
        return {"guardrail": GUARDRAIL, "passed": False, "action": "block",
                "message": f"Cross-app flow state unavailable and the policy is fail-closed: {reason}",
                "details": details, "latency_ms": round(latency_ms, 2)}
    return {"guardrail": GUARDRAIL, "passed": True, "action": "pass",
            "message": f"Cross-app flow not evaluated: {reason}",
            "details": details, "latency_ms": round(latency_ms, 2)}


def approval_rule_for(result: dict) -> dict:
    """The approval-rule dict create_approval_request expects, for the first
    violation that asked for approval."""
    for v in (result.get("details") or {}).get("flow_violations") or []:
        if v.get("action") == "require_approval":
            return {"rule_id": f"xflow:{v['rule_id']}",
                    "min_approvals": int(v.get("min_approvals", 1)),
                    "request_ttl_seconds": int(v.get("approval_ttl_seconds", 3600)),
                    "single_use": True}
    return {"rule_id": "xflow", "min_approvals": 1, "request_ttl_seconds": 3600,
            "single_use": True}


def open_approval_request(tenant_id: str, flow: dict, *, agent_key: str, tool_name: str,
                          session_id: str, tool_params: Optional[dict], workflow: str = "default",
                          agent_instance_id: Optional[str] = None,
                          resource: Optional[str] = None) -> dict:
    """Open an approval request for a flow finding, or return the one already
    pending for the same agent, tool, session, arguments and rule.

    An agent that retries a held call must not page its approvers once per
    retry: every retry would otherwise open another request.
    """
    from core.approvals import params_hash
    from storage.agentic_control_plane import create_approval_request, list_approval_requests

    rule = approval_rule_for(flow)
    wanted = params_hash(tool_params)
    try:
        for req in list_approval_requests(tenant_id, status="pending"):
            if (req.get("rule_id") == rule["rule_id"] and req.get("agent_key") == agent_key
                    and req.get("tool_name") == tool_name
                    and req.get("session_id") == session_id
                    and (req.get("agent_instance_id") or None) == (agent_instance_id or None)
                    and (req.get("resource") or None) == (resource or None)
                    and params_hash(req.get("tool_params")) == wanted):
                return req
    except Exception as e:  # listing is an optimisation; opening must still work
        logger.debug("xflow: could not list pending approvals: %s", e)
    return create_approval_request(
        tenant_id, agent_key=agent_key, tool_name=tool_name, session_id=session_id,
        workflow=workflow, tool_params=tool_params, rule=rule,
        agent_instance_id=agent_instance_id, resource=resource,
    )


# ── the two guard-path hooks ─────────────────────────────────────────


async def check_call(
    tenant_id: Optional[str],
    *,
    tool_name: str,
    params: Optional[dict] = None,
    route: Optional[str] = None,
    resource: Optional[str] = None,
    session_id: Optional[str] = None,
    agent: Optional[str] = None,
    user: Optional[str] = None,
) -> Optional[dict]:
    """Judge an outgoing call. None means "no rule applies": append nothing.

    Otherwise a result dict with guardrail "cross_app_flow" and action
    pass | log (monitor) | warn | require_approval | block. The caller maps
    require_approval onto its own approval channel.
    """
    cp = get_policy(tenant_id)
    if cp is None or not cp.rules:
        return None
    start = time.perf_counter()
    try:
        apps = apps_for(cp, tool_name, route)
        exposure = exposure_for(cp, tool_name, apps, params, resource)
        rules = destination_rules(cp, tool_name, apps, exposure)
    except Exception as e:  # pragma: no cover - pure code; defensive
        logger.warning("xflow: classification failed for %s: %s", tool_name, e)
        return None
    if not rules:
        return None
    destination = {"tool": tool_name, "apps": apps, "exposure": exposure}
    principal = principal_for(cp, agent, user)
    scopes = _read_scopes(cp, tenant_id, session_id, principal)
    if not scopes:
        return _advisory(cp, "no session id or principal to trace this call to",
                         destination, (time.perf_counter() - start) * 1000)
    try:
        records = await asyncio.to_thread(state.read, scopes)
        decision = evaluate(cp, tool_name=tool_name, apps=apps, exposure=exposure,
                            records=records, rules=rules)
    except Exception as e:
        logger.warning("xflow: state read failed for tenant %s: %s", tenant_id, e)
        return _advisory(cp, f"flow state unavailable ({type(e).__name__})", destination,
                         (time.perf_counter() - start) * 1000, block=cp.fail_closed)
    return _result(cp, decision, (time.perf_counter() - start) * 1000)


async def record_call(
    tenant_id: Optional[str],
    *,
    tool_name: str,
    evidence: str,
    path: str,
    route: Optional[str] = None,
    session_id: Optional[str] = None,
    agent: Optional[str] = None,
    user: Optional[str] = None,
    tags: Optional[list[str]] = None,
    tool_call_id: Optional[str] = None,
    input_sources: Optional[list[str]] = None,
) -> Optional[dict]:
    """Record that this session read from a classified app (or got tagged data).

    Returns the stored record, or None when there was nothing to record. Awaited
    by callers so the very next call in the session sees it; failures are
    logged and swallowed (the decision already made stands).
    """
    cp = get_policy(tenant_id)
    if cp is None or not cp.rules:
        return None
    try:
        apps = apps_for(cp, tool_name, route)
        classification = source_classification(cp, tool_name, apps)
        tags = [str(t) for t in (tags or []) if t]
        if classification is None and not tags:
            return None
        principal = principal_for(cp, agent, user)
        scopes = _write_scopes(cp, tenant_id, session_id, principal)
        if not scopes:
            return None
        record = make_record(tool_name=tool_name, route=route, apps=apps,
                             classification=classification, tags=tags, evidence=evidence,
                             path=path, at=time.time(), tool_call_id=tool_call_id,
                             input_sources=input_sources)
        await asyncio.to_thread(state.write, scopes, record)
        return record
    except Exception as e:
        logger.warning("xflow: could not record source %s for tenant %s: %s",
                       tool_name, tenant_id, e)
        return None


# ── simulation (policy API, off the hot path) ────────────────────────


def simulate(policy: Any, *, tool_name: str, route: Optional[str] = None,
             params: Optional[dict] = None, resource: Optional[str] = None,
             sources: Optional[list[dict]] = None) -> dict:
    """Decide a call exactly as enforcement would, against hypothetical sources.

    Pure: validates ``policy`` (raises PolicyError), reads and writes no state.
    Each source is {tool_name, route?, tags?}, classified like a real call.
    """
    normalized = validate_policy(policy)
    cp = compile_policy(normalized)
    now = time.time()
    records = []
    for i, src in enumerate(sources or []):
        s_tool = str(src.get("tool_name") or "")
        s_route = src.get("route")
        s_apps = apps_for(cp, s_tool, s_route)
        cls = source_classification(cp, s_tool, s_apps)
        tags = [str(t) for t in (src.get("tags") or []) if t]
        if cls is None and not tags:
            continue
        rec = make_record(tool_name=s_tool, route=s_route, apps=s_apps, classification=cls,
                          tags=tags, evidence="simulated", path="simulate", at=now + i)
        rec["scope"] = "session"
        records.append(rec)
    apps = apps_for(cp, tool_name, route)
    exposure = exposure_for(cp, tool_name, apps, params, resource)
    rules = destination_rules(cp, tool_name, apps, exposure) if cp.rules else []
    decision = evaluate(cp, tool_name=tool_name, apps=apps, exposure=exposure,
                        records=records, rules=rules)
    result = _result(cp, decision, 0.0) if rules else None
    if not cp.enabled:
        note = "policy is disabled: enforcement would not run"
    elif not rules:
        note = "no rule's destination matches this call: enforcement appends nothing"
    else:
        note = ""
    return {
        "destination": {"tool": tool_name, "apps": apps, "exposure": exposure},
        "rules_matching_destination": [r.id for r in rules],
        "recorded_sources": records,
        "decision": decision,
        "result": result,
        "note": note,
    }
