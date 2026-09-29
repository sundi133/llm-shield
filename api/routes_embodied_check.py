"""POST /v1/shield/embodied/check: the embodied action guard's server endpoint.

Data plane only. A new guard endpoint: deterministic, no model, one cached
profile lookup. The same evaluator as the robot SDK, so the robot and this
endpoint decide identically (docs/specs/embodied-action-guard.md §4, §7).

Robots decide locally; this endpoint exists for parity, for planners that run
in the cloud, and for the embodied-bench contract: POST the event, get back
{verdict, rail, reasons, ...}.

Fail safe: a physical action is blocked when the profile cannot be read and
none is cached. An approval grant can clear a require_approval verdict for the
exact action it was issued for; it never lifts a block.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from core.auth import get_tenant_from_request
from core.embodied import cache
from core.embodied.evaluator import APPROVAL, BLOCK, PASS, evaluate
from core.embodied.model import ProfileError, valid_name

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/shield/embodied", tags=["embodied"])
MAX_BODY = 64 * 1024
GUARDRAIL = "embodied_guard"


def enabled() -> bool:
    return os.environ.get("SHIELD_EMBODIED", "on").strip().lower() not in ("off", "0", "false")


def _bound_profile(tenant_id: str, agent_key: str) -> Optional[str]:
    try:
        from storage.tenant_store import kv_get
        agent = (kv_get(f"agents:{tenant_id}") or {}).get(agent_key) or {}
        return agent.get("action_profile") or None
    except Exception:
        return None


def _action(event: dict) -> tuple[str, dict]:
    a = event.get("proposed_action") if isinstance(event.get("proposed_action"), dict) else {}
    params = a.get("params") if isinstance(a.get("params"), dict) else {}
    return str(a.get("tool") or "report"), params


def _open_approval(tenant_id: str, *, agent_key: str, tool: str, params: dict, session: str,
                   rail: str) -> Optional[str]:
    """One pending request per robot, action, run and arguments: a robot that
    retries a held action does not page its approvers once per retry."""
    try:
        from core.approvals import params_hash
        from storage.agentic_control_plane import create_approval_request, list_approval_requests
        rule_id = f"embodied:{rail}"
        wanted = params_hash(params)
        for req in list_approval_requests(tenant_id, status="pending"):
            if (req.get("rule_id") == rule_id and req.get("agent_key") == agent_key
                    and req.get("tool_name") == tool and req.get("session_id") == session
                    and params_hash(req.get("tool_params")) == wanted):
                return req["request_id"]
        req = create_approval_request(tenant_id, agent_key=agent_key, tool_name=tool,
                                      session_id=session, workflow="embodied", tool_params=params,
                                      rule={"rule_id": rule_id, "min_approvals": 1})
        return req.get("request_id")
    except Exception as e:
        logger.warning("embodied: could not open an approval request: %s", e)
        return None


def _grant_clears(tenant_id: str, grant: str, *, tool: str, params: dict,
                  session: str) -> tuple[bool, str]:
    from core.approvals import ApprovalError, params_hash, verify_grant
    try:
        claims = verify_grant(grant, expected_tool=tool, expected_params_hash=params_hash(params),
                              expected_session=session, allow_breakglass=False)
    except ApprovalError as e:
        return False, f"approval grant rejected: {e}"
    if claims.tenant_id != tenant_id:
        return False, "approval grant rejected: issued for another tenant"
    return True, "approved by signed grant"


def _record(tenant_id: str, decision: dict, event: dict, *, agent_key: str, profile: str,
            phash: str, source_ip: str) -> None:
    """Decision audit for block and approval; telemetry for every non-pass."""
    if decision["verdict"] == PASS:
        return
    tool, _ = _action(event)
    ctx = event.get("context") if isinstance(event.get("context"), dict) else {}
    meta = {"path": "embodied_check", "profile": profile, "profile_hash": phash,
            "rail": decision["rail"], "reasons": decision["reasons"],
            "rails": [r["rail"] for r in decision.get("rails", [])],
            "stage": event.get("stage"), "run_id": event.get("run_id"),
            "step": event.get("step"), "request_id": decision.get("request_id")}
    action = "block" if decision["verdict"] == BLOCK else "warn"
    try:
        from storage.decision_audit import log_decision
        log_decision(tenant_id=tenant_id, action=action, guardrail=GUARDRAIL, agent_key=agent_key,
                     tool_name=f"embodied:{tool}", user_role=str(ctx.get("role") or ""),
                     session_id=str(event.get("run_id") or ""), reason=decision["message"],
                     source_ip=source_ip, metadata=meta)
    except Exception:
        pass
    try:
        from core.telemetry import build_guardrail_event, record_event
        tel = build_guardrail_event(
            trace_id=f"em-{int(time.time() * 1000)}", guardrail_name=GUARDRAIL,
            passed=False, action=action, message=decision["message"], details=meta,
            agent_key=agent_key, tenant_id=tenant_id, source_ip=source_ip,
            input_text=f"embodied:{tool}")
        tel.update({"votal.embodied.rail": decision["rail"],
                    "votal.embodied.verdict": decision["verdict"],
                    "votal.embodied.profile": profile})
        record_event(tel)
    except Exception:
        pass


@router.post("/check")
async def embodied_check(request: Request, background: BackgroundTasks,
                         profile: Optional[str] = Query(None, description="action profile name; "
                                                        "defaults to the robot's registry binding")):
    if not enabled():
        raise HTTPException(status_code=404, detail="the embodied action guard is disabled")
    tenant_id = get_tenant_from_request(request)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail=f"event larger than {MAX_BODY} bytes")
    try:
        event = json.loads(raw or b"null")
    except ValueError:
        raise HTTPException(status_code=422, detail="the body is not JSON")
    if not isinstance(event, dict):
        raise HTTPException(status_code=422, detail="the event must be a JSON object")

    agent_key = (request.headers.get("X-Agent-Key") or "").strip()
    name = profile or (_bound_profile(tenant_id, agent_key) if agent_key else None)
    if not name:
        raise HTTPException(status_code=404, detail="no action profile: pass ?profile= or bind "
                                                    "the robot (registry action_profile)")
    if not valid_name(name):
        raise HTTPException(status_code=400, detail="invalid profile name")
    try:
        found = cache.get(tenant_id, name)
    except ProfileError as e:
        raise HTTPException(status_code=409, detail={
            "message": f"stored action profile '{name}' no longer validates", "errors": e.errors})
    except cache.Unavailable:
        return {"verdict": BLOCK, "rail": "profile_unavailable", "reasons": ["profile_unavailable"],
                "message": "the action profile cannot be read; failing safe", "rails": [],
                "profile": name, "profile_hash": None, "evaluated_us": 0}
    if found is None:
        raise HTTPException(status_code=404, detail=f"action profile '{name}' not found")
    prof, phash = found

    t0 = time.perf_counter()
    decision = evaluate(prof, event)
    evaluated_us = round((time.perf_counter() - t0) * 1e6, 1)

    tool, params = _action(event)
    session = str(event.get("run_id") or "")
    who = agent_key or f"embodied:{name}"
    if decision["verdict"] == APPROVAL:
        grant = event.get("approval_grant")
        if isinstance(grant, str) and grant:
            ok, why = _grant_clears(tenant_id, grant, tool=tool, params=params, session=session)
            if ok:
                decision = {**decision, "verdict": PASS, "message": why, "approved": True}
            else:
                decision = {**decision, "message": f"{decision['message']}; {why}"}
        if decision["verdict"] == APPROVAL:
            decision["request_id"] = _open_approval(tenant_id, agent_key=who, tool=tool,
                                                    params=params, session=session,
                                                    rail=decision["rail"])

    body = {**decision, "profile": name, "profile_hash": phash, "evaluated_us": evaluated_us}
    source_ip = request.client.host if request.client else ""
    background.add_task(_record, tenant_id, body, event, agent_key=who, profile=name,
                        phash=phash, source_ip=source_ip)
    return body
