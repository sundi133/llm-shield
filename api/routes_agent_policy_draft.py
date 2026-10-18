"""Suggested policy for an agent: observations, the draft, questions, review, apply.

Spec: docs/specs/policy-from-purpose.md, section 4.1. Admin plane, off the
guard path. Reads need the tenant; anything that stores or changes something
goes through the config write gate, and apply also through the registry write
gate.

    GET  /v1/tenant/me/agents/{agent_id}/policy/observations?days=14
    POST /v1/tenant/me/agents/{agent_id}/policy/draft       {window_days, use_model}
    GET  /v1/tenant/me/agents/{agent_id}/policy/draft
    PUT  /v1/tenant/me/agents/{agent_id}/policy/draft/answers   {answers: {question_id: option}}
    POST /v1/tenant/me/agents/{agent_id}/policy/draft/simulate
    PUT  /v1/tenant/me/agents/{agent_id}/policy/draft/items/{item_id}   {status: accepted | rejected}
    POST /v1/tenant/me/agents/{agent_id}/policy/draft/accept-low-risk
    POST /v1/tenant/me/agents/{agent_id}/policy/draft/apply
    GET  /v1/tenant/me/agents/{agent_id}/policy/suggestions
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request, require_config_write
from core.policy_learning import draft as drafts
from core.policy_learning import observe

router = APIRouter(prefix="/v1/tenant/me/agents/{agent_id}/policy", tags=["agent-policy-draft"])


class ItemDecision(BaseModel):
    status: str = Field(..., pattern="^(accepted|rejected)$")


class AnswersRequest(BaseModel):
    answers: dict[str, str] = Field(default_factory=dict)


class DraftRequest(BaseModel):
    window_days: int = Field(14, ge=1, le=30)
    use_model: bool = True


def _actor(request: Request) -> str:
    try:
        from core.auth import acting_user_sub
        return acting_user_sub(request)
    except Exception:
        return ""


def _draft_or_404(tenant_id: str, agent_id: str) -> dict:
    d = drafts.load(tenant_id, agent_id)
    if d is None:
        raise HTTPException(status_code=404, detail="no draft yet: POST .../policy/draft to build one")
    return d


@router.get("/observations")
async def get_observations(agent_id: str, request: Request, days: int = 14):
    tenant_id = get_tenant_from_request(request)
    days = max(1, min(int(days), 30))
    entries = observe.read(tenant_id, agent_id, days)
    return {"agent_id": agent_id, "days": days, "entries": entries,
            "tools": len({e["tool"] for e in entries}),
            "calls": sum(int(e.get("count") or 0) for e in entries)}


@router.post("/draft")
async def build_draft(agent_id: str, request: Request, body: Optional[DraftRequest] = None):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "build a suggested policy")
    body = body or DraftRequest()
    previous = drafts.load(tenant_id, agent_id)
    model = None
    if body.use_model:
        try:
            from core.policy_learning import purpose
            model = await purpose.interpret(tenant_id, agent_id, body.window_days)
        except ImportError:
            model = None
    try:
        d = drafts.build(tenant_id, agent_id, window_days=body.window_days,
                         created_by=_actor(request), model=model, previous=previous)
    except drafts.DraftError as e:
        raise HTTPException(status_code=e.status, detail={"error": e.code, "message": str(e)})
    drafts.save(tenant_id, agent_id, d)
    return d


@router.get("/draft")
async def get_draft(agent_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    return _draft_or_404(tenant_id, agent_id)


@router.put("/draft/answers")
async def answer_questions(agent_id: str, body: AnswersRequest, request: Request):
    """Answer the draft's questions; it is rebuilt with the answers (the model
    is not asked again). Only a question's listed options are accepted."""
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "answer a suggested policy's questions")
    previous = _draft_or_404(tenant_id, agent_id)
    questions = {q["id"]: q for q in previous.get("questions") or []}
    for qid, option in body.answers.items():
        q = questions.get(qid)
        if q is None:
            raise HTTPException(status_code=422, detail=f"no question '{qid}' in this draft")
        if option not in q["options"]:
            raise HTTPException(status_code=422,
                                detail=f"'{option}' is not an answer to '{qid}'; one of {q['options']}")
    try:
        d = drafts.build(tenant_id, agent_id, window_days=int(previous.get("window_days") or 14),
                         created_by=_actor(request), model=previous.get("model_output"),
                         answers=body.answers, previous=previous)
    except drafts.DraftError as e:
        raise HTTPException(status_code=e.status, detail={"error": e.code, "message": str(e)})
    drafts.save(tenant_id, agent_id, d)
    return d


@router.post("/draft/simulate")
async def simulate_draft(agent_id: str, request: Request):
    """Changes nothing: replays the window's observed calls against the draft."""
    tenant_id = get_tenant_from_request(request)
    d = _draft_or_404(tenant_id, agent_id)
    obs = observe.read(tenant_id, agent_id, int(d.get("window_days") or 14))
    return {"agent_id": agent_id, "draft_id": d["id"], **drafts.simulate(d, obs)}


@router.put("/draft/items/{item_id:path}")
async def decide_item(agent_id: str, item_id: str, body: ItemDecision, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "review a suggested policy")
    d = _draft_or_404(tenant_id, agent_id)
    for i in d["items"]:
        if i["id"] == item_id:
            if i["status"] == "stale" and body.status == "accepted":
                raise HTTPException(status_code=409, detail="this line is stale: rebuild the draft")
            i["status"] = body.status
            drafts.save(tenant_id, agent_id, d)
            return i
    raise HTTPException(status_code=404, detail=f"no line '{item_id}' in this draft")


@router.post("/draft/accept-low-risk")
async def accept_low_risk(agent_id: str, request: Request):
    """Accept every pending low-risk line that was observed. Lines implied only
    by the purpose, and medium or high risk lines, still need a decision each."""
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "review a suggested policy")
    d = _draft_or_404(tenant_id, agent_id)
    done = []
    for i in d["items"]:
        if i["status"] == "pending" and i["risk"] == "low" and (i.get("evidence") or {}).get("observed"):
            i["status"] = "accepted"
            done.append(i["id"])
    drafts.save(tenant_id, agent_id, d)
    return {"accepted": done, "draft": d}


@router.post("/draft/apply")
async def apply_draft(agent_id: str, request: Request):
    """Write the accepted lines to the agent's registry entry, and append the
    accepted approval rules. 409 when the entry changed since the draft."""
    import time
    from core.auth import audit_actor, require_registry_write
    from storage.admin_audit import log_admin_action
    from storage.agentic_control_plane import get_control_plane_config, set_control_plane_config
    from api.routes_agents_registry import _save_agents
    from storage.tenant_store import kv_get

    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "apply a suggested policy")
    require_config_write(request, tenant_id, "apply a suggested policy")
    d = _draft_or_404(tenant_id, agent_id)
    agents = kv_get(f"agents:{tenant_id}") or {}
    before = agents.get(agent_id) if isinstance(agents, dict) else None
    if not isinstance(before, dict):
        raise HTTPException(status_code=404, detail=f"no agent '{agent_id}'")
    if before.get("updated_at") != d.get("base_version"):
        raise HTTPException(status_code=409, detail={
            "error": "agent_changed",
            "message": "the agent was edited after this draft was built; rebuild the draft"})
    if not drafts.accepted(d, "tool"):
        raise HTTPException(status_code=409, detail={
            "error": "nothing_accepted",
            "message": "accept at least one tool line: applying an empty list would remove every tool"})

    after = drafts.applied_record(before, d)
    now = int(time.time())
    after["updated_at"] = now
    after["updated_by"] = _actor(request)
    agents[agent_id] = after
    _save_agents(tenant_id, agents)

    rules = drafts.approval_rules_to_add(tenant_id, agent_id, d)
    if rules:
        cfg = get_control_plane_config(tenant_id)
        cfg.setdefault("approvals", {}).setdefault("rules", []).extend(rules)
        set_control_plane_config(tenant_id, cfg)

    d["applied"] = {"at": now, "by": _actor(request), "tools": after["tools"],
                    "role_permissions": after.get("role_permissions") or {}}
    d["base_version"] = now
    drafts.save(tenant_id, agent_id, d)
    try:
        log_admin_action(action="agent_policy_applied", actor=audit_actor(request, tenant_id),
                         tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "",
                         before=before, after=after,
                         metadata={"agent_id": agent_id, "draft_id": d["id"],
                                   "approval_rules_added": [r["rule_id"] for r in rules]})
    except Exception:       # noqa: BLE001 - the audit must not undo an applied change
        pass
    return {"status": "applied", "agent": after, "approval_rules_added": rules, "draft": d}


@router.get("/suggestions")
async def get_suggestions(agent_id: str, request: Request):
    """After apply: what the agent was seen doing outside the applied policy."""
    tenant_id = get_tenant_from_request(request)
    d = _draft_or_404(tenant_id, agent_id)
    obs = observe.read(tenant_id, agent_id, 30)
    return {"agent_id": agent_id, "applied": d.get("applied"), "suggestions": drafts.suggestions(d, obs)}
