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
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request, require_config_write
from core.policy_learning import draft as drafts
from core.policy_learning import observe

router = APIRouter(prefix="/v1/tenant/me/agents/{agent_id}/policy", tags=["agent-policy-draft"])


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
