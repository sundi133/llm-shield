"""The one call both proxy endpoints make after their input guardrails.

Spec: docs/specs/gateway-routing-failover.md, section 4.1. Returns None when
the request's `model` names no route (the endpoint then does exactly what it
did before), a Plan to dispatch, or a Refusal to answer like a block.
"""

from __future__ import annotations

import logging

from core.llm_gateway import config, select

logger = logging.getLogger("votal.llm_gateway")
DATA_CLASS_HEADER = "X-Shield-Data-Class"


def _prompt_chars(messages: list) -> int:
    n = 0
    for m in messages or []:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, str):
            n += len(c)
        elif isinstance(c, list):
            n += sum(len(p.get("text") or "") for p in c if isinstance(p, dict))
    return n


def context_for(request, tenant_id: str, input_result, agent_key, role_name, messages) -> select.CallContext:
    flagged = tuple(sorted({r.guardrail_name for r in (getattr(input_result, "results", None) or [])
                            if not r.passed}))
    data_class = ""
    try:
        data_class = (request.headers.get(DATA_CLASS_HEADER) or "").strip().lower()[:64]
    except Exception:
        pass
    return select.CallContext(tenant_id=tenant_id, agent=str(agent_key or ""), role=str(role_name or ""),
                              data_class=data_class, flagged=flagged, prompt_chars=_prompt_chars(messages))


async def resolve(request, body: dict, tenant_id: str, input_result, agent_key, role_name, messages):
    """None (not routed), select.Plan, or select.Refusal. Never raises."""
    model = body.get("model")
    if not tenant_id or not isinstance(model, str) or not config.enabled():
        return None
    try:
        snap = await config.cached(tenant_id)
        route = select.match_route(snap, model)
    except Exception:
        logger.warning("routing config unavailable; the default upstream is used", exc_info=True)
        return None
    if route is None:
        return None
    # A matched route never falls back to the default upstream: its rules may
    # exist to keep this prompt away from it.
    try:
        ctx = context_for(request, tenant_id, input_result, agent_key, role_name, messages)
        return select.plan(snap, route, ctx)
    except Exception:
        logger.warning("route %s could not be planned; refusing", route.get("name"), exc_info=True)
        return select.Refusal(route.get("name", model), "the route could not be evaluated", "error")
