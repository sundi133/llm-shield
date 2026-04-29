"""Decision audit query routes — query runtime guardrail enforcement decisions."""

from fastapi import APIRouter, Query
from typing import Optional

from storage.decision_audit import query_decisions

router = APIRouter(prefix="/v1/shield/decisions", tags=["decisions"])


@router.get("/{tenant_id}")
async def list_decisions(
    tenant_id: str,
    action: Optional[str] = Query(None, description="Filter: block, warn, pass"),
    guardrail: Optional[str] = Query(None, description="Filter by guardrail name"),
    agent_key: Optional[str] = Query(None, description="Filter by agent key"),
    tool_name: Optional[str] = Query(None, description="Filter by tool name"),
    since: Optional[str] = Query(None, description="ISO timestamp - entries after this time"),
    until: Optional[str] = Query(None, description="ISO timestamp - entries before this time"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Skip first N results"),
):
    """Query runtime guardrail decisions for a tenant.

    Returns enforcement decisions: which guardrail fired, what action was taken,
    for which agent/tool/user, and when. Essential for compliance audits.
    """
    decisions = query_decisions(
        tenant_id=tenant_id,
        action=action,
        guardrail=guardrail,
        agent_key=agent_key,
        tool_name=tool_name,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )

    return {
        "tenant_id": tenant_id,
        "decisions": decisions,
        "count": len(decisions),
        "filters": {
            "action": action,
            "guardrail": guardrail,
            "agent_key": agent_key,
            "tool_name": tool_name,
            "since": since,
            "until": until,
        },
    }
