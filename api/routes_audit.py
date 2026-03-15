"""Audit log query routes for LLM Shield."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query

from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield", tags=["audit"])


@router.get("/audit")
async def query_audit_logs(
    agent_key: Optional[str] = Query(None, description="Filter by agent key"),
    action: Optional[str] = Query(None, description="Filter by action (pass/block/warn)"),
    since: Optional[str] = Query(None, description="Filter entries since ISO datetime"),
    until: Optional[str] = Query(None, description="Filter entries until ISO datetime"),
    limit: int = Query(100, ge=1, le=1000, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """Query audit logs with optional filters."""
    filters = {}
    if agent_key:
        filters["agent_key"] = agent_key
    if action:
        filters["action_taken"] = action
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until

    results = await audit_logger.query(
        filters=filters if filters else None,
        limit=limit,
        offset=offset,
    )
    return {"entries": results, "count": len(results), "limit": limit, "offset": offset}


@router.get("/stats")
async def get_stats(
    since: Optional[str] = Query(None, description="Stats since ISO datetime"),
):
    """Get aggregated statistics from the audit log.

    Returns: requests count, block rate, top triggered guardrails, avg latency.
    """
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            since_dt = None

    stats = await audit_logger.get_stats(since=since_dt)
    return stats
