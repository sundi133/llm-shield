"""Discovery ingest (data plane): proxies, log shippers and code scans report
what AI they saw. Spec: docs/specs/ai-discovery.md, section 4.2.

    POST /v1/shield/discovery/batch   {source, observations: [...]}   a tenant key
    GET  /v1/shield/discovery/lists   for the proxy shipper: catalog domains, inspected and blocked hosts

Off the guard path. A source can add sightings, never mark anything governed.
Device observations come only through the device heartbeat (a device key).
"""

from __future__ import annotations

import threading
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.discovery import inventory

router = APIRouter(prefix="/v1/shield/discovery", tags=["discovery-ingest"])

BATCHES_PER_MINUTE = 60
_rate: dict[str, list] = {}
_rate_lock = threading.Lock()
#: Sources that may post batches here. device_agent reports through the
#: heartbeat; shield is Shield's own evidence.
BATCH_SOURCES = ("proxy", "dns_log", "repo_scan", "idp", "custom")


class Batch(BaseModel):
    source: str
    observations: list = Field(default_factory=list)


def _tenant(request: Request) -> str:
    from core.auth import SCOPE_TENANT, caller_tenant_scope
    scope, tenant = caller_tenant_scope(request)
    if scope != SCOPE_TENANT:
        raise HTTPException(status_code=400, detail="post discovery batches with a tenant API key")
    return tenant


def _rate_ok(tenant_id: str) -> bool:
    now = time.time()
    with _rate_lock:
        times = [t for t in _rate.get(tenant_id, []) if now - t < 60]
        if len(times) >= BATCHES_PER_MINUTE:
            _rate[tenant_id] = times
            return False
        times.append(now)
        _rate[tenant_id] = times
    return True


@router.post("/batch", status_code=202)
async def post_batch(body: Batch, request: Request):
    tenant_id = _tenant(request)
    if body.source not in BATCH_SOURCES:
        raise HTTPException(status_code=400,
                            detail=f"source: one of {', '.join(BATCH_SOURCES)} "
                                   f"(devices report through their heartbeat)")
    if not _rate_ok(tenant_id):
        raise HTTPException(status_code=429, detail=f"at most {BATCHES_PER_MINUTE} batches a minute",
                            headers={"Retry-After": "60"})
    try:
        out = inventory.record(tenant_id, body.source, body.observations)
    except inventory.InventoryError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    except Exception:
        raise HTTPException(status_code=503, detail="inventory store unavailable; retry the batch")
    try:
        from core.discovery import notify
        await notify.dispatch(tenant_id, out["events"])
    except Exception:                       # webhooks never fail the batch
        pass
    return {k: v for k, v in out.items() if k != "events"} | {"new_entries": len(out["events"])}


@router.get("/lists")
async def get_lists(request: Request):
    """What a proxy shipper needs: the catalog's domains (to recognize AI
    traffic), the hosts Shield inspects, and the hosts blocked from the AI
    inventory. Read-only."""
    tenant_id = _tenant(request)
    from core.discovery import catalog
    from core.dlp import device_store
    policy = device_store.get_policy(tenant_id)
    return {"catalog_version": catalog.VERSION, "domains": catalog.domains(tenant_id),
            "ai_hosts": list(policy.get("ai_hosts") or []),
            "blocked_hosts": list((policy.get("discovery") or {}).get("blocked_hosts") or [])}
