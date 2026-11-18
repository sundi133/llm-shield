"""AI agent detection, admin plane (docs/specs/agent-impersonation-defense.md
section 9). Mounted by admin_app.py; nothing here is on the guard path.

Site keys for the tag (rev 8 step R1):

  GET    /v1/agent-detection/sitekeys              the tenant's site keys
  POST   /v1/agent-detection/sitekeys              create one
  DELETE /v1/agent-detection/sitekeys/{site_key}   delete one

Enforcement handoff (R6, spec section 5):

  GET    /v1/agent-detection/indicators            THE FEED for the edge: JSON, ?format=csv|nginx;
                                                   X-Shield-Feed-Token only; ETag; empty in monitor
  GET    /v1/agent-detection/indicators/preview    every indicator with its mode (portal)
  POST   /v1/agent-detection/indicators/{id}/revoke
  POST   /v1/agent-detection/indicators/clear      kill switch: remove all, pause publishing
  POST   /v1/agent-detection/indicators/resume
  GET|PUT /v1/agent-detection/enforcement          monitor/enforce per type, action, lifetime
  GET    /v1/agent-detection/enforcement/log
  GET|POST /v1/agent-detection/feed-tokens; DELETE /v1/agent-detection/feed-tokens/{id}

Reads take a portal session or a tenant key. Writes also pass the
configuration write gate (a portal admin or an admin-scoped key, per
SHIELD_CONFIG_WRITE_SCOPE). The feed takes ONLY a feed token: it is not a
tenant API key, so it can read the feed and nothing else, and the shared key
middleware (the guard path's) is untouched. SHIELD_AGENT_DETECTION=off
answers 404.
"""

from __future__ import annotations

from typing import Any, Optional

import hashlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from core import agent_detection as _agd
from core.agent_detection import indicators as ind
from core.agent_detection import sitekeys

router = APIRouter(tags=["agent-detection"])


class SiteKeyIn(BaseModel):
    origins: list[Any] = Field(default_factory=list)
    platform: str = "web"
    consent: str = "none"
    xff_hops: int = 1
    traps: bool = True
    label: Optional[str] = ""


def _on() -> None:
    if not _agd.enabled():
        raise HTTPException(status_code=404, detail="Not Found")


def _tenant(request: Request) -> str:
    from api.routes_tenant_self import _require_tenant
    return _require_tenant(request)


def _write(request: Request, tenant_id: str, action: str) -> None:
    from core.auth import require_config_write
    require_config_write(request, tenant_id, action)


def _actor(request: Request, tenant_id: str) -> str:
    try:
        from api.routes_tenant_self import _actor as actor
        return actor(request, tenant_id) or ""
    except Exception:       # noqa: BLE001 - attribution is best effort
        return ""


def _audit(request: Request, tenant_id: str, action: str, **meta) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", metadata=meta)
    except Exception:       # noqa: BLE001 - the action happened; the audit is best effort
        pass


@router.get("/v1/agent-detection/sitekeys")
def list_site_keys(request: Request):
    _on()
    tid = _tenant(request)
    return {"site_keys": sitekeys.list_for(tid), "max": sitekeys.MAX_PER_TENANT}


@router.post("/v1/agent-detection/sitekeys", status_code=201)
def create_site_key(body: SiteKeyIn, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "create an agent detection site key")
    try:
        rec = sitekeys.create(tid, origins=body.origins, platform=body.platform,
                              consent=body.consent, xff_hops=body.xff_hops, traps=body.traps,
                              label=body.label or "", created_by=_actor(request, tid))
    except sitekeys.SiteKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except sitekeys.LimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    _audit(request, tid, "agent_detection.sitekey.create", site_key=rec["site_key"],
           origins=rec["origins"])
    return rec


@router.delete("/v1/agent-detection/sitekeys/{site_key}")
def delete_site_key(site_key: str, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "delete an agent detection site key")
    if not sitekeys.delete(tid, site_key):
        raise HTTPException(status_code=404, detail="no such site key")
    _audit(request, tid, "agent_detection.sitekey.delete", site_key=site_key)
    return {"deleted": site_key}


# ── enforcement handoff (R6) ─────────────────────────────────────────

_FORMATS = {"json": "application/json", "csv": "text/csv; charset=utf-8",
            "nginx": "text/plain; charset=utf-8"}


@router.get("/v1/agent-detection/indicators")
def indicator_feed(request: Request, format: str = "json"):
    """The pull feed. Polling every 60 s is cheap: the ETag is the body's
    hash, so an unchanged list answers 304 with no body."""
    _on()
    tenant = ind.resolve_token(request.headers.get("x-shield-feed-token") or "")
    if not tenant:
        raise HTTPException(status_code=401, detail="send a feed token in X-Shield-Feed-Token")
    if format not in _FORMATS:
        raise HTTPException(status_code=400, detail="format must be json, csv or nginx")
    items = ind.feed(tenant)
    if format == "csv":
        body = ind.as_csv(items)
    elif format == "nginx":
        body = ind.as_nginx(items)
    else:
        body = ind.as_json(items)
    # the generated stamp changes every call; the ETag covers the indicators only
    etag = '"' + hashlib.sha256(ind.as_csv(items).encode() + format.encode()).hexdigest()[:32] + '"'
    headers = {"ETag": etag, "Cache-Control": "no-cache", "X-Indicator-Count": str(len(items))}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type=_FORMATS[format], headers=headers)


@router.get("/v1/agent-detection/indicators/preview")
def indicator_preview(request: Request):
    _on()
    tid = _tenant(request)
    st = ind.settings(tid)
    items = ind.active(tid)
    for i in items:
        i["mode"] = "paused" if st["paused"] else st["modes"].get(i["type"], "monitor")
    return {"settings": st, "indicators": items,
            "would_publish": sum(1 for i in items if i["mode"] == "monitor"),
            "published": sum(1 for i in items if i["mode"] == "enforce")}


@router.post("/v1/agent-detection/indicators/clear")
def indicator_clear(request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "clear all agent detection indicators")
    n = ind.clear(tid, who=_actor(request, tid))
    _audit(request, tid, "agent_detection.indicators.clear", removed=n)
    return {"removed": n, "paused": True}


@router.post("/v1/agent-detection/indicators/resume")
def indicator_resume(request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "resume agent detection indicators")
    st = ind.resume(tid, who=_actor(request, tid))
    _audit(request, tid, "agent_detection.indicators.resume")
    return {"settings": st}


@router.post("/v1/agent-detection/indicators/{indicator_id}/revoke")
def indicator_revoke(indicator_id: str, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "revoke an agent detection indicator")
    if not ind.revoke(tid, indicator_id, who=_actor(request, tid)):
        raise HTTPException(status_code=404, detail="no such indicator")
    _audit(request, tid, "agent_detection.indicator.revoke", indicator=indicator_id)
    return {"revoked": indicator_id, "held_for_s": ind.REVOKE_HOLD_S}


class EnforcementIn(BaseModel):
    modes: Optional[dict] = None
    action: Optional[str] = None
    lifetime_s: Optional[int] = None


@router.get("/v1/agent-detection/enforcement")
def get_enforcement(request: Request):
    _on()
    return ind.settings(_tenant(request))


@router.put("/v1/agent-detection/enforcement")
def put_enforcement(body: EnforcementIn, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "change agent detection enforcement")
    change = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        st = ind.save_settings(tid, change)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    ind.log_event(tid, "settings", by=_actor(request, tid), **change)
    _audit(request, tid, "agent_detection.enforcement.change", **change)
    return st


@router.get("/v1/agent-detection/enforcement/log")
def enforcement_log(request: Request, limit: int = 100):
    _on()
    return {"events": ind.read_log(_tenant(request), max(1, min(limit, 1000)))}


class FeedTokenIn(BaseModel):
    label: Optional[str] = ""


@router.get("/v1/agent-detection/feed-tokens")
def list_feed_tokens(request: Request):
    _on()
    return {"feed_tokens": ind.list_tokens(_tenant(request)), "max": ind.MAX_FEED_TOKENS}


@router.post("/v1/agent-detection/feed-tokens", status_code=201)
def create_feed_token(body: FeedTokenIn, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "create an agent detection feed token")
    try:
        rec, token = ind.mint_token(tid, body.label or "")
    except OverflowError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    _audit(request, tid, "agent_detection.feed_token.create", token_id=rec["id"])
    return {**rec, "token": token, "note": "Shown once. The edge sends it as X-Shield-Feed-Token."}


@router.delete("/v1/agent-detection/feed-tokens/{token_id}")
def delete_feed_token(token_id: str, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "delete an agent detection feed token")
    if not ind.delete_token(tid, token_id):
        raise HTTPException(status_code=404, detail="no such feed token")
    _audit(request, tid, "agent_detection.feed_token.delete", token_id=token_id)
    return {"deleted": token_id}
