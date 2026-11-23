"""AI agent detection, admin plane (docs/specs/agent-impersonation-defense.md
section 9). Mounted by admin_app.py; nothing here is on the guard path.

Site keys for the tag (rev 8 step R1):

  GET    /v1/agent-detection/sitekeys              the tenant's site keys
  POST   /v1/agent-detection/sitekeys              create one
  DELETE /v1/agent-detection/sitekeys/{site_key}   delete one

Portal reads (R7, spec section 9):

  GET    /v1/agent-detection/detections?band=     flagged sessions with reasons (clear_agent, grey, all)
  GET    /v1/agent-detection/sessions/{shs}       one session's summary and verdict
  GET    /v1/agent-detection/fleets               fleets seen in the last 24 h
  GET    /v1/agent-detection/stats?days=          daily counters
  GET    /v1/agent-detection/tag                  install snippets per site key, and whether beacons arrive

Decoys (rev 9 R9, spec 2.6 and 14):

  GET|PUT /v1/agent-detection/decoys               settings and this tenant's decoy paths
  POST   /v1/agent-detection/decoys/reroll         draw a new set
  GET    /v1/agent-detection/decoys/edge?site_key=&format=nginx|json   the edge rules

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
import os
import re
import time

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
    decoys: bool = False
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
                              consent=body.consent, xff_hops=body.xff_hops, traps=body.traps, decoys=body.decoys,
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
    # as one field: the change may carry "action", which is _audit's own parameter
    _audit(request, tid, "agent_detection.enforcement.change", change=change)
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


# ── portal reads (R7) ────────────────────────────────────────────────

_BANDS = {"clear_agent": ("clear_agent",), "grey": ("grey",), "flagged": ("clear_agent", "grey"),
          "all": ("clear_agent", "grey", "human_like")}


def _store():
    from core.agent_detection import worker
    return worker.store_for_env()


def _summary(s: dict) -> dict:
    from core.agent_detection import scoring
    v = s.get("verdict") or {}
    dev = s.get("device") or {}
    return {"shs": s["shs"], "first": s.get("first"), "last": s.get("last"), "beacons": s.get("n"),
            "score": v.get("score"), "band": v.get("band"), "reasons": v.get("reasons", []),
            "signals": v.get("signals", {}), "pages": (s.get("pages") or [])[:10],
            "renderer": str(dev.get("renderer", ""))[:80], "renderer_class": dev.get("renderer_class"),
            "device": scoring.device_of(s), "clients": len(s.get("clients") or []),
            "networks": len(s.get("nets") or []), "traps": s.get("traps", {}),
            "links": (s.get("links") or [])[:20], "pack": v.get("pack"),
            "decoys": (s.get("decoys") or [])[:20], "pseudo": bool(s.get("pseudo"))}


@router.get("/v1/agent-detection/detections")
def list_detections(request: Request, band: str = "flagged", limit: int = 100):
    _on()
    tid = _tenant(request)
    if band not in _BANDS:
        raise HTTPException(status_code=400, detail=f"band must be one of {', '.join(_BANDS)}")
    limit = max(1, min(limit, 500))
    store = _store()
    ids = store.recent_ids(tid, 2000)
    out = []
    for i in range(0, len(ids), 500):
        got = store.get_sessions(tid, ids[i:i + 500])
        for shs in ids[i:i + 500]:
            s = got.get(shs)
            if s and (s.get("verdict") or {}).get("band") in _BANDS[band]:
                out.append(_summary(s))
        if len(out) >= limit:
            break
    fleet_of = {m: f["id"] for f in store.list_fleets(tid) for m in f.get("members", [])}
    for d in out[:limit]:
        d["fleet_id"] = fleet_of.get(d["shs"])
    return {"detections": out[:limit], "scanned": len(ids)}


@router.get("/v1/agent-detection/sessions/{shs}")
def get_session(shs: str, request: Request):
    _on()
    tid = _tenant(request)
    if not re.fullmatch(r"[0-9a-f]{24}", shs):
        raise HTTPException(status_code=404, detail="no such session")
    s = _store().get_sessions(tid, [shs]).get(shs)
    if not s:
        raise HTTPException(status_code=404, detail="no such session")
    from core.agent_detection import scoring
    return {**_summary(s), "interaction": scoring.interaction(s), "automation": s.get("automation", {})}


@router.get("/v1/agent-detection/fleets")
def list_fleets(request: Request):
    _on()
    tid = _tenant(request)
    fleets = _store().list_fleets(tid)
    for f in fleets:
        f["member_count"] = len(f.get("members", []))
        f["members"] = f.get("members", [])[:50]
    return {"fleets": fleets}


@router.get("/v1/agent-detection/stats")
def get_stats(request: Request, days: int = 7):
    _on()
    tid = _tenant(request)
    days = max(1, min(days, 35))
    now = time.time()
    keys = [time.strftime("%Y%m%d", time.gmtime(now - n * 86400)) for n in range(days)]
    store = _store()
    daily = store.daily_stats(tid, keys)
    return {"days": [{"day": d, **daily.get(d, {})} for d in keys],
            "fleets_active": len(store.list_fleets(tid)),
            "indicators_active": len(ind.active(tid)), "enforcement": ind.settings(tid)}


def _tag_urls() -> tuple[str, str]:
    """Where released tags live and where the collector answers, for the snippet."""
    collector = (os.environ.get("SHIELD_AGENT_DETECTION_COLLECTOR_URL", "") or "").strip().rstrip("/")
    tag_base = (os.environ.get("SHIELD_AGENT_DETECTION_TAG_URL", "") or "").strip().rstrip("/") or collector
    return tag_base, collector


@router.get("/v1/agent-detection/tag")
def tag_install(request: Request):
    """The install snippets, and whether each site key's beacons are arriving
    (from the newest 500 stream entries, so a quiet site shows no data)."""
    _on()
    tid = _tenant(request)
    from core.agent_detection import tag as tag_mod
    tag_base, collector = _tag_urls()
    seen: dict[str, dict] = {}
    try:
        for e in _store().last_entries(tid, 500):
            k = e.get("site_key")
            if not k:
                continue
            row = seen.setdefault(k, {"last_beacon": 0.0, "kinds": {}, "traps_shown": False})
            row["last_beacon"] = max(row["last_beacon"], float((e.get("req") or {}).get("ts") or 0))
            row["kinds"][e.get("kind")] = row["kinds"].get(e.get("kind"), 0) + 1
            row["traps_shown"] = row["traps_shown"] or bool((e.get("traps") or {}).get("shown"))
    except Exception:       # noqa: BLE001 - the install check is advice, never an error page
        pass
    keys = []
    for rec in sitekeys.list_for(tid):
        k, consent = rec["site_key"], rec.get("consent", "none")
        base = tag_base or "https://YOUR-TAG-HOST"
        keys.append({**rec, "reporting": seen.get(k),
                     "snippet_first_party": tag_mod.snippet(k, base, "", consent),
                     "snippet_direct": tag_mod.snippet(k, base, collector or "https://YOUR-COLLECTOR", consent)})
    return {"version": tag_mod.version(), "integrity": tag_mod.sri(), "file": tag_mod.filename(),
            "tag_base": tag_base, "collector": collector,
            "configured": bool(tag_base and collector), "site_keys": keys,
            "first_party_path": "/_shs/"}


# ── decoys (rev 9, R9) ───────────────────────────────────────────────


class DecoysIn(BaseModel):
    enabled: Optional[bool] = None
    key_prefix: Optional[str] = None
    stack: Optional[str] = None
    avoid: Optional[list] = None
    scanners: Optional[dict] = None


def _decoy_view(tid: str) -> dict:
    from core.agent_detection import decoys
    st = decoys.settings(tid)
    p = decoys.plan(tid, st)
    return {"enabled": st["enabled"], "key_prefix": st["key_prefix"], "stack": st["stack"],
            "stacks": sorted(decoys.STACKS), "avoid": st["avoid"], "scanners": st["scanners"],
            "updated": st["updated"],
            "decoys": {"D1 admin login": p["admin"], "D2 config files": p["configs"],
                       "D4 internal API": p["api"] + "/" if p["api"] else "",
                       "instruction header": p["header"]},
            "paths": decoys.paths(p), "robots_txt_line": decoys.robots_line(p)}


@router.get("/v1/agent-detection/decoys")
def get_decoys(request: Request):
    _on()
    return _decoy_view(_tenant(request))


@router.put("/v1/agent-detection/decoys")
def put_decoys(body: DecoysIn, request: Request):
    _on()
    from core.agent_detection import decoys
    tid = _tenant(request)
    _write(request, tid, "change agent detection decoys")
    change = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        decoys.save(tid, change)
    except decoys.DecoyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    _audit(request, tid, "agent_detection.decoys.change", change=change)
    return _decoy_view(tid)


@router.post("/v1/agent-detection/decoys/reroll")
def reroll_decoys(request: Request):
    _on()
    from core.agent_detection import decoys
    tid = _tenant(request)
    _write(request, tid, "draw new agent detection decoys")
    decoys.reroll(tid)
    _audit(request, tid, "agent_detection.decoys.reroll")
    return _decoy_view(tid)


@router.get("/v1/agent-detection/decoys/edge")
def decoy_edge_rules(request: Request, site_key: str, format: str = "nginx"):
    _on()
    from core.agent_detection import decoys
    tid = _tenant(request)
    rec = sitekeys.get(site_key)
    if not rec or rec.get("tenant") != tid:
        raise HTTPException(status_code=404, detail="no such site key")
    _, collector = _tag_urls()
    p = decoys.plan(tid)
    if format == "nginx":
        return Response(decoys.edge_nginx(p, site_key, collector), media_type="text/plain; charset=utf-8",
                        headers={"Cache-Control": "no-store"})
    if format == "json":            # the portal reads JSON only, so the Nginx text rides along
        return {**decoys.edge_json(p, site_key, collector), "nginx": decoys.edge_nginx(p, site_key, collector)}
    raise HTTPException(status_code=400, detail="format must be nginx or json")
