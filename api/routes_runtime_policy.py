"""Runtime profiles (infrastructure guardrails): tenant API and runtime bundle.

Spec: docs/specs/infra-guardrails.md §6. Off the hot path: nothing here runs
on /guardrails/*, cap/mint or tools/call. Mounted on both planes, like the
other /v1/tenant/me/* routers.

  /v1/tenant/me/runtime-profiles/...   manage, validate, template, export
  /v1/edge/runtime-bundle              what a sandbox or sidecar pulls (ETag,
                                       signed), plus the JWKS to verify it

The tenant always comes from the authenticated key. Writes go through the
registry write gate (SHIELD_REGISTRY_WRITE_SCOPE), like cross-app flow
control, because a profile loosened by an agent's own runtime key is a
sandbox that let itself out.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from core.auth import get_tenant_from_request, require_registry_write
from core.runtime_policy import bundle as rt_bundle
from core.runtime_policy import check as runtime_check
from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers import TARGETS, ExportContext, compile_profile
from core.runtime_policy.compilers.openshell import live_change
from core.runtime_policy.model import ProfileError, profile_hash, templates, valid_name, \
    validate_profile
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant/me/runtime-profiles", tags=["runtime-profiles"])
edge_router = APIRouter(prefix="/v1/edge", tags=["edge"])


def _audit(request: Request, action: str, tenant_id: str, metadata: dict) -> None:
    try:
        log_admin_action(action=action, actor=f"tenant:{tenant_id}", tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "",
                         metadata=metadata)
    except Exception:
        pass


def _name(name: str) -> str:
    if not valid_name(name):
        raise HTTPException(status_code=400, detail="profile name: lowercase letters, digits, "
                                                    ". _ - (1-64 characters)")
    return name


def _invalid(e: ProfileError) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": "invalid runtime profile",
                                                  "errors": e.errors})


def _bound_agents(tenant_id: str) -> dict[str, list[str]]:
    """profile name -> agent ids bound to it in the registry."""
    out: dict[str, list[str]] = {}
    try:
        from storage.tenant_store import kv_get
        for agent_id, agent in (kv_get(f"agents:{tenant_id}") or {}).items():
            name = (agent or {}).get("runtime_profile")
            if name:
                out.setdefault(name, []).append(agent_id)
    except Exception:
        pass
    return out


def _shield_endpoint(request: Request, shield_url: Optional[str]) -> tuple[str, int]:
    """Host and port the sandbox must be able to reach: ?shield_url, else
    SHIELD_PUBLIC_URL, else the URL this request came in on."""
    import os
    url = shield_url or os.environ.get("SHIELD_PUBLIC_URL", "").strip() or str(request.base_url)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="shield_url must be an http(s) URL")
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _load(tenant_id: str, name: str) -> dict:
    try:
        profile = rt_store.get_profile(tenant_id, name)
    except ProfileError as e:
        raise HTTPException(status_code=409, detail={
            "message": f"stored profile '{name}' no longer validates; save it again",
            "errors": e.errors})
    if profile is None:
        raise HTTPException(status_code=404, detail=f"runtime profile '{name}' not found")
    return profile


_NS = __import__("re").compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")


def _options(request: Request) -> dict:
    """Validated target options from the query string."""
    import ipaddress
    q = request.query_params
    opts: dict = {}
    if q.get("namespace"):
        if not _NS.match(q["namespace"]):
            raise HTTPException(status_code=400, detail="namespace: a DNS-1123 label")
        opts["namespace"] = q["namespace"]
    cidrs = q.getlist("egress_cidr")
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"egress_cidr: not a CIDR: {c[:60]!r}")
    if cidrs:
        opts["egress_cidrs"] = cidrs[:50]
    sources = q.getlist("source_cidr")
    for c in sources:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"source_cidr: not a CIDR: {c[:60]!r}")
    if sources:
        opts["source_cidrs"] = [str(ipaddress.ip_network(c, strict=False)) for c in sources[:50]]
    if q.get("run_as_uid"):
        try:
            uid = int(q["run_as_uid"])
        except ValueError:
            uid = -1
        if not 1 <= uid <= 2**31 - 1:
            raise HTTPException(status_code=400, detail="run_as_uid: a non-root numeric UID")
        opts["run_as_uid"] = uid
    for k in ("container", "image"):
        if q.get(k):
            if len(q[k]) > 255 or any(ch.isspace() for ch in q[k]):
                raise HTTPException(status_code=400, detail=f"{k}: invalid")
            opts[k] = q[k]
    return opts


def _compile(request: Request, tenant_id: str, name: str, target: str,
             shield_url: Optional[str]) -> tuple[dict, str, object]:
    if target not in TARGETS:
        raise HTTPException(status_code=400,
                            detail=f"target must be one of: {', '.join(TARGETS)}")
    profile = _load(tenant_id, name)
    phash = profile_hash(profile)
    host, port = _shield_endpoint(request, shield_url)
    try:
        compiled = compile_profile(target, profile, ExportContext(
            profile_name=name, profile_hash=phash, shield_host=host, shield_port=port,
            options=_options(request)))
    except ValueError as e:     # a target's required option is missing
        raise HTTPException(status_code=400, detail=str(e))
    return profile, phash, compiled


# ── tenant API ───────────────────────────────────────────────────────


@router.get("")
async def list_runtime_profiles(request: Request):
    tenant_id = get_tenant_from_request(request)
    bound = _bound_agents(tenant_id)
    profiles = {}
    for name, rec in rt_store.list_profiles(tenant_id).items():
        if "error" in rec:
            profiles[name] = {"error": rec["error"], "agents": bound.get(name, [])}
            continue
        profiles[name] = {"hash": rec["hash"], "description": rec["profile"]["description"],
                          "updated_at": rec.get("updated_at"), "agents": bound.get(name, [])}
    return {"tenant_id": tenant_id, "profiles": profiles, "targets": list(TARGETS)}


@router.get("/templates")
async def runtime_profile_templates(request: Request):
    get_tenant_from_request(request)
    return {"templates": templates()}


@router.post("/validate")
async def validate_runtime_profile(request: Request, profile: dict = Body(...)):
    get_tenant_from_request(request)
    try:
        normalized = validate_profile(profile)
    except ProfileError as e:
        return {"valid": False, "errors": e.errors, "profile": None}
    return {"valid": True, "errors": [], "profile": normalized, "hash": profile_hash(normalized)}


@router.get("/{name}")
async def get_runtime_profile(name: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    profile = _load(tenant_id, _name(name))
    return {"tenant_id": tenant_id, "name": name, "profile": profile,
            "hash": profile_hash(profile), "agents": _bound_agents(tenant_id).get(name, [])}


def _actor(request: Request, tenant_id: str) -> str:
    """Who made a change, for profile history: the signed-in user, else the key."""
    try:
        from core.auth import portal_principal
        principal = portal_principal(request)
    except Exception:
        principal = None
    if principal:
        return f"user:{principal.get('email') or principal.get('sub') or '?'}"
    return f"tenant:{tenant_id}"


def _previous(tenant_id: str, name: str) -> Optional[dict]:
    try:
        return rt_store.get_profile(tenant_id, name)
    except ProfileError:
        return None


@router.put("/{name}")
async def put_runtime_profile(name: str, request: Request, profile: dict = Body(...)):
    tenant_id = get_tenant_from_request(request)
    _name(name)
    require_registry_write(request, tenant_id, "change a runtime profile")
    previous = _previous(tenant_id, name)
    try:
        normalized = rt_store.save_profile(tenant_id, name, profile,
                                           actor=_actor(request, tenant_id), reason="put")
    except ProfileError as e:
        raise _invalid(e)
    phash = profile_hash(normalized)
    runtime_check.invalidate(tenant_id)
    _audit(request, "tenant_set_runtime_profile", tenant_id, {"profile": name, "hash": phash})
    return {"tenant_id": tenant_id, "name": name, "profile": normalized, "hash": phash,
            "live_change": live_change(previous, normalized) if previous is not None else None}


@router.get("/{name}/history")
async def runtime_profile_history(name: str, request: Request):
    """Saved versions, newest first. ``live_change`` on each says whether a
    running sandbox could move to it from the version before without a
    restart (null for the oldest one kept)."""
    tenant_id = get_tenant_from_request(request)
    current = profile_hash(_load(tenant_id, _name(name)))
    versions = rt_store.history(tenant_id, name)
    out = []
    for i, v in enumerate(versions):
        older = versions[i + 1]["profile"] if i + 1 < len(versions) else None
        try:
            change = live_change(older, v["profile"]) if older is not None else None
        except Exception:       # an old entry the current compiler cannot read
            change = None
        out.append({**v, "live_change": change})
    return {"tenant_id": tenant_id, "name": name, "current_hash": current, "versions": out}


@router.delete("/{name}")
async def delete_runtime_profile(name: str, request: Request,
                                 force: bool = Query(False)):
    tenant_id = get_tenant_from_request(request)
    _name(name)
    require_registry_write(request, tenant_id, "delete a runtime profile")
    agents = _bound_agents(tenant_id).get(name, [])
    if agents and not force:
        # Deleting a profile agents still reference silently removes their
        # boundary. Make the operator say so.
        raise HTTPException(status_code=409, detail={
            "message": f"runtime profile '{name}' is bound to {len(agents)} agent(s); "
                       f"rebind them or pass force=true",
            "agents": agents})
    deleted = rt_store.delete_profile(tenant_id, name)
    runtime_check.invalidate(tenant_id)
    _audit(request, "tenant_delete_runtime_profile", tenant_id,
           {"profile": name, "deleted": deleted, "bound_agents": agents})
    return {"tenant_id": tenant_id, "name": name, "deleted": deleted}


@router.get("/{name}/drift")
async def runtime_profile_drift(name: str, request: Request):
    """Sandboxes seen attesting a profile hash other than the current one (or
    none at all): the ones still running an old or unknown boundary."""
    from core.runtime_policy.attest import instances, list_drift
    tenant_id = get_tenant_from_request(request)
    profile = _load(tenant_id, _name(name))
    current = profile_hash(profile)
    stale = list_drift(tenant_id, name, current)
    return {"tenant_id": tenant_id, "name": name, "current_hash": current,
            "attestation": profile["identity"]["require_attestation"],
            "stale_count": len(stale), "stale": stale,
            "instances": instances(tenant_id, name, current)}


@router.get("/{name}/export")
async def export_runtime_profile(
    name: str, request: Request,
    target: str = Query("openshell"),
    shield_url: Optional[str] = Query(None, description="Where the sandbox reaches Shield"),
    raw: bool = Query(False, description="Return the artifact itself as a file"),
):
    tenant_id = get_tenant_from_request(request)
    profile, phash, compiled = _compile(request, tenant_id, _name(name), target, shield_url)
    if raw:
        return PlainTextResponse(compiled.artifact, media_type=compiled.content_type, headers={
            "Content-Disposition": f'attachment; filename="{compiled.filename}"',
            "X-Shield-Profile-Hash": phash,
            "X-Shield-Unsupported-Count": str(len(compiled.unsupported)),
        })
    return {"tenant_id": tenant_id, "name": name, "target": target, "profile_hash": phash,
            "filename": compiled.filename, "content_type": compiled.content_type,
            "unsupported": compiled.unsupported, "notes": compiled.notes,
            "artifact": compiled.artifact}


# ── runtime bundle (what sandboxes pull) ─────────────────────────────


@edge_router.get("/runtime-bundle")
async def runtime_bundle(
    request: Request, response: Response,
    profile: str = Query(...),
    target: str = Query("openshell"),
    shield_url: Optional[str] = Query(None),
):
    """The compiled policy for a runtime, signed, with ETag/304 so a sidecar
    can poll cheaply. Verify ``signature`` against /v1/edge/runtime-bundle/jwks
    before applying ``artifact``."""
    tenant_id = get_tenant_from_request(request)
    _, phash, compiled = _compile(request, tenant_id, _name(profile), target, shield_url)
    digest = rt_bundle.artifact_digest(compiled.artifact)
    etag = f'"{digest[7:39]}"'
    if (request.headers.get("if-none-match") or "").strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    try:
        signature = rt_bundle.sign_bundle(tenant_id=tenant_id, profile=profile,
                                          profile_hash=phash, target=target,
                                          artifact=compiled.artifact)
    except rt_bundle.SignerError as e:
        raise HTTPException(status_code=500, detail=f"runtime bundle signing key misconfigured: {e}")
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"
    return {"tenant_id": tenant_id, "profile": profile, "target": target,
            "profile_hash": phash, "artifact_sha256": digest, "filename": compiled.filename,
            "artifact": compiled.artifact, "unsupported": compiled.unsupported,
            "notes": compiled.notes, "signed": signature is not None, "signature": signature}


@edge_router.get("/runtime-bundle/jwks")
async def runtime_bundle_jwks(request: Request):
    """Public keys that sign runtime bundles."""
    get_tenant_from_request(request)
    return rt_bundle.jwks()
