"""AIBOM API — per-tenant AI Bill of Materials (docs/spec-aibom.md).

    GET    /v1/tenant/me/aibom?view=full|observed|declared
    GET    /v1/tenant/me/aibom/components
    PUT    /v1/tenant/me/aibom/components/{section}
    DELETE /v1/tenant/me/aibom/components/{section}/{component_id}
    POST   /v1/tenant/me/aibom/snapshots
    GET    /v1/tenant/me/aibom/snapshots[/{snapshot_id}]
    GET    /v1/tenant/me/aibom/drift[?snapshot_id=]

Generation is a read-only aggregation on the admin plane over data already
written by the registry/auth/guard paths; nothing here touches the guard
path. Declares hold references only — values that look like credentials
(sk-/AKIA/PEM/ghp_/xox?-) are rejected so secret material can never land
in a BOM.
"""

import asyncio
import json
import re
import time

from fastapi import APIRouter, HTTPException, Request

from api.routes_agents_registry import get_tenant_from_api_key
from storage.admin_audit import log_admin_action
from storage.aibom import (
    DECLARABLE_SECTIONS,
    VIEWS,
    compute_drift,
    create_snapshot,
    generate_aibom,
    get_snapshot,
    list_snapshots,
    load_declared,
    save_declared,
)

router = APIRouter(prefix="/v1/tenant/me/aibom", tags=["aibom"])

# Hardening limits (spec §5): per-section id count and serialized size.
MAX_COMPONENTS_PER_SECTION = 200
MAX_SECTION_BYTES = 64 * 1024

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CREDENTIAL_RES = (
    re.compile(r"^sk-[A-Za-z0-9]"),          # OpenAI/Anthropic-style keys
    re.compile(r"^AKIA[0-9A-Z]{12,}"),        # AWS access key ids
    re.compile(r"-----BEGIN [A-Z ]*KEY"),     # PEM private keys
    re.compile(r"^gh[pousr]_[A-Za-z0-9]"),    # GitHub tokens
    re.compile(r"^xox[abps]-"),               # Slack tokens
)


def _find_credential_shaped(value, path: str = "") -> str | None:
    """Return the path of the first credential-shaped string value, if any."""
    if isinstance(value, str):
        for rx in _CREDENTIAL_RES:
            if rx.search(value):
                return path or "(value)"
    elif isinstance(value, dict):
        for k, v in value.items():
            hit = _find_credential_shaped(v, f"{path}.{k}" if path else str(k))
            if hit:
                return hit
    elif isinstance(value, list):
        for i, v in enumerate(value):
            hit = _find_credential_shaped(v, f"{path}[{i}]")
            if hit:
                return hit
    return None


def _validate_section(section: str) -> None:
    if section not in DECLARABLE_SECTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"unknown section '{section}' — must be one of: {', '.join(DECLARABLE_SECTIONS)}")


def _validate_components(section: str, components: dict) -> None:
    """Shared request validation for declare payloads (raises 422)."""
    if not isinstance(components, dict) or not components:
        raise HTTPException(status_code=422, detail='body must be {"components": {id: {...} | null}}')
    for cid, comp in components.items():
        if not _ID_RE.match(cid):
            raise HTTPException(
                status_code=422,
                detail=f"invalid component id '{cid[:64]}' (allowed: [A-Za-z0-9._-], max 128 chars)")
        if comp is not None and section != "metadata" and not isinstance(comp, dict):
            raise HTTPException(status_code=422, detail=f"component '{cid}' must be an object or null")
        hit = _find_credential_shaped(comp, cid)
        if hit:
            raise HTTPException(
                status_code=422,
                detail=f"value at '{hit}' looks like a credential — declare secret *names*, never values")


def _merge_components(section: str, stored: dict, components: dict) -> tuple[dict, int]:
    """Merge-by-id (null deletes) and enforce post-merge caps. Returns
    (merged, deleted_count); raises 422 on cap violations."""
    deleted = 0
    for cid, comp in components.items():
        if comp is None:
            deleted += 1 if stored.pop(cid, None) is not None else 0
        else:
            stored[cid] = comp
    if len(stored) > MAX_COMPONENTS_PER_SECTION:
        raise HTTPException(
            status_code=422,
            detail=f"section '{section}' would hold {len(stored)} entries (max {MAX_COMPONENTS_PER_SECTION})")
    size = len(json.dumps(stored))
    if size > MAX_SECTION_BYTES:
        raise HTTPException(
            status_code=422,
            detail=f"section '{section}' would be {size} bytes serialized (max {MAX_SECTION_BYTES})")
    return stored, deleted


_FORMATS = ("aibom", "cyclonedx")
MAX_INGEST_BYTES = 1024 * 1024


@router.get("")
async def get_aibom(request: Request, view: str = "full", format: str = "aibom"):
    """Generate the tenant's current AIBOM document.

    format=cyclonedx returns the same inventory as a CycloneDX 1.6 ML-BOM
    for standard supply-chain tooling.
    """
    tenant_id = get_tenant_from_api_key(request)
    if view not in VIEWS:
        raise HTTPException(status_code=422, detail=f"view must be one of: {', '.join(VIEWS)}")
    if format not in _FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of: {', '.join(_FORMATS)}")
    doc = generate_aibom(tenant_id, view=view)
    if format == "cyclonedx":
        from storage.aibom_interop import to_cyclonedx
        return to_cyclonedx(doc)
    return doc


@router.post("/ingest")
async def ingest_bom(request: Request):
    """Ingest an external CycloneDX BOM (e.g. a k8s-aibom webhook sink)
    into the declared sections.

    Components map by type (machine-learning-model -> models, data ->
    knowledge_sources, everything else -> supply_chain), tagged with
    source: cyclonedx-ingest. This is the bulk/automated path, so
    credential-shaped values skip that component (counted in the response)
    instead of rejecting the whole document; post-merge section caps still
    reject with 422 — no silent truncation.
    """
    tenant_id = get_tenant_from_api_key(request)
    raw = await request.body()
    if len(raw) > MAX_INGEST_BYTES:
        raise HTTPException(
            status_code=422, detail=f"document is {len(raw)} bytes (max {MAX_INGEST_BYTES})")
    try:
        doc = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=422, detail="body must be JSON")

    from storage.aibom_interop import from_cyclonedx
    try:
        mapped, notes = from_cyclonedx(doc)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    skipped_credential = 0
    for section, components in mapped.items():
        safe = {}
        for cid, comp in components.items():
            if _find_credential_shaped(comp, cid):
                skipped_credential += 1
                continue
            safe[cid] = comp
        mapped[section] = safe
    if skipped_credential:
        notes.append(f"{skipped_credential} components skipped (credential-shaped values)")

    declared = load_declared(tenant_id)
    counts = {}
    for section, components in mapped.items():
        if not components:
            continue
        stored, _ = _merge_components(section, declared.get(section) or {}, components)
        declared[section] = stored
        counts[section] = len(components)
    if counts:
        declared["updated_at"] = int(time.time())
        save_declared(tenant_id, declared)

    log_admin_action(
        action="aibom_ingest_bom",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"ingested": counts, "notes": notes},
    )
    return {"tenant_id": tenant_id, "ingested": counts, "notes": notes}


@router.get("/components")
async def get_components(request: Request):
    """The tenant's declared components (models, prompts, ... , metadata)."""
    tenant_id = get_tenant_from_api_key(request)
    declared = load_declared(tenant_id)
    return {
        "tenant_id": tenant_id,
        "declared": {s: declared.get(s) or {} for s in DECLARABLE_SECTIONS},
        "updated_at": declared.get("updated_at"),
    }


@router.put("/components")
async def put_manifest(request: Request):
    """Upsert the whole declared doc in one call (the CI `aibom.json` flow).

    Body: {"components": {section: {id: {...} | null}}} — each section merges
    by id exactly like the per-section route; sections not mentioned are left
    untouched. All-or-nothing: any invalid section/id/value rejects the whole
    request before anything is written.
    """
    tenant_id = get_tenant_from_api_key(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="body must be JSON")
    manifest = (body or {}).get("components")
    if not isinstance(manifest, dict) or not manifest:
        raise HTTPException(
            status_code=422, detail='body must be {"components": {section: {id: {...} | null}}}')

    for section, components in manifest.items():
        _validate_section(section)
        _validate_components(section, components)

    declared = load_declared(tenant_id)
    counts = {}
    for section, components in manifest.items():
        stored, _ = _merge_components(section, declared.get(section) or {}, components)
        declared[section] = stored
        counts[section] = len(stored)
    declared["updated_at"] = int(time.time())
    save_declared(tenant_id, declared)

    log_admin_action(
        action="aibom_declare_manifest",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"sections": sorted(manifest.keys()), "counts": counts},
    )
    return {"tenant_id": tenant_id, "sections": counts, "updated_at": declared["updated_at"]}


@router.put("/components/{section}")
async def put_components(section: str, request: Request):
    """Upsert declared entries for one section.

    Body: {"components": {id: {...} | null}} — merge-by-id; null deletes an
    id. For the flat "metadata" section, ids are field names and values may
    be any JSON scalar/object.
    """
    tenant_id = get_tenant_from_api_key(request)
    _validate_section(section)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="body must be JSON")
    components = (body or {}).get("components")
    _validate_components(section, components)

    declared = load_declared(tenant_id)
    stored, deleted = _merge_components(section, declared.get(section) or {}, components)
    declared[section] = stored
    declared["updated_at"] = int(time.time())
    save_declared(tenant_id, declared)

    log_admin_action(
        action="aibom_declare_components",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"section": section, "upserted": len(components) - deleted,
                  "deleted": deleted, "total": len(stored)},
    )
    return {"tenant_id": tenant_id, "section": section, "components": stored,
            "count": len(stored), "updated_at": declared["updated_at"]}


@router.delete("/components/{section}/{component_id}")
async def delete_component(section: str, component_id: str, request: Request):
    """Remove one declared entry."""
    tenant_id = get_tenant_from_api_key(request)
    _validate_section(section)
    declared = load_declared(tenant_id)
    stored = declared.get(section) or {}
    if component_id not in stored:
        raise HTTPException(status_code=404, detail=f"'{component_id}' not declared in '{section}'")
    stored.pop(component_id)
    declared[section] = stored
    declared["updated_at"] = int(time.time())
    save_declared(tenant_id, declared)

    log_admin_action(
        action="aibom_delete_component",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"section": section, "component_id": component_id},
    )
    return {"deleted": True, "section": section, "component_id": component_id}


@router.post("/snapshots")
async def post_snapshot(request: Request):
    """Approve the current full BOM as the design-time baseline for drift."""
    tenant_id = get_tenant_from_api_key(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    approved_by = ((body or {}).get("approved_by") or "tenant").strip()[:128]
    note = ((body or {}).get("note") or "").strip()[:500]
    try:
        entry = create_snapshot(tenant_id, approved_by=approved_by, note=note)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    log_admin_action(
        action="aibom_snapshot_created",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"snapshot_id": entry["snapshot_id"]},
    )
    return entry


@router.get("/snapshots")
async def get_snapshots(request: Request):
    tenant_id = get_tenant_from_api_key(request)
    return {"tenant_id": tenant_id, "snapshots": list_snapshots(tenant_id)}


@router.get("/snapshots/{snapshot_id}")
async def get_one_snapshot(snapshot_id: str, request: Request):
    tenant_id = get_tenant_from_api_key(request)
    snapshot = get_snapshot(tenant_id, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"snapshot '{snapshot_id}' not found")
    return snapshot


@router.get("/drift")
async def get_drift(request: Request, snapshot_id: str = None):
    """Diff the current BOM against the approved snapshot (spec §18).

    Fires an aibom_drift_detected webhook (summary only, never the full
    BOM) for subscribed tenants when drift is present; webhook failures
    never fail this request.
    """
    tenant_id = get_tenant_from_api_key(request)
    report = compute_drift(tenant_id, snapshot_id=snapshot_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="no approved snapshot — POST /v1/tenant/me/aibom/snapshots first"
            if snapshot_id is None else f"snapshot '{snapshot_id}' not found")

    if not report["clean"]:
        try:
            from core.webhook_dispatcher import dispatch_event
            summary = {
                "snapshot_id": report["snapshot_id"],
                "drift_count": report["drift_count"],
                "sections": sorted(
                    s for s, d in report["drift"].items()
                    if d["added"] or d["removed"] or d["changed"]),
            }
            asyncio.create_task(dispatch_event(tenant_id, "aibom_drift_detected", summary))
        except Exception:
            pass
    return report
