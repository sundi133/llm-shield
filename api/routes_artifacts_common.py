"""Shared helpers and router factory for the artifact registry endpoints.

One factory produces a router per artifact kind so the URL surface and the
behavior stay identical across models / skills / software / mcp (extended).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core import feature_flags
from core.artifacts import Artifact, ArtifactKind, ArtifactStatus, Provenance
from core.artifact_policy import evaluate_for_approval
from core.provenance import annotate_provenance
from storage.admin_audit import log_admin_action
from storage.artifact_store import get_store

logger = logging.getLogger("votal.artifact_registry")


# ---------------- Request bodies ----------------


class ProvenanceBody(BaseModel):
    issuer: Optional[str] = None
    build_id: Optional[str] = None
    source_repo: Optional[str] = None
    source_commit: Optional[str] = None
    sbom_uri: Optional[str] = None
    signature: Optional[str] = None
    license: Optional[str] = None


class RegisterBody(BaseModel):
    tenant_id: str
    name: str
    version: str
    source_uri: str
    sha256: Optional[str] = None
    provenance: ProvenanceBody = Field(default_factory=ProvenanceBody)
    scopes: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class TenantOnlyBody(BaseModel):
    tenant_id: str
    reason: Optional[str] = None


class PinBody(BaseModel):
    tenant_id: str
    version: Optional[str] = None  # None = clear pin


# ---------------- Helpers ----------------


def _actor_from_request(request: Request) -> str:
    key = (
        request.headers.get("X-Admin-Key")
        or request.headers.get("X-API-Key")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    if not key:
        return "unknown"
    return f"user:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _fire_webhook(tenant_id: str, event_type: str, payload: dict) -> None:
    if not feature_flags.WEBHOOKS_ENABLED:
        return
    try:
        from core.webhook_dispatcher import dispatch_event
        asyncio.create_task(dispatch_event(
            tenant_id=tenant_id,
            event_type=event_type,
            payload=payload,
        ))
    except Exception as e:  # webhook failures must never break the request
        logger.warning("artifact webhook dispatch failed: %s", e)


def _to_artifact(kind: ArtifactKind, body: RegisterBody, actor: str) -> Artifact:
    artifact = Artifact(
        kind=kind,
        name=body.name,
        version=body.version,
        tenant_id=body.tenant_id,
        source_uri=body.source_uri,
        sha256=body.sha256,
        provenance=Provenance(**body.provenance.model_dump()),
        scopes=list(body.scopes),
        owners=list(body.owners),
        metadata=dict(body.metadata),
        created_by=actor,
        created_at=datetime.utcnow(),
    )
    return annotate_provenance(artifact)


def _require_registry_enabled():
    if not feature_flags.ARTIFACT_REGISTRY_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="artifact registry is disabled; set SHIELD_ENABLE_ARTIFACT_REGISTRY=true",
        )


def _get_or_404(tenant_id: str, kind: ArtifactKind, name: str, version: str) -> Artifact:
    art = get_store().get(tenant_id, kind, name, version)
    if art is None:
        raise HTTPException(status_code=404, detail=f"{kind.value} {name}@{version} not found")
    return art


# ---------------- Router factory ----------------


def build_registry_router(kind: ArtifactKind, *, prefix: str, tag: str) -> APIRouter:
    """Return a router exposing the standard lifecycle endpoints for `kind`."""

    router = APIRouter(prefix=prefix, tags=[tag])

    @router.post("/register")
    async def register(body: RegisterBody, request: Request):
        _require_registry_enabled()
        actor = _actor_from_request(request)
        artifact = _to_artifact(kind, body, actor)
        get_store().put(artifact)

        log_admin_action(
            action=f"{kind.value}_registered",
            actor=actor,
            tenant_id=body.tenant_id,
            source_ip=_source_ip(request),
            after={"name": body.name, "version": body.version, "source_uri": body.source_uri},
        )
        _fire_webhook(body.tenant_id, f"{kind.value}.registered", {
            "name": body.name, "version": body.version, "actor": actor,
        })
        return {"status": "registered", "artifact": artifact.model_dump(mode="json")}

    @router.get("")
    async def list_artifacts(tenant_id: str, name: Optional[str] = None):
        _require_registry_enabled()
        items = get_store().list(tenant_id, kind=kind, name=name)
        return {
            "items": [a.model_dump(mode="json") for a in items],
            "count": len(items),
        }

    @router.get("/{name}/{version}")
    async def get_artifact(name: str, version: str, tenant_id: str):
        _require_registry_enabled()
        artifact = _get_or_404(tenant_id, kind, name, version)
        return artifact.model_dump(mode="json")

    @router.post("/{name}/{version}/approve")
    async def approve(name: str, version: str, body: TenantOnlyBody, request: Request):
        _require_registry_enabled()
        actor = _actor_from_request(request)
        artifact = _get_or_404(body.tenant_id, kind, name, version)
        decision = evaluate_for_approval(artifact)
        if not decision.allowed:
            raise HTTPException(status_code=409, detail={
                "error": "approval_policy_failed",
                "reasons": decision.reasons,
            })
        artifact.status = ArtifactStatus.APPROVED
        get_store().put(artifact)
        log_admin_action(
            action=f"{kind.value}_approved", actor=actor, tenant_id=body.tenant_id,
            source_ip=_source_ip(request),
            after={"name": name, "version": version},
        )
        _fire_webhook(body.tenant_id, f"{kind.value}.approved", {
            "name": name, "version": version, "actor": actor,
        })
        return {"status": "approved", "artifact": artifact.model_dump(mode="json")}

    @router.post("/{name}/{version}/deprecate")
    async def deprecate(name: str, version: str, body: TenantOnlyBody, request: Request):
        _require_registry_enabled()
        actor = _actor_from_request(request)
        artifact = _get_or_404(body.tenant_id, kind, name, version)
        artifact.status = ArtifactStatus.DEPRECATED
        get_store().put(artifact)
        log_admin_action(
            action=f"{kind.value}_deprecated", actor=actor, tenant_id=body.tenant_id,
            source_ip=_source_ip(request),
            after={"name": name, "version": version, "reason": body.reason},
        )
        _fire_webhook(body.tenant_id, f"{kind.value}.deprecated", {
            "name": name, "version": version, "reason": body.reason, "actor": actor,
        })
        return {"status": "deprecated", "artifact": artifact.model_dump(mode="json")}

    @router.post("/{name}/{version}/revoke")
    async def revoke(name: str, version: str, body: TenantOnlyBody, request: Request):
        _require_registry_enabled()
        actor = _actor_from_request(request)
        artifact = _get_or_404(body.tenant_id, kind, name, version)
        artifact.status = ArtifactStatus.REVOKED
        get_store().put(artifact)

        # For MCP artifacts also flip the tool killswitch so the existing
        # runtime gate picks it up even when artifact enforcement is off.
        if kind == ArtifactKind.MCP:
            try:
                from storage.tool_killswitch import disable_tool
                disable_tool(body.tenant_id, name, reason=body.reason or "artifact revoked", actor=actor)
            except Exception as e:
                logger.warning("mcp revoke: killswitch propagation failed: %s", e)

        log_admin_action(
            action=f"{kind.value}_revoked", actor=actor, tenant_id=body.tenant_id,
            source_ip=_source_ip(request),
            after={"name": name, "version": version, "reason": body.reason},
        )
        _fire_webhook(body.tenant_id, f"{kind.value}.revoked", {
            "name": name, "version": version, "reason": body.reason, "actor": actor,
        })
        return {"status": "revoked", "artifact": artifact.model_dump(mode="json")}

    @router.post("/{name}/pin")
    async def pin(name: str, body: PinBody, request: Request):
        _require_registry_enabled()
        actor = _actor_from_request(request)

        if body.version is not None:
            # Must exist and be approved to pin.
            artifact = _get_or_404(body.tenant_id, kind, name, body.version)
            if artifact.status != ArtifactStatus.APPROVED:
                raise HTTPException(
                    status_code=409,
                    detail=f"cannot pin to non-approved version (status={artifact.status.value})",
                )

        get_store().set_pin(body.tenant_id, kind, name, body.version)
        log_admin_action(
            action=f"{kind.value}_pinned", actor=actor, tenant_id=body.tenant_id,
            source_ip=_source_ip(request),
            after={"name": name, "version": body.version},
        )
        _fire_webhook(body.tenant_id, f"{kind.value}.pinned", {
            "name": name, "version": body.version, "actor": actor,
        })
        return {"status": "ok", "name": name, "pinned_version": body.version}

    @router.get("/{name}/pin")
    async def get_pin(name: str, tenant_id: str):
        _require_registry_enabled()
        version = get_store().get_pin(tenant_id, kind, name)
        return {"name": name, "pinned_version": version}

    return router
