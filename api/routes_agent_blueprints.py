"""Agent identity blueprints — templates that instantiate multiple agents.

A blueprint is a reusable definition of a role: its tool set, RBAC mapping,
and accountable human owner. Customers instantiate a blueprint to mint a
concrete agent in the existing registry (`agents:{tenant_id}`), with the
blueprint id stamped on the instance for lineage.

The registry endpoints in `routes_agents_registry.py` are untouched; this
module adds an orthogonal `agent_blueprints:{tenant_id}` Redis namespace
plus an instantiation handler that writes into the existing registry.
"""

from __future__ import annotations

import json
import time as _time

from fastapi import APIRouter, HTTPException, Request

from api.routes_agents_registry import (
    _MAX_TOOL_NAME_LEN,
    _sanitize_string,
    _sanitize_value,
    _validate_agent_body,
    _validate_agent_id,
    _validate_owner_email,
    get_redis_data,
    get_tenant_from_api_key,
)
from storage.tenant_store import _get_redis

router = APIRouter(prefix="/v1/agents/blueprints", tags=["agent-blueprints"])


def _blueprints_key(tenant_id: str) -> str:
    return f"agent_blueprints:{tenant_id}"


def _agents_key(tenant_id: str) -> str:
    return f"agents:{tenant_id}"


def _build_blueprint_record(body: dict, *, existing: dict | None = None) -> dict:
    """Normalize and sanitize an inbound blueprint payload."""
    owner_email = _validate_owner_email(body.get("owner_email"), required=existing is None)
    now = int(_time.time())
    record = dict(existing or {})
    record.update({
        "name": _sanitize_string(body.get("name", record.get("name", ""))),
        "description": _sanitize_string(body.get("description", record.get("description", ""))),
        "tools": [
            _sanitize_string(t, _MAX_TOOL_NAME_LEN)
            for t in body.get("tools", record.get("tools", []))
        ],
        "role_permissions": _sanitize_value(
            body.get("role_permissions", record.get("role_permissions", {}))
        ),
        "agent_permissions": _sanitize_value(
            body.get("agent_permissions", record.get("agent_permissions", {}))
        ),
        "updated_at": now,
    })
    if owner_email:
        record["owner_email"] = owner_email
    elif "owner_email" not in record:
        record["owner_email"] = existing.get("owner_email", "") if existing else ""
    if "owner_name" in body:
        record["owner_name"] = _sanitize_string(body.get("owner_name", ""))
    elif existing and "owner_name" in existing:
        record["owner_name"] = existing["owner_name"]
    if existing is None:
        record["created_at"] = now
        record["version"] = 1
    else:
        record["version"] = int(existing.get("version", 1)) + 1
    return record


@router.get("")
async def list_blueprints(request: Request):
    """List all blueprints for the tenant."""
    tenant_id = get_tenant_from_api_key(request)
    blueprints = get_redis_data(_blueprints_key(tenant_id)) or {}
    return {
        "success": True,
        "tenant_id": tenant_id,
        "blueprints": blueprints,
        "total": len(blueprints),
    }


@router.post("")
async def create_blueprint(request: Request):
    """Create a new blueprint."""
    tenant_id = get_tenant_from_api_key(request)
    body = await request.json()

    blueprint_id = (body.get("blueprint_id") or "").strip()
    if not blueprint_id:
        raise HTTPException(status_code=400, detail="blueprint_id is required")
    _validate_agent_id(blueprint_id)
    _validate_agent_body(body, require_owner=True)

    key = _blueprints_key(tenant_id)
    blueprints = get_redis_data(key) or {}
    if blueprint_id in blueprints:
        raise HTTPException(status_code=409, detail=f"Blueprint '{blueprint_id}' already exists")

    record = _build_blueprint_record(body)
    record["blueprint_id"] = blueprint_id
    blueprints[blueprint_id] = record

    r = _get_redis()
    if r is None:
        raise HTTPException(status_code=503, detail="Redis connection not available")
    r.set(key, json.dumps(blueprints))

    return {"success": True, "blueprint": record}


@router.get("/{blueprint_id}")
async def get_blueprint(blueprint_id: str, request: Request):
    _validate_agent_id(blueprint_id)
    tenant_id = get_tenant_from_api_key(request)
    blueprints = get_redis_data(_blueprints_key(tenant_id)) or {}
    if blueprint_id not in blueprints:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    return {"success": True, "blueprint": blueprints[blueprint_id]}


@router.put("/{blueprint_id}")
async def update_blueprint(blueprint_id: str, request: Request):
    _validate_agent_id(blueprint_id)
    tenant_id = get_tenant_from_api_key(request)
    body = await request.json()
    _validate_agent_body(body)

    key = _blueprints_key(tenant_id)
    blueprints = get_redis_data(key) or {}
    if blueprint_id not in blueprints:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    record = _build_blueprint_record(body, existing=blueprints[blueprint_id])
    record["blueprint_id"] = blueprint_id
    blueprints[blueprint_id] = record

    r = _get_redis()
    if r is None:
        raise HTTPException(status_code=503, detail="Redis connection not available")
    r.set(key, json.dumps(blueprints))

    return {"success": True, "blueprint": record}


@router.delete("/{blueprint_id}")
async def delete_blueprint(blueprint_id: str, request: Request):
    _validate_agent_id(blueprint_id)
    tenant_id = get_tenant_from_api_key(request)

    key = _blueprints_key(tenant_id)
    blueprints = get_redis_data(key) or {}
    if blueprint_id not in blueprints:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    removed = blueprints.pop(blueprint_id)

    r = _get_redis()
    if r is None:
        raise HTTPException(status_code=503, detail="Redis connection not available")
    r.set(key, json.dumps(blueprints))

    return {"success": True, "deleted_blueprint": removed}


@router.post("/{blueprint_id}/instantiate")
async def instantiate_blueprint(blueprint_id: str, request: Request):
    """Mint a new agent in `agents:{tenant_id}` from this blueprint."""
    _validate_agent_id(blueprint_id)
    tenant_id = get_tenant_from_api_key(request)
    body = await request.json()

    agent_id = (body.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    _validate_agent_id(agent_id)

    blueprints = get_redis_data(_blueprints_key(tenant_id)) or {}
    bp = blueprints.get(blueprint_id)
    if bp is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    agents_key = _agents_key(tenant_id)
    agents = get_redis_data(agents_key) or {}
    if agent_id in agents:
        raise HTTPException(status_code=409, detail=f"Agent '{agent_id}' already exists")

    # Owner: caller may override; otherwise inherit from blueprint.
    owner_email = body.get("owner_email") or bp.get("owner_email", "")
    owner_email = _validate_owner_email(owner_email, required=True)

    now = int(_time.time())
    name_suffix = _sanitize_string(body.get("name_suffix", ""))
    instance_name = _sanitize_string(
        body.get("name") or (f"{bp.get('name', blueprint_id)} {name_suffix}".strip())
    )
    record = {
        "agent_id": agent_id,
        "name": instance_name,
        "description": _sanitize_string(body.get("description", bp.get("description", ""))),
        "tools": list(bp.get("tools", [])),
        "role_permissions": dict(bp.get("role_permissions", {})),
        "agent_permissions": dict(bp.get("agent_permissions", {})),
        "owner_email": owner_email,
        "owner_name": _sanitize_string(body.get("owner_name", bp.get("owner_name", ""))),
        "blueprint_id": blueprint_id,
        "blueprint_version": bp.get("version", 1),
        "status": body.get("status", "active"),
        "created_at": now,
        "updated_at": now,
    }
    agents[agent_id] = record

    r = _get_redis()
    if r is None:
        raise HTTPException(status_code=503, detail="Redis connection not available")
    r.set(agents_key, json.dumps(agents))

    return {"success": True, "agent": record}
