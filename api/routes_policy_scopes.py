"""Policy scopes config routes (docs/specs/policy-scopes.md, task 2).

Global + per-team I/O policies selected by a request header. Two routers share
one set of handlers:

- ``/v1/tenant/me/policy-scopes``: the tenant itself (key or portal session).
  Reads need the tenant; writes go through ``require_config_write``, the same
  gate as every other tenant config write.
- ``/v1/admin/tenants/{tenant_id}/policy-scopes``: the platform operator.
  ``/v1/admin/*`` is already admin-authenticated; managed credentials are
  scoped per operation like the rest of ``routes_tenant``.

Off the guard path: these routes only read and write the tenant record. The
guard path reads ``policy_scopes`` from the tenant config it already caches
(task 3), so a change applies within that cache's 60 s, like any policy edit.
``POST .../preview`` reads the store fresh, so it reflects a save at once.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from core.auth import require_config_write
from core.policy_scopes import (
    MISSING, RULE_GLOBAL, STAGE_KEYS, resolve, scopes_disabled,
)
from storage.admin_audit import log_admin_action
from storage.policy_scopes_store import (
    AmbiguousKeyPrefix, InvalidScopes, KeyPrefixNotFound, TenantNotFound,
    VersionConflict, change_scopes, get_scopes, resolve_key_prefix, stale_warnings,
)

tenant_router = APIRouter(prefix="/v1/tenant/me/policy-scopes", tags=["policy-scopes"])
admin_router = APIRouter(prefix="/v1/admin/tenants/{tenant_id}/policy-scopes",
                         tags=["policy-scopes"])


class SettingsBody(BaseModel):
    enabled: bool = True
    selectors: list[dict] = Field(default_factory=list)
    missing: str = "global"
    unmatched: Optional[dict] = None
    expected_version: Optional[int] = None


class RuleBody(BaseModel):
    match: dict = Field(default_factory=dict)
    input_guardrails: Optional[dict] = None
    output_guardrails: Optional[dict] = None
    expected_version: Optional[int] = None


class KeyBindingBody(BaseModel):
    allowed: list[str] = Field(default_factory=list)
    expected_version: Optional[int] = None


class PreviewBody(BaseModel):
    headers: dict = Field(default_factory=dict)
    key_prefix: Optional[str] = None


# ── Caller resolution ────────────────────────────────────────────────────────

async def _tenant_caller(request: Request, body: Optional[BaseModel] = None,
                         write: bool = False) -> tuple[str, str]:
    """``(tenant_id, actor)`` for the tenant routes."""
    from api.routes_tenant_self import _actor, _reject_tenant_id_spoof, _require_tenant
    await _reject_tenant_id_spoof(request, body.model_dump() if body else None)
    tenant_id = _require_tenant(request)
    if write:
        require_config_write(request, tenant_id, "change the tenant's policy scopes")
    return tenant_id, _actor(request, tenant_id)


def _admin_caller(request: Request, tenant_id: str, write: bool = False) -> str:
    """The actor for the admin routes, after the managed-credential scope check."""
    from core.auth import admin_actor, require_admin_scope
    require_admin_scope(request, "tenants:write" if write else "tenants:read", tenant_id)
    return admin_actor(request)


# ── Shared handlers ──────────────────────────────────────────────────────────

def _errors_to_http(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except TenantNotFound:
        raise HTTPException(status_code=404, detail="Tenant not found")
    except VersionConflict as e:
        raise HTTPException(status_code=409, detail={
            "message": "Policy scopes changed since you loaded them. Reload and retry.",
            "current_version": e.current})
    except InvalidScopes as e:
        raise HTTPException(status_code=422, detail={"errors": e.errors})


def _audit(request: Request, action: str, actor: str, tenant_id: str, metadata: dict) -> None:
    log_admin_action(
        action=action, actor=actor, tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata=metadata,
    )


def _read(tenant_id: str) -> dict:
    tenant, scopes = _errors_to_http(get_scopes, tenant_id)
    return {"tenant_id": tenant_id, "policy_scopes": scopes,
            "warnings": stale_warnings(tenant, scopes),
            "kill_switch": scopes_disabled()}


def _put_settings(request: Request, tenant_id: str, actor: str, body: SettingsBody) -> dict:
    def mutate(s: dict) -> None:
        s["enabled"] = body.enabled
        s["selectors"] = body.selectors
        s["missing"] = body.missing
        if body.unmatched is None:
            s.pop("unmatched", None)
        else:
            s["unmatched"] = body.unmatched
    saved = _errors_to_http(change_scopes, tenant_id, mutate, body.expected_version,
                            only_rules=set(), check_unmatched=True)
    _audit(request, "policy_scopes_settings", actor, tenant_id, {
        "enabled": body.enabled,
        "selectors": [s.get("header") for s in body.selectors if isinstance(s, dict)],
        "missing": body.missing, "unmatched": body.unmatched is not None,
        "version": saved["version"]})
    return {"status": "updated", "policy_scopes": saved}


def _put_rule(request: Request, tenant_id: str, actor: str, rule_id: str, body: RuleBody) -> dict:
    rule = {"id": rule_id, "match": body.match}
    for stage in STAGE_KEYS:
        value = getattr(body, stage)
        if value is not None:
            rule[stage] = value
    created = []

    def mutate(s: dict) -> None:
        rules = s.setdefault("rules", [])
        for i, existing in enumerate(rules):
            if isinstance(existing, dict) and existing.get("id") == rule_id:
                rules[i] = rule
                return
        rules.append(rule)
        created.append(True)
    saved = _errors_to_http(change_scopes, tenant_id, mutate, body.expected_version,
                            only_rules={rule_id})
    _audit(request, "policy_scopes_rule_create" if created else "policy_scopes_rule_update",
           actor, tenant_id, {"rule": rule_id, "match": body.match,
                              "input_guardrails": list((body.input_guardrails or {}).keys()),
                              "output_guardrails": list((body.output_guardrails or {}).keys()),
                              "version": saved["version"]})
    return {"status": "created" if created else "updated", "rule": rule, "policy_scopes": saved}


def _delete_rule(request: Request, tenant_id: str, actor: str, rule_id: str) -> Response:
    def mutate(s: dict) -> None:
        rules = s.get("rules") or []
        kept = [r for r in rules if not (isinstance(r, dict) and r.get("id") == rule_id)]
        if len(kept) == len(rules):
            raise LookupError(rule_id)
        s["rules"] = kept
    try:
        saved = _errors_to_http(change_scopes, tenant_id, mutate)
    except LookupError:
        raise HTTPException(status_code=404, detail=f"No rule '{rule_id}'")
    _audit(request, "policy_scopes_rule_delete", actor, tenant_id,
           {"rule": rule_id, "version": saved["version"]})
    return Response(status_code=204)


def _put_binding(request: Request, tenant_id: str, actor: str, key_prefix: str,
                 body: KeyBindingBody) -> dict:
    try:
        _errors_to_http(resolve_key_prefix, tenant_id, key_prefix)
    except KeyPrefixNotFound:
        raise HTTPException(status_code=404, detail=f"No key of this tenant starts with '{key_prefix}'")
    except AmbiguousKeyPrefix:
        raise HTTPException(status_code=409, detail=f"More than one key starts with '{key_prefix}'")

    def mutate(s: dict) -> None:
        s.setdefault("key_bindings", {})[key_prefix] = body.allowed
    saved = _errors_to_http(change_scopes, tenant_id, mutate, body.expected_version)
    _audit(request, "policy_scopes_key_binding", actor, tenant_id,
           {"key_prefix": key_prefix, "allowed": body.allowed, "version": saved["version"]})
    return {"status": "updated", "key_prefix": key_prefix, "allowed": body.allowed,
            "policy_scopes": saved}


def _delete_binding(request: Request, tenant_id: str, actor: str, key_prefix: str) -> Response:
    def mutate(s: dict) -> None:
        bindings = s.get("key_bindings") or {}
        if key_prefix not in bindings:
            raise LookupError(key_prefix)
        del bindings[key_prefix]
    try:
        saved = _errors_to_http(change_scopes, tenant_id, mutate)
    except LookupError:
        raise HTTPException(status_code=404, detail=f"No binding for '{key_prefix}'")
    _audit(request, "policy_scopes_key_binding_delete", actor, tenant_id,
           {"key_prefix": key_prefix, "version": saved["version"]})
    return Response(status_code=204)


def _tiers(effective: dict) -> dict:
    """Each effective guardrail's tier, so a slow (LLM) guardrail is visible
    before it is saved. The admin image ships no guardrail registry; there the
    tier reads as unknown rather than failing the preview."""
    try:
        from guardrails.registry import get_guardrail
    except Exception:
        get_guardrail = None
    out = {}
    for stage in STAGE_KEYS:
        for name in effective.get(stage) or {}:
            g = get_guardrail(name) if get_guardrail else None
            out[name] = getattr(g, "tier", None) or "unknown"
    return out


def _preview(tenant_id: str, body: PreviewBody) -> dict:
    """Which rule a request would land in, and the policy it would run.

    Evaluated even while scopes are switched off for the tenant, so an admin
    can test rules before turning them on; ``scopes_active`` says whether live
    traffic would see the same thing.
    """
    tenant, scopes = _errors_to_http(get_scopes, tenant_id)
    active = bool(scopes.get("enabled")) and not scopes_disabled()
    trial = dict(tenant)
    trial["policy_scopes"] = {**scopes, "enabled": True}

    lowered = {}
    for name, value in (body.headers or {}).items():
        values = value if isinstance(value, list) else [value]
        lowered.setdefault(str(name).lower(), []).extend(str(v) for v in values)

    resolution = resolve(trial, lambda n: lowered.get(n.lower(), []),
                         key_prefix=body.key_prefix, memo=False)
    decision = resolution.decision
    effective = {stage: (resolution.config or {}).get(stage) or {} for stage in STAGE_KEYS}
    return {
        "tenant_id": tenant_id,
        "scopes_active": active,
        "kill_switch": scopes_disabled(),
        "value": decision.value if decision else MISSING,
        "source_header": decision.header if decision else None,
        "rule": decision.rule if decision else RULE_GLOBAL,
        "outcome": decision.outcome if decision else "applied",
        "effective": effective,
        "guardrail_tiers": _tiers(effective),
    }


# ── Tenant routes ────────────────────────────────────────────────────────────

@tenant_router.get("")
async def get_my_policy_scopes(request: Request):
    tenant_id, _ = await _tenant_caller(request)
    return _read(tenant_id)


@tenant_router.put("/settings")
async def put_my_settings(request: Request, body: SettingsBody):
    tenant_id, actor = await _tenant_caller(request, body, write=True)
    return _put_settings(request, tenant_id, actor, body)


@tenant_router.put("/rules/{rule_id}")
async def put_my_rule(request: Request, rule_id: str, body: RuleBody):
    tenant_id, actor = await _tenant_caller(request, body, write=True)
    return _put_rule(request, tenant_id, actor, rule_id, body)


@tenant_router.delete("/rules/{rule_id}", status_code=204)
async def delete_my_rule(request: Request, rule_id: str):
    tenant_id, actor = await _tenant_caller(request, write=True)
    return _delete_rule(request, tenant_id, actor, rule_id)


@tenant_router.put("/key-bindings/{key_prefix}")
async def put_my_binding(request: Request, key_prefix: str, body: KeyBindingBody):
    tenant_id, actor = await _tenant_caller(request, body, write=True)
    return _put_binding(request, tenant_id, actor, key_prefix, body)


@tenant_router.delete("/key-bindings/{key_prefix}", status_code=204)
async def delete_my_binding(request: Request, key_prefix: str):
    tenant_id, actor = await _tenant_caller(request, write=True)
    return _delete_binding(request, tenant_id, actor, key_prefix)


@tenant_router.post("/preview")
async def preview_my_scope(request: Request, body: PreviewBody):
    tenant_id, _ = await _tenant_caller(request, body)
    return _preview(tenant_id, body)


# ── Admin routes ─────────────────────────────────────────────────────────────

@admin_router.get("")
async def admin_get_policy_scopes(request: Request, tenant_id: str):
    _admin_caller(request, tenant_id)
    return _read(tenant_id)


@admin_router.put("/settings")
async def admin_put_settings(request: Request, tenant_id: str, body: SettingsBody):
    actor = _admin_caller(request, tenant_id, write=True)
    return _put_settings(request, tenant_id, actor, body)


@admin_router.put("/rules/{rule_id}")
async def admin_put_rule(request: Request, tenant_id: str, rule_id: str, body: RuleBody):
    actor = _admin_caller(request, tenant_id, write=True)
    return _put_rule(request, tenant_id, actor, rule_id, body)


@admin_router.delete("/rules/{rule_id}", status_code=204)
async def admin_delete_rule(request: Request, tenant_id: str, rule_id: str):
    actor = _admin_caller(request, tenant_id, write=True)
    return _delete_rule(request, tenant_id, actor, rule_id)


@admin_router.put("/key-bindings/{key_prefix}")
async def admin_put_binding(request: Request, tenant_id: str, key_prefix: str,
                            body: KeyBindingBody):
    actor = _admin_caller(request, tenant_id, write=True)
    return _put_binding(request, tenant_id, actor, key_prefix, body)


@admin_router.delete("/key-bindings/{key_prefix}", status_code=204)
async def admin_delete_binding(request: Request, tenant_id: str, key_prefix: str):
    actor = _admin_caller(request, tenant_id, write=True)
    return _delete_binding(request, tenant_id, actor, key_prefix)


@admin_router.post("/preview")
async def admin_preview(request: Request, tenant_id: str, body: PreviewBody):
    _admin_caller(request, tenant_id)
    return _preview(tenant_id, body)
