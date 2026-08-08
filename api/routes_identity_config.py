"""Tenant self-service configuration for role binding (IdP claim paths).

Role binding reads a role out of a verified credential instead of trusting the
`X-User-Role` header. Which claim carries that role differs per IdP: Keycloak
nests realm roles at ``realm_access.roles``, Okta uses ``groups``, Entra ID uses
``roles``. Without per-tenant configuration, role binding works against
Keycloak and nothing else.

The storage key has existed for a while. Until now there was no writer at all —
configuring a tenant meant hand-writing JSON with ``redis-cli``.

Admin plane only. Nothing here runs on the guard path.
"""
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request
from core.identity_resolution import (_MODES, _env_mode, DEFAULT_ROLE_CLAIM,
                                      MODE_OFF)
from storage.admin_audit import log_admin_action
from storage.role_binding_config import MODE_STRENGTH, get_config, set_config

router = APIRouter(prefix="/v1/tenant/me/identity", tags=["tenant-identity-config"])

MAX_CLAIM_LEN = 128
MAX_MAP_ENTRIES = 256
MAX_TERM_LEN = 128

#: Known-good claim paths, so operators do not guess. Guessing here fails
#: silently: a wrong path yields no roles, role binding falls back, and the
#: symptom looks like "binding is broken" rather than "the path is wrong".
PRESETS = {
    "keycloak": {"role_claim": "realm_access.roles",
                 "note": "Keycloak realm roles. The default."},
    "okta": {"role_claim": "groups",
             "note": "Requires a groups claim on the authorization server."},
    "entra": {"role_claim": "roles",
              "note": "Entra ID app roles. Directory groups appear as 'groups'."},
    "auth0": {"role_claim": "https://<your-namespace>/roles",
              "note": "Namespaced claims are not yet resolvable by the dotted "
                      "path reader. Tracked in spec-idp-role-claim-config."},
}


class RoleBindingConfigRequest(BaseModel):
    mode: Optional[str] = Field(None, description="off | prefer | strict | strict_proxy")
    role_claim: Optional[str] = Field(None, description="Dotted path to the role claim")
    role_map: Optional[dict[str, str]] = Field(None, description="IdP group -> Shield role")
    role_allowlist: Optional[list[str]] = Field(
        None, description="Shield role names to accept; others are dropped")


def _tenant_id(request: Request) -> str:
    return get_tenant_from_request(request)


def _view(tenant_id: str) -> dict[str, Any]:
    """The stored config plus why it may not be taking effect.

    ``effective_mode`` and ``env_kill_switch`` exist because
    SHIELD_ROLE_BINDING=off overrides tenant config globally, and that asymmetry
    is otherwise invisible: the tenant sees "prefer" stored, observes header
    roles still winning, and has nothing to look at.
    """
    stored = get_config(tenant_id) or {}
    env = _env_mode()
    stored_mode = str(stored.get("mode", "") or "").strip().lower()
    if stored_mode not in _MODES:
        stored_mode = ""

    effective = env if (env == MODE_OFF or not stored_mode) else stored_mode

    return {
        "tenant_id": tenant_id,
        "mode": stored_mode or None,
        "effective_mode": effective,
        "env_mode": env,
        "env_kill_switch": env == MODE_OFF,
        "role_claim": stored.get("role_claim") or DEFAULT_ROLE_CLAIM,
        "role_map": stored.get("role_map") or {},
        "role_allowlist": stored.get("role_allowlist") or [],
        "updated_at": stored.get("updated_at"),
        "updated_by": stored.get("updated_by"),
        "propagation_seconds": 30,
    }


def _validate(body: RoleBindingConfigRequest) -> None:
    if body.mode is not None:
        mode = body.mode.strip().lower()
        if mode not in _MODES:
            raise HTTPException(422, f"mode must be one of {sorted(_MODES)}")
        env = _env_mode()
        # A tenant may strengthen its own binding, never weaken the deployment
        # baseline. An operator who set strict made a security decision; a
        # tenant storing "off" over it would quietly undo that for their traffic.
        if env != MODE_OFF and MODE_STRENGTH[mode] < MODE_STRENGTH[env]:
            raise HTTPException(
                422,
                f"mode {mode!r} is weaker than the deployment setting {env!r}; "
                f"a tenant may strengthen role binding but not weaken it")

    if body.role_claim is not None:
        claim = body.role_claim.strip()
        if not claim:
            raise HTTPException(422, "role_claim must not be empty")
        if len(claim) > MAX_CLAIM_LEN:
            raise HTTPException(422, f"role_claim exceeds {MAX_CLAIM_LEN} characters")

    if body.role_allowlist is not None:
        if len(body.role_allowlist) > MAX_MAP_ENTRIES:
            raise HTTPException(
                422, f"role_allowlist exceeds {MAX_MAP_ENTRIES} entries")
        for r in body.role_allowlist:
            if not str(r).strip():
                raise HTTPException(422, "role_allowlist entries must not be empty")
            if len(str(r)) > MAX_TERM_LEN:
                raise HTTPException(
                    422, f"role_allowlist entries must be under {MAX_TERM_LEN} characters")

    if body.role_map is not None:
        if len(body.role_map) > MAX_MAP_ENTRIES:
            raise HTTPException(422, f"role_map exceeds {MAX_MAP_ENTRIES} entries")
        for k, v in body.role_map.items():
            if not str(k).strip() or not str(v).strip():
                raise HTTPException(422, "role_map keys and values must not be empty")
            if len(str(k)) > MAX_TERM_LEN or len(str(v)) > MAX_TERM_LEN:
                raise HTTPException(
                    422, f"role_map keys and values must be under {MAX_TERM_LEN} characters")


@router.get("/role-binding")
async def get_role_binding(request: Request):
    """Current role-binding config for the calling tenant."""
    return _view(_tenant_id(request))


@router.get("/role-binding/presets")
async def get_role_binding_presets(request: Request):
    """Known-good claim paths per IdP."""
    _tenant_id(request)          # authenticate; presets are not tenant-specific
    return {"presets": PRESETS}


@router.put("/role-binding")
async def put_role_binding(body: RoleBindingConfigRequest, request: Request):
    """Merge a partial config over the stored value.

    Omitted fields are left untouched, so an operator can change the claim path
    without restating the role map.
    """
    tenant_id = _tenant_id(request)
    _validate(body)

    import time

    current = dict(get_config(tenant_id) or {})
    if body.mode is not None:
        current["mode"] = body.mode.strip().lower()
    if body.role_claim is not None:
        current["role_claim"] = body.role_claim.strip()
    if body.role_map is not None:
        current["role_map"] = {str(k).strip(): str(v).strip()
                               for k, v in body.role_map.items()}
    if body.role_allowlist is not None:
        current["role_allowlist"] = [str(r).strip() for r in body.role_allowlist
                                     if str(r).strip()]
    current["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    current["updated_by"] = f"tenant:{tenant_id}"

    try:
        set_config(tenant_id, current)
    except Exception as e:
        # Refused, not silently dropped. A config that looks saved and is not
        # leaves the operator believing role binding is configured.
        raise HTTPException(503, f"could not persist role-binding config: {e}")

    log_admin_action(
        action="identity.role_binding.update",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"mode": current.get("mode"),
                  "role_claim": current.get("role_claim"),
                  "role_map_entries": len(current.get("role_map") or {}),
                  "role_allowlist_entries": len(current.get("role_allowlist") or [])},
    )

    return _view(tenant_id)
