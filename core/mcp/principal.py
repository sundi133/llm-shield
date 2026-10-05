"""Who is calling the MCP gateway, and how sure we are.

`resolve_caller` wraps the gateway's existing identity resolution and adds the
verified principal behind the request, if there is one: a person who signed in
(a Shield access token naming a principal) or a service account (a principal
key). The result is recorded on every decision in the audit trail.

For a tenant key, enforcement gets exactly what the legacy resolver returns:
the role is whatever `X-User-Role` says, as before, and the caller is recorded
as unverified. That record is what tells a tenant when it can switch a route to
"verified callers only" (task A4) without breaking a client.

A credential that names a principal (a token from MCP sign-in, or a principal
key) is different, because it is new and nothing depends on the old behaviour:
- its role comes from the principal. `X-User-Role` may pick one of the
  principal's own roles and is otherwise ignored, so a signed-in employee
  cannot claim `admin` with a header;
- it admits the caller only while the principal is active.

A Shield access token whose `jti` was revoked is not accepted (`_oauth_claims`).

Latency (guard path): tenant-key callers add no Redis read. A Shield token adds
the revocation read; a principal token adds one principal read, cached
in-process for `_CACHE_TTL_S`. A principal key adds its own one read.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.2, §4.10)
"""

from __future__ import annotations

import logging
import os
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("votal.mcp.principal")

# How the identity was established. Only the first three are verified.
METHOD_OAUTH_USER = "oauth_user"
METHOD_OAUTH_SERVICE_ACCOUNT = "oauth_service_account"
METHOD_PRINCIPAL_KEY = "principal_key"
METHOD_OAUTH_LEGACY = "oauth_legacy"            # Shield token with no principal
METHOD_PRINCIPAL_INACTIVE = "principal_inactive"  # suspended, deprovisioned or unknown
METHOD_TENANT_MISMATCH = "principal_tenant_mismatch"
METHOD_TENANT_KEY = "tenant_key"
METHOD_NONE = "none"

_CACHE_TTL_S = 15.0
_CACHE_MAX = 10_000
_cache: dict[tuple[str, str], tuple[float, Optional[dict]]] = {}


@dataclass
class Caller:
    """The resolved caller. `tenant_id`, `agent_key` and `user_role` are what
    enforcement uses; everything else describes the identity for the audit."""

    tenant_id: str
    agent_key: str
    user_role: str
    identity_method: str = METHOD_NONE
    verified: bool = False
    role_source: str = "none"
    principal_id: str = ""
    principal_type: str = ""
    email: str = ""
    principal_roles: list = field(default_factory=list)
    client_id: str = ""
    role_override_refused: bool = False

    def audit_fields(self) -> dict:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "email": self.email,
            "identity_method": self.identity_method,
            "verified": self.verified,
            "role_source": self.role_source,
            "principal_roles": list(self.principal_roles),
            "client_id": self.client_id,
            "role_override_refused": self.role_override_refused,
        }


_current: ContextVar[Optional[Caller]] = ContextVar("shield_mcp_caller", default=None)


def current_caller() -> Optional[Caller]:
    """The caller of the gateway request being handled, if any."""
    return _current.get()


def set_current_caller(caller: Optional[Caller]):
    return _current.set(caller)


def reset_current_caller(token) -> None:
    _current.reset(token)


def clear_cache() -> None:
    _cache.clear()
    _policy_cache.clear()


def _cached_principal(tenant_id: str, pid: str) -> Optional[dict]:
    key = (tenant_id, pid)
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    from storage.principal_store import get_principal
    doc = get_principal(tenant_id, pid)
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()
    _cache[key] = (now + _CACHE_TTL_S, doc)
    return doc


def _bearer(headers) -> str:
    auth = headers.get("authorization", "") or ""
    return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


def _apply_principal(caller: Caller, tenant_id: str, doc: Optional[dict],
                     method: str, token_roles: Any = None) -> None:
    """Record `doc` on the caller if it is active and in the caller's tenant."""
    from storage.principal_store import is_active
    if caller.tenant_id and tenant_id and caller.tenant_id != tenant_id:
        caller.identity_method = METHOD_TENANT_MISMATCH
        return
    if not is_active(doc):
        caller.identity_method = METHOD_PRINCIPAL_INACTIVE
        return
    caller.identity_method = method
    caller.verified = True
    caller.principal_id = doc["id"]
    caller.principal_type = doc.get("type", "")
    caller.email = doc.get("email", "")
    roles = token_roles if isinstance(token_roles, list) else doc.get("roles")
    ordered: list = []
    for r in roles or []:
        r = str(r)
        if r and r not in ordered:
            ordered.append(r)
    caller.principal_roles = ordered


def _select_role(caller: Caller, header_role: str) -> None:
    """A verified caller acts as one of its own roles, never a header's choice.

    `X-User-Role` may pick among the principal's roles; any other value is
    ignored and recorded. With no pick, the first role (the order the IdP gave,
    filtered by the tenant's role allowlist at sign-in).
    """
    roles = caller.principal_roles
    if header_role and header_role in roles:
        caller.user_role, caller.role_source = header_role, "principal_selected"
    elif roles:
        caller.user_role, caller.role_source = roles[0], "principal"
    else:
        caller.user_role, caller.role_source = "", "principal_none"
    caller.role_override_refused = bool(header_role) and header_role not in roles


def _tenant_proven_otherwise(request, tenant_id: str) -> bool:
    """Whether the caller's tenant is established by something other than the
    principal credential: middleware state or a valid tenant key."""
    st = getattr(request, "state", None)
    if st is not None and getattr(st, "tenant_id", ""):
        return True
    api_key = (request.headers.get("x-api-key") or "").strip()
    if not api_key:
        return False
    from storage.tenant_store import resolve_tenant_by_api_key
    return (resolve_tenant_by_api_key(api_key) or "") == tenant_id


def _attach_principal(caller: Caller, request, oauth_claims: Callable[[Any], Optional[dict]]) -> None:
    from storage.principal_store import (
        TYPES, looks_like_principal_key, resolve_principal_key)

    headers = request.headers
    claims = oauth_claims(request)
    if claims:
        caller.client_id = str(claims.get("client_id") or "")
        ptype, pid = claims.get("ptype"), claims.get("sub") or ""
        if ptype in TYPES and pid:
            token_tenant = claims.get("tenant_id") or ""
            doc = _cached_principal(token_tenant, pid)
            if doc is not None and doc.get("type") != ptype:
                doc = None
            method = (METHOD_OAUTH_USER if ptype == "user" else METHOD_OAUTH_SERVICE_ACCOUNT)
            _apply_principal(caller, token_tenant, doc, method,
                             token_roles=claims.get("roles"))
            if not caller.verified and caller.tenant_id == token_tenant \
                    and not _tenant_proven_otherwise(request, token_tenant):
                # A principal token is honoured only for an active principal.
                caller.tenant_id = ""
        else:
            caller.identity_method = METHOD_OAUTH_LEGACY
        return

    for candidate in (headers.get("x-api-key", "").strip(), _bearer(headers)):
        if not looks_like_principal_key(candidate):
            continue
        rec = resolve_principal_key(candidate)
        if not rec:
            caller.identity_method = METHOD_PRINCIPAL_INACTIVE
            return
        key_tenant = rec.get("tenant_id") or ""
        tenant_from_key = not caller.tenant_id and bool(key_tenant)
        if tenant_from_key:
            caller.tenant_id = key_tenant   # a principal key names its own tenant
        _apply_principal(caller, key_tenant,
                         _cached_principal(key_tenant, rec.get("principal_id") or ""),
                         METHOD_PRINCIPAL_KEY)
        if tenant_from_key and not caller.verified:
            # A principal key is a new kind of credential, honoured only for an
            # active principal. It never un-admits a caller whose tenant was
            # established some other way.
            caller.tenant_id = ""
        return

    if caller.tenant_id:
        caller.identity_method = METHOD_TENANT_KEY


def resolve_caller(request, *, legacy: Callable[[Any], tuple],
                   oauth_claims: Callable[[Any], Optional[dict]]) -> Caller:
    """Resolve the caller. Never raises.

    `legacy` is the gateway's existing `(tenant, agent_key, user_role)`
    resolver and `oauth_claims` returns the verified Shield token claims for the
    request (or None). Both are passed in so the gateway keeps one definition of
    each and tests can substitute them.
    """
    tenant_id, agent_key, user_role = legacy(request)
    headers = getattr(request, "headers", None) or {}
    header_role = (headers.get("x-user-role") or "").strip()
    if not user_role:
        role_source = "none"
    elif user_role == header_role:
        role_source = "header"
    else:
        role_source = "state"       # set by middleware ahead of the gateway
    caller = Caller(tenant_id=tenant_id or "", agent_key=agent_key,
                    user_role=user_role or "", role_source=role_source)
    try:
        _attach_principal(caller, request, oauth_claims)
        if caller.verified:
            _select_role(caller, header_role)
    except Exception as e:      # noqa: BLE001 - identity recording must not fail a call
        logger.warning("mcp caller resolution failed, using legacy identity: %s", e)
        caller.tenant_id = tenant_id or ""
        caller.user_role = user_role or ""
        caller.role_source = role_source
        caller.identity_method = METHOD_TENANT_KEY if tenant_id else METHOD_NONE
        caller.verified = False
        caller.principal_id = caller.principal_type = caller.email = caller.client_id = ""
        caller.principal_roles = []
        caller.role_override_refused = False
        if _names_principal(request, oauth_claims) and not _proven_safely(request, tenant_id):
            # New credential kinds fail closed: without the principal store we
            # cannot tell an active principal from a suspended one, and the
            # legacy path would hand its holder a header-chosen role.
            caller.tenant_id = ""
    return caller


def _proven_safely(request, tenant_id: str) -> bool:
    try:
        return bool(tenant_id) and _tenant_proven_otherwise(request, tenant_id)
    except Exception:       # noqa: BLE001
        return False


def _names_principal(request, oauth_claims) -> bool:
    try:
        from storage.principal_store import TYPES, looks_like_principal_key
        claims = oauth_claims(request) or {}
        if claims.get("ptype") in TYPES:
            return True
        headers = request.headers
        return any(looks_like_principal_key(v) for v in
                   ((headers.get("x-api-key") or "").strip(), _bearer(headers)))
    except Exception:       # noqa: BLE001
        return True


# ── "verified callers only" (task A4) ────────────────────────────────────

_POLICY_TTL_S = 15.0
_policy_cache: dict[str, tuple[float, bool]] = {}


class IdentityRequired(Exception):
    """The route requires a verified caller and this one is not.

    Raised before the upstream is contacted. The gateway answers it with HTTP
    401 and the route's sign-in metadata, because MCP clients begin sign-in
    only on a 401.
    """

    def __init__(self, tenant_id: str, route: str, caller: Optional[Caller]):
        super().__init__("this MCP server accepts only signed-in users and service accounts")
        self.tenant_id, self.route, self.caller = tenant_id, route, caller


def enforcement_enabled() -> bool:
    """SHIELD_MCP_REQUIRE_VERIFIED=0 turns the rejection off fleet-wide, for
    rollback without editing routes. Identity is still resolved and recorded."""
    return os.environ.get("SHIELD_MCP_REQUIRE_VERIFIED", "1").strip().lower() not in (
        "0", "off", "false", "no")


def _tenant_default(tenant_id: str) -> bool:
    now = time.monotonic()
    hit = _policy_cache.get(tenant_id)
    if hit and hit[0] > now:
        return hit[1]
    from storage.identity_policy import get_policy
    value = bool(get_policy(tenant_id).get("require_verified_identity"))
    if len(_policy_cache) >= _CACHE_MAX:
        _policy_cache.clear()
    _policy_cache[tenant_id] = (now + _POLICY_TTL_S, value)
    return value


def requires_verified(tenant_id: str, cfg: Optional[dict]) -> bool:
    """Whether this route accepts only verified callers.

    The route's own `require_verified_identity` wins when it is a boolean
    (an explicit false exempts one route from a tenant-wide default); absent,
    the tenant default applies, read through a 15 s in-process cache so the
    guard path pays no store read.
    """
    value = (cfg or {}).get("require_verified_identity")
    if isinstance(value, bool):
        return value
    return _tenant_default(tenant_id)


def check_verified(tenant_id: str, route: str, cfg: Optional[dict]) -> None:
    """Raise IdentityRequired when the current gateway caller may not use this
    route. A no-op outside a gateway request (no caller), so other users of the
    router are unaffected."""
    caller = current_caller()
    if caller is None or caller.verified or not enforcement_enabled():
        return
    if requires_verified(tenant_id, cfg):
        raise IdentityRequired(tenant_id, route, caller)
