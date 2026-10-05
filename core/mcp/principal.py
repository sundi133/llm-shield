"""Who is calling the MCP gateway, and how sure we are.

`resolve_caller` wraps the gateway's existing identity resolution and adds the
verified principal behind the request, if there is one: a person who signed in
(a Shield access token naming a principal) or a service account (a principal
key). The result is recorded on every decision in the audit trail.

**Task A1 is audit only.** The tenant, agent key and role that enforcement uses
are exactly what the legacy resolver returns, so no decision changes. What is
new is the record of who the principal was and whether the identity was
verified; that record is what tells a tenant when it can switch a route to
"verified callers only" (task A4) without breaking a client.

The one behaviour that does change sits in `_oauth_claims`: a Shield access
token whose `jti` was revoked is no longer accepted.

Latency (guard path): tenant-key callers add no Redis read. A Shield token adds
the revocation read; a principal token adds one principal read, cached
in-process for `_CACHE_TTL_S`. A principal key adds its own one read.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.2, §4.10)
"""

from __future__ import annotations

import logging
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

    def audit_fields(self) -> dict:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "email": self.email,
            "identity_method": self.identity_method,
            "verified": self.verified,
            "role_source": self.role_source,
            "principal_roles": list(self.principal_roles),
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
    caller.principal_roles = sorted({str(r) for r in (roles or [])})


def _attach_principal(caller: Caller, request, oauth_claims: Callable[[Any], Optional[dict]]) -> None:
    from storage.principal_store import (
        TYPES, looks_like_principal_key, resolve_principal_key)

    headers = request.headers
    claims = oauth_claims(request)
    if claims:
        ptype, pid = claims.get("ptype"), claims.get("sub") or ""
        if ptype in TYPES and pid:
            doc = _cached_principal(claims.get("tenant_id") or "", pid)
            if doc is not None and doc.get("type") != ptype:
                doc = None
            method = (METHOD_OAUTH_USER if ptype == "user" else METHOD_OAUTH_SERVICE_ACCOUNT)
            _apply_principal(caller, claims.get("tenant_id") or "", doc, method,
                             token_roles=claims.get("roles"))
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
    except Exception as e:      # noqa: BLE001 - identity recording must not fail a call
        logger.warning("mcp caller resolution failed, using legacy identity: %s", e)
        caller.tenant_id = tenant_id or ""
        caller.identity_method = METHOD_TENANT_KEY if tenant_id else METHOD_NONE
        caller.verified = False
        caller.principal_id = caller.principal_type = caller.email = ""
        caller.principal_roles = []
    return caller
