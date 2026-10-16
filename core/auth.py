"""API key authentication middleware for LLM Shield."""

import hashlib
import hmac
import logging
import os
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import config.schema as _config_module

logger = logging.getLogger("votal.auth")


# ── Brute-force protection (IEMLabs VAPT finding 8.9, May 2026) ──────
#
# Track failed auth attempts per client IP. After MAX_FAILED_ATTEMPTS
# within the WINDOW, subsequent requests from that IP are rejected with
# 429 until the window expires. This prevents credential stuffing and
# brute-force attacks on the tenant login without requiring CAPTCHA at
# the API layer.

_MAX_FAILED_ATTEMPTS = int(os.environ.get("SHIELD_AUTH_MAX_FAILURES", "10"))
_LOCKOUT_WINDOW_SECS = int(os.environ.get("SHIELD_AUTH_LOCKOUT_SECS", "300"))

# Exact paths whose route checks its own non-API-key credential. Adding one is
# a deliberate act: the route must refuse an unauthenticated caller itself.
_SELF_AUTHENTICATED_PATHS = frozenset({"/v1/devices/enroll"})

# {ip: [(timestamp, ...),]} — in-memory; Redis-backed deployments can
# override via SHIELD_AUTH_RATE_LIMIT_REDIS=1 in future.
_failed_attempts: dict[str, list[float]] = defaultdict(list)

_TRUTHY = ("1", "true", "yes", "on")


def _client_ip(request: Request) -> str:
    """Resolve the real client IP for rate-limiting.

    The app runs behind an edge proxy (e.g. Railway), so request.client.host
    is the proxy's IP — keying the lockout on it would lock out every user
    at once and never isolate a single attacker. When SHIELD_TRUST_PROXY_HEADERS
    is enabled we use the last entry of X-Forwarded-For, which is the address
    the nearest trusted proxy observed and the client cannot forge (the proxy
    appends it). Without the flag we keep request.client.host so a directly
    exposed deployment can't be bypassed via a spoofed header.
    """
    if os.environ.get("SHIELD_TRUST_PROXY_HEADERS", "").strip().lower() in _TRUTHY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return request.client.host if request.client else "unknown"


def _record_auth_failure(client_ip: str) -> None:
    """Record a failed authentication attempt for the given IP."""
    now = time.monotonic()
    _failed_attempts[client_ip].append(now)
    # Prune old entries outside the window
    cutoff = now - _LOCKOUT_WINDOW_SECS
    _failed_attempts[client_ip] = [
        t for t in _failed_attempts[client_ip] if t > cutoff
    ]


def _is_ip_locked_out(client_ip: str) -> bool:
    """Check if the IP has exceeded the failure threshold."""
    now = time.monotonic()
    cutoff = now - _LOCKOUT_WINDOW_SECS
    attempts = _failed_attempts.get(client_ip, [])
    recent = [t for t in attempts if t > cutoff]
    _failed_attempts[client_ip] = recent  # prune while checking
    return len(recent) >= _MAX_FAILED_ATTEMPTS


def _clear_auth_failures(client_ip: str) -> None:
    """Clear failure counter on successful auth (reward good behavior)."""
    _failed_attempts.pop(client_ip, None)


class AuthMiddleware(BaseHTTPMiddleware):
    """Validates API key on protected endpoints.

    Checks for API key in:
    1. Authorization: Bearer <key>
    2. X-API-Key: <key>

    Admin endpoints (/v1/admin/*) require a separate admin key, provided
    via X-Admin-Key header and validated against SHIELD_ADMIN_KEY env var.

    Public paths (health, docs, playground) are exempted.
    When auth is disabled in config, all requests pass through.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        cfg = _config_module.config
        path = request.url.path
        client_ip = _client_ip(request)

        # Brute-force lockout check (finding 8.9)
        if _is_ip_locked_out(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many failed authentication attempts. Try again later.",
                },
                headers={"Retry-After": str(_LOCKOUT_WINDOW_SECS)},
            )

        # Admin routes: require an admin SSO session OR the admin key.
        if path.startswith("/v1/admin/"):
            # The admin-auth routes authenticate via the IdP themselves, so they
            # must be reachable without a session or key, or login/callback could
            # never complete.
            if path.startswith("/v1/admin/auth/"):
                return await call_next(request)

            # SSO session is the primary operator login; X-Admin-Key below stays
            # as break-glass. Lazy import keeps module load acyclic.
            try:
                from storage.admin_sessions import get_session as _get_admin_session
                sid = request.cookies.get(ADMIN_COOKIE_NAME, "")
                if sid:
                    rec = _get_admin_session(sid)
                    if rec:
                        request.state.admin_session = rec
                        _clear_auth_failures(client_ip)
                        return await call_next(request)
            except Exception:
                pass  # fall through to the key; never fail-open on a store hiccup

            admin_key = os.environ.get("SHIELD_ADMIN_KEY", "")
            if not admin_key:
                return JSONResponse(
                    status_code=500,
                    content={"error": "SHIELD_ADMIN_KEY not configured — admin endpoints disabled"},
                )

            provided = request.headers.get("X-Admin-Key", "").strip()
            if not provided:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Not authenticated. Sign in via SSO "
                             "(/v1/admin/auth/login), or provide X-Admin-Key "
                             "(break-glass) for /v1/admin/* routes."},
                )

            # Root key: the env secret, compared first and WITHOUT touching
            # Redis, so an existing single-key deployment is byte-identical.
            if hmac.compare_digest(provided, admin_key):
                request.state.admin_identity = {
                    "kind": "admin_root", "id": "root", "name": "root"}
                _clear_auth_failures(client_ip)
                return await call_next(request)

            # A named, managed credential (shadm_...): a partner or automation
            # key that is attributable, expirable and revocable on its own. Only
            # a non-root value reaches here, so the Redis lookup never burdens
            # the root path. A store error falls through to the 403 below —
            # never fail-open on a store hiccup.
            if os.environ.get("SHIELD_ADMIN_CREDENTIALS", "on").strip().lower() \
                    not in ("off", "0", "false", "no"):
                try:
                    from storage.admin_credentials import (
                        record_last_used, resolve_admin_credential)
                    rec = resolve_admin_credential(provided)
                    if rec:
                        request.state.admin_identity = {
                            "kind": "admin_credential",
                            "id": rec.get("id", ""),
                            "name": rec.get("name", ""),
                            "scope": rec.get("scope"),
                        }
                        try:
                            record_last_used(rec.get("key_hash", ""))
                        except Exception:
                            pass
                        _clear_auth_failures(client_ip)
                        return await call_next(request)
                except Exception:
                    pass

            _record_auth_failure(client_ip)
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid admin key"},
            )

        if cfg is None or not cfg.auth.enabled:
            return await call_next(request)

        # Routes that authenticate the caller themselves with a credential
        # that is not an API key: a laptop enrolling with its MDM-issued
        # enrollment token (docs/specs/device-dlp-agent.md §6).
        if path in _SELF_AUTHENTICATED_PATHS:
            return await call_next(request)

        # Check if path is public
        for public in cfg.auth.public_paths:
            if path == public or path.startswith(public + "/"):
                return await call_next(request)

        # No keys configured means auth is misconfigured — reject
        if not cfg.auth.api_keys:
            return JSONResponse(
                status_code=500,
                content={"error": "Auth enabled but no API keys configured"},
            )

        # Extract key from request
        api_key = _extract_api_key(request)
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Missing API key. Use Authorization: Bearer <key> or X-API-Key header."
                },
            )

        # Validate key against global keys OR tenant keys in Redis
        if not _validate_key(api_key, cfg.auth.api_keys):
            # Fall back to tenant API key resolution
            try:
                from storage.tenant_store import resolve_tenant_by_api_key
                tenant_id = resolve_tenant_by_api_key(api_key)

                # Special handling for test API keys
                if not tenant_id and api_key.startswith("sk-test-"):
                    # Allow test API keys for development/testing
                    tenant_id = "test-tenant-001"

                    # Ensure test tenant exists in storage
                    from storage.tenant_store import get_tenant, create_tenant
                    if not get_tenant(tenant_id):
                        create_tenant(tenant_id, {
                            "name": "Test Healthcare Organization",
                            "plan": "enterprise",
                            "description": "Test tenant for healthcare AI agents",
                            "industry": "healthcare",
                            "compliance_frameworks": ["hipaa"],
                            "created_at": "2026-04-08T00:00:00Z"
                        })

                if not tenant_id:
                    _record_auth_failure(client_ip)
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Invalid API key"},
                    )

                # Store tenant_id in request state
                request.state.tenant_id = tenant_id

                # And the HASH of the credential that authenticated. Write
                # routes need to know WHICH key this was, not just which
                # tenant, and by this point only the tenant survives. A route
                # that re-read the X-API-Key header instead would silently
                # exempt every Authorization: Bearer caller from any check
                # based on it.
                #
                # The hash, never the key: request.state can end up in an
                # exception dump. One SHA-256 over ~40 characters, no syscall,
                # roughly three orders of magnitude below the Redis GET that
                # produced tenant_id above.
                try:
                    from storage.tenant_store import _hash_key
                    request.state.api_key_hash = _hash_key(api_key)
                except Exception:
                    request.state.api_key_hash = ""

            except Exception:
                _record_auth_failure(client_ip)
                return JSONResponse(
                    status_code=403,
                    content={"error": "Invalid API key"},
                )

        _clear_auth_failures(client_ip)
        return await call_next(request)


def _extract_api_key(request: Request) -> str | None:
    """Extract tenant API key from request headers.

    Prefers X-API-Key / X-Tenant-Key to avoid collision with upstream
    proxies like RunPod which consume Authorization: Bearer.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    tenant_key = request.headers.get("X-Tenant-Key")
    if tenant_key:
        return tenant_key.strip()
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


def _validate_key(provided: str, valid_keys: list[str]) -> bool:
    """Validate an API key against the list of valid keys.

    Supports both plaintext keys and SHA-256 hashed keys (prefixed with "sha256:").
    Uses constant-time comparison to prevent timing attacks.
    """
    provided_hash = hashlib.sha256(provided.encode()).hexdigest()

    for valid_key in valid_keys:
        if valid_key.startswith("sha256:"):
            # Compare against stored hash
            stored_hash = valid_key[7:]
            if hmac.compare_digest(provided_hash, stored_hash):
                return True
        else:
            # Compare plaintext with constant-time comparison
            if hmac.compare_digest(provided, valid_key):
                return True

    return False


def get_tenant_from_request(request: Request) -> str:
    """Extract tenant ID from request state (set by AuthMiddleware).

    This is a FastAPI dependency function for use with Depends().
    """
    from fastapi import HTTPException

    if not hasattr(request, "state") or not hasattr(request.state, "tenant_id"):
        raise HTTPException(
            status_code=401,
            detail="No valid tenant API key provided. Use X-API-Key header."
        )

    tenant_id = request.state.tenant_id
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid tenant context. Please check your API key."
        )

    return tenant_id


def require_tenant_access(tenant_id: str, request: Request) -> None:
    """Authorize access to a tenant-scoped resource identified in the path.

    Closes IDOR / broken object-level authorization: a tenant-scoped API key
    may only act on its own tenant_id. Master/global keys (validated against
    cfg.auth.api_keys) leave request.state.tenant_id unset and remain
    unrestricted, preserving admin-portal cross-tenant management.
    """
    from fastapi import HTTPException

    caller_tenant = getattr(getattr(request, "state", None), "tenant_id", None)
    if caller_tenant and caller_tenant != tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: API key is not authorized for this tenant.",
        )


def verify_tenant_path_access(request: Request, tenant_id: str | None = None) -> None:
    """Router dependency that enforces tenant ownership of a path tenant_id.

    FastAPI resolves ``tenant_id`` from the route's path parameter when one
    exists; routes without a ``{tenant_id}`` path parameter receive ``None``
    and are left unaffected.
    """
    if tenant_id is None:
        return
    require_tenant_access(tenant_id, request)


# ---------------------------------------------------------------------------
# Body-named tenants
#
# Some management routes take the tenant from the request body or query rather
# than from a path parameter or the key (the kill switch, cert registration).
# Nothing checked that name against the caller, so any caller, with or without
# a credential, could act for any tenant. One rule, shared, so the routes that
# need it cannot drift apart.
#
# See docs/specs/killswitch-tenant-scope.md
# ---------------------------------------------------------------------------

SCOPE_ADMIN = "admin"
SCOPE_TENANT = "tenant"


def _is_master_key(api_key: str) -> bool:
    """A global key from auth.api_keys / SHIELD_API_KEYS: an operator key.

    require_tenant_access already treats these as unrestricted; this keeps the
    two answers the same.
    """
    try:
        keys = _config_module.config.auth.api_keys if _config_module.config else []
    except Exception:
        return False
    return bool(keys) and _validate_key(api_key, keys)


def caller_tenant_scope(request: Request, *, unauthenticated_status: int = 401,
                        unauthenticated_detail: str = "",
                        admin_key_unset_detail: str = "") -> tuple:
    """Who is calling: ("admin", None) or ("tenant", tenant_id). Raises otherwise.

    In order:

    * An admin identity (the workload-identity providers: admin key, SPIFFE,
      mTLS, whichever are enabled), or a global master key: any tenant. An
      identity that itself carries a tenant (an mTLS agent, the tenant_key
      provider) is confined to that tenant instead; it identifies one of the
      tenant's workloads, not an operator.
    * A signed-in portal user: their session's tenant.
    * A tenant API key: its tenant.

    Fails closed: a key that cannot be resolved because the store is down is a
    503, never "act for whichever tenant the body names".
    """
    from fastapi import HTTPException
    from core.workload_identity import enabled_providers, resolve_workload_identity

    identity = resolve_workload_identity(request)
    if identity is not None:
        claims = identity.claims if isinstance(identity.claims, dict) else {}
        if claims.get("tenant_id"):
            return SCOPE_TENANT, str(claims["tenant_id"])
        request.state.workload_identity = identity
        return SCOPE_ADMIN, None

    principal = portal_principal(request)
    if principal and principal.get("tenant_id"):
        return SCOPE_TENANT, principal["tenant_id"]

    state_tenant = getattr(getattr(request, "state", None), "tenant_id", None)
    if state_tenant:
        return SCOPE_TENANT, state_tenant

    api_key = _extract_api_key(request)
    if api_key:
        if _is_master_key(api_key):
            return SCOPE_ADMIN, None
        try:
            from storage.tenant_store import resolve_tenant_by_api_key
            tenant = resolve_tenant_by_api_key(api_key)
        except Exception as exc:
            logger.warning("could not resolve API key (%s)", exc.__class__.__name__)
            tenant, degraded = None, True
        else:
            degraded = not tenant and _store_is_degraded()
        if tenant:
            return SCOPE_TENANT, tenant
        if degraded:
            raise HTTPException(
                status_code=503,
                detail="Cannot verify the API key (key store unavailable).")

    if admin_key_unset_detail:
        names = [p.name for p in enabled_providers()]
        if "admin_key" in names and not os.environ.get("SHIELD_ADMIN_KEY", ""):
            raise HTTPException(status_code=500, detail=admin_key_unset_detail)
    raise HTTPException(
        status_code=unauthenticated_status,
        detail=unauthenticated_detail or "admin identity or tenant API key required")


def authorized_tenant_scope(request: Request, claimed_tenant_id: str = "") -> tuple:
    """The tenant this request may act for, and how: (tenant_id, scope).

    An admin identity acts for the tenant it names, and must name one (400). A
    tenant caller acts for its own tenant: the name may be omitted, and naming
    a different one is a 403.
    """
    from fastapi import HTTPException

    claimed = (claimed_tenant_id or "").strip()
    scope, tenant = caller_tenant_scope(request)
    if scope == SCOPE_ADMIN:
        if not claimed:
            raise HTTPException(status_code=400,
                                detail="tenant_id is required for an admin caller")
        return claimed, scope
    if claimed and claimed != tenant:
        raise HTTPException(
            status_code=403,
            detail="tenant mismatch: this credential is not authorized for that tenant")
    return tenant, scope


# ---------------------------------------------------------------------------
# Registry write scope
#
# A tenant key resolves to a tenant and nothing else, so the credential an
# agent must hold to be guarded is also the credential that can rewrite the
# agent registry and grant that agent every tool. This is the enforcement half
# of that split: `runtime` keys may be guarded, `admin` keys may write.
#
# Lives here rather than in a route module because six different routes across
# three routers reach a registry write, and a control that covers five of them
# is a bypass with a changelog entry.
#
# See docs/spec-registry-write-authorization.md
# ---------------------------------------------------------------------------

MODE_OFF = "off"
MODE_WARN = "warn"
MODE_ENFORCE = "enforce"
REGISTRY_WRITE_MODES = (MODE_OFF, MODE_WARN, MODE_ENFORCE)

_SANDBOX_TENANT_ID = "test-tenant-001"


def registry_write_mode() -> str:
    """off | warn | enforce, read from the PROCESS and never from the request.

    An unrecognised value reads as `off`: a typo in a deploy config must not
    silently enable a control that refuses traffic, nor silently disable one an
    operator believes is on. `off` matches the documented default.
    """
    import os
    mode = (os.environ.get("SHIELD_REGISTRY_WRITE_SCOPE", MODE_OFF) or MODE_OFF).strip().lower()
    return mode if mode in REGISTRY_WRITE_MODES else MODE_OFF


def _store_is_degraded() -> bool:
    """True when Redis is configured but unreachable.

    Matters because the in-memory fallback answers every scope lookup with
    None. Without this check a Redis outage would present as "every key in your
    estate is suddenly unscoped", which under `enforce` is a total registry
    outage reported as an authorization failure.
    """
    import os
    try:
        from storage import tenant_store as ts
        configured = bool(os.environ.get("REDIS_URL", "").strip()
                          or os.environ.get("UPSTASH_REDIS_REST_URL", "").strip())
        if not configured:
            return False        # in-memory IS the intended store here
        ts._get_redis()         # force lazy init so the flag means something
        return not ts._redis_available
    except Exception:
        return True


def caller_key_scope(request) -> "tuple":
    """(scope, resolved). resolved=False means the scope could not be read.

    Prefers the hash the auth middleware stashed. Falling back to the
    X-API-Key header covers SHIELD_AUTH_ENABLED being off; it must never be
    the only source, or every Authorization: Bearer caller is silently exempt
    from whatever is built on this.
    """
    try:
        from storage.tenant_store import key_scope, key_scope_by_hash
        key_hash = getattr(getattr(request, "state", None), "api_key_hash", "") or ""
        if key_hash:
            return key_scope_by_hash(key_hash), True
        raw = (request.headers.get("X-API-Key") or "").strip()
        if raw:
            return key_scope(raw), True
        return None, True       # no credential at all; other layers 401 first
    except Exception:
        return None, False


def require_registry_write(request, tenant_id: str = "",
                           action: str = "write the agent registry") -> None:
    """Refuse a registry write by a key that is not admin-scoped.

    No-op under `off`. Under `warn` every write proceeds and a non-admin write
    is recorded, which is the preflight: it names the callers `enforce` would
    break before it breaks them. Under `enforce` only an admin-scoped key
    writes — unscoped legacy keys included, which is the whole point, since
    every key in existence today is unscoped.
    """
    from fastapi import HTTPException

    mode = registry_write_mode()
    if mode == MODE_OFF:
        return

    # Passed explicitly by callers that resolved it themselves: routes reached
    # with SHIELD_AUTH_ENABLED off never have request.state.tenant_id set, and
    # the sandbox exemption below has to work there too.
    # A signed-in human is decided by their groups, not by a key scope. Two
    # notions of "may administer" now exist and they must not become two
    # different answers — an administrator who signs in should be able to do
    # what an admin-scoped key can do, and a non-administrator should be
    # refused exactly like a runtime key.
    principal = portal_principal(request)
    if principal is not None:
        if principal.get("is_admin"):
            return
        if mode == MODE_WARN:
            _record_scope_warning(request, principal.get("tenant_id", ""),
                                  "user:not-admin", action)
            return
        raise HTTPException(
            status_code=403,
            detail=(f"{principal.get('email') or principal.get('sub')} is "
                    f"signed in but is not a portal administrator, so cannot "
                    f"{action}."),
        )

    tenant_id = (tenant_id
                 or getattr(getattr(request, "state", None), "tenant_id", "")
                 or "")

    # The zero-setup quickstart registers an agent in a throwaway tenant. A
    # sandbox that requires a key-minting ceremony is a quickstart nobody
    # finishes, and nothing of value lives in this one tenant.
    if tenant_id == _SANDBOX_TENANT_ID:
        return

    scope, resolved = caller_key_scope(request)

    if mode == MODE_ENFORCE and (not resolved or _store_is_degraded()):
        # Fail CLOSED, and say which it is. A refused write is recoverable by
        # retrying; a wrongly-allowed one is a permanent grant nobody revisits.
        raise HTTPException(
            status_code=503,
            detail="Cannot verify API key scope (key store unavailable). "
                   "Registry writes are refused while "
                   "SHIELD_REGISTRY_WRITE_SCOPE=enforce.",
        )

    if scope == "admin":
        return

    if mode == MODE_WARN:
        _record_scope_warning(request, tenant_id, scope, action)
        return

    raise HTTPException(
        status_code=403,
        detail=(f"This API key is scoped {scope!r} and cannot {action}. "
                f"Use an admin-scoped key. "
                f"(SHIELD_REGISTRY_WRITE_SCOPE=enforce)")
        if scope else
        (f"This API key has no scope and cannot {action} while "
         f"SHIELD_REGISTRY_WRITE_SCOPE=enforce. Mint an admin-scoped key "
         f"(POST /v1/admin/tenants/{{tenant}}/api-keys with scope=admin)."),
    )


def _record_scope_warning(request, tenant_id: str, scope, action: str) -> None:
    """Warn mode's only output, and the thing the rollout procedure reads.

    Never raises: a failure to record a warning must not fail a write that
    `warn` has already decided to allow.
    """
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(
            action="registry_write_scope_warning",
            actor=f"tenant:{tenant_id}",
            tenant_id=tenant_id,
            source_ip=(request.client.host if getattr(request, "client", None) else ""),
            metadata={"scope": scope or "unscoped", "attempted": action,
                      "path": str(getattr(request, "url", "")),
                      "would_be_refused_under_enforce": True},
        )
    except Exception:
        logger.warning(
            "registry write by %s-scoped key for tenant %s (%s) — would be "
            "refused under SHIELD_REGISTRY_WRITE_SCOPE=enforce",
            scope or "un", tenant_id, action)


# ---------------------------------------------------------------------------
# Constrained self-registration
#
# Scoping keys answers "may this credential write the registry at all". This
# answers the softer question underneath it: a developer should be able to run
# one command and see their agent appear, without a ticket, and without being
# able to grant it anything.
#
# The enforcement already exists. _registry_agent_status() blocks any agent
# whose status is not "active", so an entry written as "pending" is inert with
# no new code in the guard path. What was missing was a reason for anything to
# be written that way.
# ---------------------------------------------------------------------------

SELF_REGISTER_ON = "on"
SELF_REGISTER_PENDING = "pending"
SELF_REGISTER_OFF = "off"
SELF_REGISTER_MODES = (SELF_REGISTER_ON, SELF_REGISTER_PENDING, SELF_REGISTER_OFF)

# Everything a non-admin caller must not be able to give itself. Grants only —
# name, description, owner and environments are descriptive and survive, which
# is what makes the pending entry worth reviewing rather than an empty shell.
_GRANT_FIELDS = {
    "tools": list,
    "role_permissions": dict,
    "agent_permissions": dict,
    "allowed_resources": list,
}


def self_register_mode() -> str:
    """on | pending | off. Unrecognised reads as `on`, the documented default."""
    import os
    mode = (os.environ.get("SHIELD_REGISTRY_SELF_REGISTER", SELF_REGISTER_ON)
            or SELF_REGISTER_ON).strip().lower()
    return mode if mode in SELF_REGISTER_MODES else SELF_REGISTER_ON


def constrain_self_registration(request, tenant_id: str, entry: dict) -> dict:
    """Return the entry to store, stripped of self-granted permissions.

    CREATION ONLY. An update to an existing agent is governed by the write
    scope, not by this: demoting a live agent to pending because someone
    renamed it would be an outage caused by a governance feature.

    Raises 403 under `off`.
    """
    from fastapi import HTTPException

    mode = self_register_mode()
    if mode == SELF_REGISTER_ON:
        return entry

    tenant_id = (tenant_id
                 or getattr(getattr(request, "state", None), "tenant_id", "")
                 or "")
    if tenant_id == _SANDBOX_TENANT_ID:
        return entry

    scope, _resolved = caller_key_scope(request)
    if scope == "admin":
        return entry

    if mode == SELF_REGISTER_OFF:
        raise HTTPException(
            status_code=403,
            detail="Self-registration is disabled "
                   "(SHIELD_REGISTRY_SELF_REGISTER=off). An administrator must "
                   "register this agent.",
        )

    # pending: the declaration is kept, every grant in it is not.
    out = dict(entry)
    out["status"] = "pending"
    for field, kind in _GRANT_FIELDS.items():
        out[field] = kind()
    out["require_resource_scope"] = False
    out["self_registered"] = True       # why this is pending, for the reviewer
    return out


# ---------------------------------------------------------------------------
# Portal sessions as a caller identity
#
# A tenant API key answers "which tenant". A portal session answers "which
# human", which is what makes an administrative action attributable to a person
# rather than to a shared credential.
#
# Admin plane only. Nothing on the guard path reads a session.
# ---------------------------------------------------------------------------

PORTAL_COOKIE_NAME = "shield_portal_session"
# Admin-operator SSO session cookie (core/admin_sessions). Distinct from the
# tenant portal cookie: an operator is not a tenant, and the two must never be
# interchangeable.
ADMIN_COOKIE_NAME = "shield_admin_session"


def admin_principal(request):
    """The signed-in platform OPERATOR behind this request, or None.

    Mirrors portal_principal for the admin plane, cached on a distinct
    request.state slot. An admin session is NOT tenant-scoped.
    """
    state = getattr(request, "state", None)
    if state is not None and hasattr(state, "_admin_principal"):
        return state._admin_principal

    principal = None
    try:
        session_id = ""
        cookies = getattr(request, "cookies", None)
        if cookies:
            session_id = cookies.get(ADMIN_COOKIE_NAME, "") or ""
        if session_id:
            from storage.admin_sessions import get_session, touch_session
            record = get_session(session_id)
            if record:
                touch_session(session_id)
                principal = {
                    "kind": "admin_operator",
                    "sub": record.get("sub", ""),
                    "email": record.get("email", ""),
                    "name": record.get("name", ""),
                    "roles": list(record.get("roles") or []),
                    "issuer": record.get("issuer", ""),
                    "auth_time": record.get("auth_time"),
                }
    except Exception as e:
        logger.debug("admin session lookup failed: %s", e)
        principal = None

    if state is not None:
        state._admin_principal = principal
    return principal


def portal_principal(request):
    """The signed-in human behind this request, or None.

    Cached on request.state for the life of the request: _require_tenant is
    called by two dozen handlers and some call it more than once, and a session
    lookup is a store read.

    Resolution is deliberately cookie-first. A browser that still holds a
    tenant API key in localStorage from before SSO was enabled would otherwise
    keep acting as that key after the user signs in, and every action would
    stay attributed to the tenant — the exact problem this is here to fix.
    """
    state = getattr(request, "state", None)
    if state is not None and hasattr(state, "_portal_principal"):
        return state._portal_principal

    principal = None
    try:
        session_id = ""
        cookies = getattr(request, "cookies", None)
        if cookies:
            session_id = cookies.get(PORTAL_COOKIE_NAME, "") or ""
        if session_id:
            from storage.portal_sessions import get_session, touch_session
            record = get_session(session_id)
            if record:
                touch_session(session_id)
                principal = {
                    "kind": "user",
                    "tenant_id": record.get("tenant_id", ""),
                    "sub": record.get("sub", ""),
                    "email": record.get("email", ""),
                    "name": record.get("name", ""),
                    "is_admin": bool(record.get("is_admin")),
                    "issuer": record.get("issuer", ""),
                }
    except Exception as e:
        # A broken session store must not 500 every portal request. The API key
        # path below is exactly as trustworthy as it was before sessions
        # existed, so falling through to it is the safe failure.
        logger.debug("portal session lookup failed: %s", e)
        principal = None

    if state is not None:
        state._portal_principal = principal
    return principal


def require_portal_admin(request) -> None:
    """Refuse a signed-in human who is not an administrator.

    Only meaningful for a session; a key-authenticated caller is governed by
    its scope instead. Returns quietly when there is no session at all, so
    callers can layer this over the existing key checks.
    """
    from fastapi import HTTPException

    principal = portal_principal(request)
    if principal is None or principal.get("is_admin"):
        return
    raise HTTPException(
        status_code=403,
        detail=f"{principal.get('email') or principal.get('sub')} is signed in "
               f"but is not a portal administrator for this tenant.",
    )


def audit_actor(request, tenant_id: str = "") -> str:
    """Who to record for an administrative action.

    `user:{sub}` when a human is signed in, `tenant:{id}` otherwise.

    The tenant form is what every record carries today, and it answers "which
    organisation" rather than "who" — which is why an access review could not
    say who granted an agent its tools. This upgrades that answer wherever a
    session is present and changes nothing where one is not.

    The subject, not the email: an email can be reassigned inside a directory
    and an audit trail that says dana@acme.com years later may mean a different
    person. The email is recorded alongside, as metadata, for legibility.
    """
    principal = portal_principal(request)
    if principal and principal.get("sub"):
        return f"user:{principal['sub']}"
    tenant_id = (tenant_id
                 or getattr(getattr(request, "state", None), "tenant_id", "")
                 or "")
    return f"tenant:{tenant_id}"


def audit_actor_metadata(request) -> dict:
    """Legible detail about the actor, for the audit record's metadata.

    Empty for a key-authenticated caller. An empty field is honest; a guessed
    one is not, and a reviewer cannot tell a guess from a fact after the fact.
    """
    principal = portal_principal(request)
    if not principal:
        return {"actor_kind": "api_key"}
    return {
        "actor_kind": "user",
        "actor_email": principal.get("email", ""),
        "actor_name": principal.get("name", ""),
        "actor_issuer": principal.get("issuer", ""),
    }


def acting_user_sub(request) -> str:
    """The signed-in subject, or "" when a credential is acting.

    Used for created_by/updated_by on records. Deliberately empty rather than
    falling back to the tenant: "created_by: tenant:acme" on every row looks
    like attribution while carrying no information, and it would make the rows
    that DO name a person harder to spot.
    """
    principal = portal_principal(request)
    return f"user:{principal['sub']}" if principal and principal.get("sub") else ""


def admin_actor(request) -> str:
    """Who to record for an ADMIN-PLANE action (/v1/admin/*).

    `operator:{sub}` for an SSO operator, `adminkey:{id}` for a named managed
    credential, `adminroot` for the SHIELD_ADMIN_KEY, else `unknown`. This is
    the admin-plane counterpart to audit_actor, which only knows portal humans
    and tenants and never had an admin-key branch — so admin-key actions used to
    log as an opaque hash of the one shared key, identical for every caller.
    """
    operator = admin_principal(request)
    if operator and operator.get("sub"):
        return f"operator:{operator['sub']}"
    ident = getattr(getattr(request, "state", None), "admin_identity", None)
    if isinstance(ident, dict):
        kind = ident.get("kind")
        if kind == "admin_credential":
            return f"adminkey:{ident.get('id', '')}"
        if kind == "admin_root":
            return "adminroot"
    return "unknown"


def require_admin_root_or_operator(request) -> None:
    """Allow only the root SHIELD_ADMIN_KEY or a signed-in operator; refuse a
    managed admin credential.

    Credential administration must not be reachable from a managed credential:
    a minted key that could mint itself more keys or revoke the operator's would
    escalate past its own revocation. Bootstrapping therefore always starts from
    the root secret or an operator session.
    """
    from fastapi import HTTPException

    if admin_principal(request) is not None:
        return
    ident = getattr(getattr(request, "state", None), "admin_identity", None)
    if isinstance(ident, dict) and ident.get("kind") == "admin_root":
        return
    raise HTTPException(
        status_code=403,
        detail="Managing admin credentials requires the root SHIELD_ADMIN_KEY "
               "or a signed-in operator; a managed credential cannot.",
    )


def require_admin_scope(request, operation: str, tenant_id: str = "",
                        *, cross_tenant: bool = False) -> None:
    """Enforce a managed credential's scope for one admin operation.

    Only a managed credential carries a scope. The root key, an SSO operator,
    and a middleware-less mount (no admin_identity on state) are unconstrained
    here — their authority is decided by the gate, not by scope. A credential
    with no scope (scope is None) is full-admin, which is every Task-1
    credential, so this is a no-op for them and fully backward-compatible.

    A scoped credential is allowed iff `operation` is in its operations
    allowlist (or the allowlist is ["*"]) AND, when a tenant_id is given, that
    tenant is in its tenants allowlist (empty tenants = all tenants, "*" = all).

    `cross_tenant=True` marks an endpoint that spans every tenant (the dashboard,
    an unfiltered global audit). A credential restricted to specific tenants
    (a non-empty tenants allowlist without "*") is refused such an endpoint —
    otherwise a tenant-scoped partner key could read every tenant through it.
    """
    from fastapi import HTTPException

    ident = getattr(getattr(request, "state", None), "admin_identity", None)
    if not (isinstance(ident, dict) and ident.get("kind") == "admin_credential"):
        return
    scope = ident.get("scope")
    if not scope:
        return

    operations = scope.get("operations") or []
    if "*" not in operations and operation not in operations:
        raise HTTPException(
            status_code=403,
            detail=f"this admin credential is not scoped for {operation}")

    tenants = scope.get("tenants") or []
    restricted_to_tenants = bool(tenants) and "*" not in tenants
    if cross_tenant and restricted_to_tenants:
        raise HTTPException(
            status_code=403,
            detail="this admin credential is restricted to specific tenants and "
                   "cannot use a cross-tenant endpoint")
    if tenant_id and restricted_to_tenants and tenant_id not in tenants:
        raise HTTPException(
            status_code=403,
            detail=f"this admin credential is not scoped for tenant {tenant_id}")
