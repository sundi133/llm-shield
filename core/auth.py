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

        # Admin routes: always require admin key regardless of auth config
        if path.startswith("/v1/admin/"):
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
                    content={"error": "Missing admin key. Use X-Admin-Key header for /v1/admin/* routes."},
                )

            if not hmac.compare_digest(provided, admin_key):
                _record_auth_failure(client_ip)
                return JSONResponse(
                    status_code=403,
                    content={"error": "Invalid admin key"},
                )

            _clear_auth_failures(client_ip)
            return await call_next(request)

        if cfg is None or not cfg.auth.enabled:
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
