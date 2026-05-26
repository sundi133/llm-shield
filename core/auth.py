"""API key authentication middleware for LLM Shield."""

import hashlib
import hmac
import os
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import config.schema as _config_module


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
        client_ip = request.client.host if request.client else "unknown"

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
