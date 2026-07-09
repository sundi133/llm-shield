"""Security headers + HTTPS enforcement middleware for FastAPI/Starlette apps.

Addresses IEMLabs VAPT findings (May 2026):
  - 8.4 Missing X-Content-Type-Options header
  - 8.5 Missing HTTP Strict-Transport-Security (HSTS) header
  - 8.6 Cookie without Secure/HttpOnly flags
  - 8.8 Missing X-Frame-Options / clickjacking protection

The middleware is intentionally dependency-free (pure Starlette) so it can be
added to any FastAPI app without pulling extra packages.

HSTS / HTTPS notes
------------------
The app is deployed behind a TLS-terminating edge proxy (``railway-edge``),
so the application itself usually sees plain ``http`` with the original scheme
carried in the ``X-Forwarded-Proto`` header. Both the HSTS emission and the
HTTP->HTTPS redirect therefore consult ``X-Forwarded-Proto`` so they behave
correctly behind a proxy and do not cause redirect loops.

Environment knobs (all optional, sane defaults):
  HSTS_MAX_AGE            HSTS max-age in seconds (default 31536000 = 1 year)
  HSTS_INCLUDE_SUBDOMAINS "true"/"false" (default true)
  HSTS_PRELOAD            "true"/"false" (default false; only enable after the
                          domain has been validated and submitted to
                          https://hstspreload.org)
  FORCE_HTTPS             "true"/"false" (default false locally). When enabled,
                          plain-HTTP requests are 308-redirected to HTTPS.
"""
from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response


# Default Content-Security-Policy. Kept permissive enough for the bundled
# admin/tenant portals (inline styles, Google Fonts, hCaptcha) while still
# disallowing framing and arbitrary script origins.
_DEFAULT_CSP = (
    "frame-ancestors 'none'; "
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://hcaptcha.com https://*.hcaptcha.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; "
    "frame-src https://hcaptcha.com https://*.hcaptcha.com"
)

# Paths that must stay reachable over plain HTTP (platform health checks /
# ACME HTTP-01 challenges) so we never redirect or break them.
_REDIRECT_EXEMPT_PREFIXES = ("/healthz", "/health", "/.well-known/acme-challenge")


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _request_is_https(request: Request) -> bool:
    """Best-effort original-scheme detection, proxy aware."""
    xfproto = request.headers.get("x-forwarded-proto")
    if xfproto:
        # May be a comma-separated list ("https, http"); the first hop wins.
        return xfproto.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def build_hsts_value(
    max_age: int | None = None,
    include_subdomains: bool | None = None,
    preload: bool | None = None,
) -> str:
    """Construct a Strict-Transport-Security header value from env/args."""
    if max_age is None:
        max_age = int(os.getenv("HSTS_MAX_AGE", "31536000"))
    if include_subdomains is None:
        include_subdomains = _env_bool("HSTS_INCLUDE_SUBDOMAINS", True)
    if preload is None:
        preload = _env_bool("HSTS_PRELOAD", False)

    parts = [f"max-age={max_age}"]
    if include_subdomains:
        parts.append("includeSubDomains")
    # `preload` is only valid alongside includeSubDomains and a long max-age.
    if preload and include_subdomains:
        parts.append("preload")
    return "; ".join(parts)


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Redirect plain-HTTP requests to HTTPS (proxy aware, loop safe).

    Disabled by default so local development over http://localhost keeps
    working. Set FORCE_HTTPS=true (e.g. in the Railway service) to enforce.
    """

    def __init__(self, app, enabled: bool | None = None):
        super().__init__(app)
        self._enabled = _env_bool("FORCE_HTTPS", False) if enabled is None else enabled

    async def dispatch(self, request: Request, call_next):
        if self._enabled and not _request_is_https(request):
            path = request.url.path
            if not path.startswith(_REDIRECT_EXEMPT_PREFIXES):
                https_url = request.url.replace(scheme="https")
                # 308 preserves method + body (unlike 301/302).
                return RedirectResponse(str(https_url), status_code=308)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject standard security headers into every HTTP response."""

    def __init__(self, app, csp: str | None = None, hsts_max_age: int | None = None):
        super().__init__(app)
        self._csp = csp or _DEFAULT_CSP
        self._hsts = build_hsts_value(max_age=hsts_max_age)

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        headers = response.headers

        # 8.8 Clickjacking / framing protection
        headers.setdefault("X-Frame-Options", "DENY")

        # 8.4 MIME sniffing protection
        headers.setdefault("X-Content-Type-Options", "nosniff")

        # Content Security Policy (defence-in-depth, also blocks framing)
        headers.setdefault("Content-Security-Policy", self._csp)

        # 8.5 HTTP Strict Transport Security. Emitted unconditionally: browsers
        # ignore HSTS received over plain HTTP (RFC 6797 sec. 8.1), and emitting
        # it always guarantees the header is present even when the upstream
        # proxy's X-Forwarded-Proto is unavailable/untrusted.
        headers.setdefault("Strict-Transport-Security", self._hsts)

        # Referrer hardening
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # Limit powerful browser features
        headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )

        # Disable legacy XSS auditor (modern guidance: rely on CSP)
        headers.setdefault("X-XSS-Protection", "0")

        # Avoid caching sensitive API/JSON responses
        ct = headers.get("Content-Type", "")
        if "application/json" in ct or "text/event-stream" in ct:
            headers.setdefault("Cache-Control", "no-store")
            headers.setdefault("Pragma", "no-cache")

        # 8.6 Ensure any Set-Cookie carries Secure + HttpOnly + SameSite
        cookie_values = response.headers.getlist("set-cookie")
        if cookie_values:
            del response.headers["set-cookie"]
            for cookie in cookie_values:
                patched = cookie
                low = patched.lower()
                if "httponly" not in low:
                    patched += "; HttpOnly"
                if "secure" not in low:
                    patched += "; Secure"
                if "samesite" not in low:
                    patched += "; SameSite=Strict"
                response.headers["set-cookie"] = patched

        return response
