"""Security headers middleware for all HTTP responses.

Addresses IEMLabs VAPT findings (May 2026):
  8.4  Missing Security Headers (Low)
  8.5  HSTS                     (Low)
  8.6  No Cookie Validation     (Low)
  8.8  Clickjacking Vulnerable  (Low)

These headers are applied at the application level so they are present
regardless of whether a reverse proxy (nginx, Cloudflare, etc.) is in
front. Duplicate headers from an upstream proxy are harmless — the
browser uses the most restrictive value.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject browser-security headers into every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Clickjacking protection (finding 8.8)
        response.headers["X-Frame-Options"] = "DENY"

        # MIME-type sniffing protection
        response.headers["X-Content-Type-Options"] = "nosniff"

        # CSP frame-ancestors — modern replacement for X-Frame-Options
        # Only set if the response doesn't already carry a CSP header
        # (some routes may set a more specific policy).
        if "content-security-policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "frame-ancestors 'none'; "
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://hcaptcha.com https://*.hcaptcha.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; "
                "frame-src https://hcaptcha.com https://*.hcaptcha.com"
            )

        # HSTS — enforce HTTPS for 1 year, including subdomains (finding 8.5)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Referrer policy — don't leak full URL to third-party origins
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy — disable browser features we don't use
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Deprecated but still respected by some older browsers; 0 disables
        # the built-in XSS filter (CSP is the modern replacement).
        response.headers["X-XSS-Protection"] = "0"

        # Prevent caching of API responses that may contain sensitive data.
        # Static assets served via StaticFiles mount set their own
        # Cache-Control, so this only affects dynamic responses.
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type or "text/event-stream" in content_type:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        # Cookie security (finding 8.6): if any Set-Cookie header is
        # present, ensure it has HttpOnly, Secure, and SameSite flags.
        # This catches cookies set by any downstream handler or framework.
        if "set-cookie" in response.headers:
            raw_cookie = response.headers["set-cookie"]
            parts = [p.strip() for p in raw_cookie.split(";")]
            flags = {p.lower() for p in parts}
            if not any("httponly" in f for f in flags):
                parts.append("HttpOnly")
            if not any("secure" in f for f in flags):
                parts.append("Secure")
            if not any("samesite" in f for f in flags):
                parts.append("SameSite=Strict")
            response.headers["set-cookie"] = "; ".join(parts)

        return response
