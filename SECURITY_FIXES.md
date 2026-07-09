# Security Fixes

Tracking remediations for the IEMLabs VAPT findings (May 2026).

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 8.4 | Missing security headers | Low | ✅ Fixed |
| 8.5 | Missing HSTS header + force HTTPS | Medium | ✅ Fixed |
| 8.6 | Cookies without Secure/HttpOnly/SameSite | Low | ✅ Fixed |
| 8.8 | Clickjacking / missing X-Frame-Options | Low | ✅ Fixed |

## 8.5 Missing HSTS header + HTTPS enforcement

The `SecurityHeadersMiddleware` (`core/security_headers.py`) sets
`Strict-Transport-Security: max-age=31536000; includeSubDomains` on every
response. It is emitted unconditionally — browsers ignore HSTS received over
plain HTTP (RFC 6797 §8.1), and emitting it always guarantees the header is
present even when the edge proxy's `X-Forwarded-Proto` is unavailable. The
middleware is wired into both the production app (`core/app.py`) and the admin
portal (`admin_app.py`).

**Force HTTPS / redirect HTTP → HTTPS.** `HTTPSRedirectMiddleware`
(`core/security_headers.py`) 308-redirects plain-HTTP requests to HTTPS. It is
proxy aware (honours `X-Forwarded-Proto`, so it never loops behind
`railway-edge`) and exempts health-check / ACME paths. The uvicorn entrypoints
(`handler.py`, `core/app.py`, `admin_app.py`) run with `proxy_headers=True` so
the original scheme is detected correctly behind the TLS-terminating edge.

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HSTS_MAX_AGE` | `31536000` | HSTS max-age in seconds (1 year). |
| `HSTS_INCLUDE_SUBDOMAINS` | `true` | Add `includeSubDomains` directive. |
| `HSTS_PRELOAD` | `false` | Add `preload` directive (see below). |
| `FORCE_HTTPS` | `false` | Redirect HTTP → HTTPS at the app layer. |
| `FORWARDED_ALLOW_IPS` | `*` | Trusted proxy IPs for `X-Forwarded-*`. |

In production (Railway), set `FORCE_HTTPS=true`. TLS is already terminated by
`railway-edge` with a valid managed certificate; keep "redirect HTTP to HTTPS"
enabled at the edge as well so insecure access is fully disabled.

### HSTS preload (optional — only after validation)

Once the site has served HSTS with `max-age` ≥ 31536000, `includeSubDomains`,
and `preload` over HTTPS for **all** subdomains, set `HSTS_PRELOAD=true` and
submit the apex domain at <https://hstspreload.org>. Preload is hard to
reverse, so only do this when every subdomain can serve HTTPS.

### Valid / trusted TLS certificates

Production uses Railway's managed certificate. For on-prem / self-hosted
deployments, terminate TLS at the reverse proxy with a CA-issued certificate
(e.g. Let's Encrypt) and enable the HTTP→HTTPS redirect there too — see the
nginx example in `onprem_installation.md` (`listen 80` → `return 301 https://`
plus the `Strict-Transport-Security` header on the `443` server block).
Setting `FORCE_HTTPS=true` additionally enforces the redirect at the
application layer as defence-in-depth.

Coverage: `tests/test_security_vapt_fixes.py::TestSecurityHeaders`.
