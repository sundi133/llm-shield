"""Middleware that extracts SPIFFE workload identity from requests.

Checks for:
1. SPIFFE JWT SVID in Authorization: Bearer header (when no API key match)
2. SPIFFE X.509 SVID in X-Client-Cert header (from reverse proxy / Envoy)

Sets request.state.spiffe_identity on successful validation.
Additive -- does not replace existing auth flows.
"""

from __future__ import annotations

import logging
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("votal.spiffe_mw")


def _trusted_proxy_only() -> bool:
    """Trust X-Forwarded-Client-Cert only from a configured proxy source."""
    return os.environ.get("SHIELD_TRUSTED_PROXY_ONLY", "").lower() in ("true", "1", "yes")


def _peer_is_trusted(request: Request) -> bool:
    """True if the immediate TCP peer is a configured trusted proxy.

    SHIELD_TRUSTED_PROXY_IPS is a comma list of IPs / CIDRs (e.g. the Envoy
    front door). Empty list in trusted-proxy-only mode trusts nobody (fail closed).
    """
    import ipaddress

    entries = [e.strip() for e in os.environ.get("SHIELD_TRUSTED_PROXY_IPS", "").split(",") if e.strip()]
    if not entries:
        return False
    peer = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


class SPIFFEMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Only run if SPIFFE is enabled
        if not os.environ.get("SHIELD_SPIFFE_ENABLED", "").lower() in ("true", "1", "yes"):
            return await call_next(request)

        # Trust boundary: in trusted-proxy-only mode, ignore client-supplied
        # X-Forwarded-Client-Cert unless the request came from the configured
        # proxy (Envoy). Otherwise a client that reaches Shield directly could
        # spoof the header and impersonate a workload.
        if _trusted_proxy_only() and not _peer_is_trusted(request):
            return await call_next(request)

        # Check for X.509 SVID in client cert header
        cert_header = request.headers.get("X-Client-Cert", "").strip()
        if not cert_header:
            cert_header = request.headers.get("X-Forwarded-Client-Cert", "").strip()

        if cert_header:
            try:
                identity = await self._validate_x509_svid(cert_header, request)
                if identity:
                    request.state.spiffe_identity = identity
            except Exception as e:
                logger.debug(f"SPIFFE X.509 validation skipped: {e}")

        return await call_next(request)

    async def _validate_x509_svid(
        self, cert_pem: str, request: Request
    ) -> dict | None:
        """Validate an X.509 SVID and return identity claims."""
        from core.oauth.spiffe import (
            SPIFFETrustDomain,
            validate_x509_svid,
            spiffe_id_to_identity,
        )

        # Load trust domains from config
        trust_domains = self._get_trust_domains()
        if not trust_domains:
            return None

        tenant_id = getattr(request.state, "tenant_id", "") or ""

        for td in trust_domains.values():
            try:
                spiffe_id = validate_x509_svid(cert_pem, td)
                return spiffe_id_to_identity(spiffe_id, tenant_id)
            except Exception:
                continue

        return None

    @staticmethod
    def _get_trust_domains() -> dict:
        """Load SPIFFE trust domains from environment."""
        from core.oauth.spiffe import SPIFFETrustDomain

        domains = {}
        # Simple env-based config: SHIELD_SPIFFE_TRUST_DOMAIN=domain
        # SHIELD_SPIFFE_TRUST_BUNDLE=/path/to/bundle.pem
        # SHIELD_SPIFFE_JWKS_URI=file:///path/to/jwks.json
        domain = os.environ.get("SHIELD_SPIFFE_TRUST_DOMAIN", "").strip()
        if domain:
            domains[domain] = SPIFFETrustDomain(
                trust_domain=domain,
                jwks_uri=os.environ.get("SHIELD_SPIFFE_JWKS_URI", "").strip(),
                trust_bundle_path=os.environ.get("SHIELD_SPIFFE_TRUST_BUNDLE", "").strip(),
                allowed_workloads=[
                    w.strip()
                    for w in os.environ.get("SHIELD_SPIFFE_ALLOWED_WORKLOADS", "").split(",")
                    if w.strip()
                ],
            )
        return domains
