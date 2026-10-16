"""mTLS middleware -- extracts client certificate identity from requests.

Supports two modes:
1. Reverse proxy mode: reads cert from X-Forwarded-Client-Cert (Envoy/Istio)
   or X-Client-Cert-Fingerprint header
2. Direct TLS: reads cert from the TLS connection (when uvicorn terminates TLS)

Sets request.state.mtls_identity on successful validation.
Additive -- does not replace existing auth flows.

On-prem friendly: no cloud dependencies, works with any CA.
"""

from __future__ import annotations

import hashlib
import logging
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("votal.mtls_mw")

from core.proxy_trust import trusted_proxy_only, peer_is_trusted

_warned_unguarded = False


class MTLSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Only run if mTLS is enabled
        if not os.environ.get("SHIELD_MTLS_ENABLED", "").lower() in ("true", "1", "yes"):
            return await call_next(request)

        # SECURITY: this middleware derives identity from a header-carried cert by
        # fingerprint — it does NOT prove possession of the private key (a cert is
        # public). That is only safe when a trusted proxy (Envoy) performed real
        # mTLS and injected the header. Gate header-derived identity to that proxy.
        if trusted_proxy_only():
            if not peer_is_trusted(request):
                return await call_next(request)
        else:
            global _warned_unguarded
            if not _warned_unguarded:
                _warned_unguarded = True
                logger.warning(
                    "SHIELD_MTLS_ENABLED without SHIELD_TRUSTED_PROXY_ONLY: mTLS "
                    "identity is derived from a header-carried cert fingerprint "
                    "with no proof-of-possession and is spoofable. Set "
                    "SHIELD_TRUSTED_PROXY_ONLY=true + SHIELD_TRUSTED_PROXY_IPS to "
                    "the proxy that terminates mTLS."
                )

        # The forwarded certificate (reverse proxy mode): the whole certificate
        # (Envoy XFCC, nginx URL-encoded, or raw PEM), or only its fingerprint.
        # The certificate is preferred: it can be checked for expiry, and can
        # be matched through the tenant's CA anchors and rules, not only pins.
        cert_header_name = os.environ.get(
            "SHIELD_MTLS_CERT_HEADER", "X-Forwarded-Client-Cert"
        )
        cert_value = request.headers.get(cert_header_name, "").strip()
        fingerprint = request.headers.get("X-Client-Cert-Fingerprint", "").strip()

        if cert_value or fingerprint:
            tenant_id = _tenant_for(request)
            identity = _resolve_mtls_identity(tenant_id, fingerprint, cert_value)
            if identity:
                request.state.mtls_identity = identity

        return await call_next(request)


def _tenant_for(request: Request) -> str:
    """The caller's tenant. This middleware runs before ShieldMiddleware, which
    is what normally sets request.state.tenant_id, so it was always empty here
    and no certificate ever resolved. Resolve it from the API key, through the
    same cache ShieldMiddleware uses (docs/specs/agent-cert-identity.md)."""
    tenant_id = getattr(request.state, "tenant_id", "") or ""
    if tenant_id:
        return tenant_id
    try:
        from core.middleware import _extract_api_key, _get_cached_tenant
        api_key = _extract_api_key(request)
        if api_key:
            return _get_cached_tenant(api_key)[0] or ""
    except Exception:
        logger.debug("mTLS: tenant lookup failed", exc_info=True)
    return ""


def _compute_cert_fingerprint(cert_pem: str) -> str:
    """Compute SHA-256 fingerprint of a PEM certificate."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        )
        return cert.fingerprint(hashes=hashlib.sha256()).hex()
    except Exception:
        # Fallback: hash the raw PEM
        return hashlib.sha256(cert_pem.encode()).hexdigest()


def _resolve_mtls_identity(tenant_id: str, fingerprint: str, cert_value: str = "") -> dict | None:
    """The agent a forwarded certificate (or its fingerprint) identifies, via a
    pinned registration or the tenant's CA anchors and rules
    (core/cert_identity.py). None when it identifies nobody."""
    if not tenant_id:
        return None
    try:
        from core import cert_identity
        found = None
        if cert_value:
            found = cert_identity.verify_forwarded(tenant_id, cert_value)
        if found is None and fingerprint:
            found = cert_identity.verify_fingerprint(tenant_id, fingerprint)
        if not found:
            logger.debug("mTLS: forwarded certificate identifies no agent for %s", tenant_id)
            return None
        return {
            "agent_key": found["agent_key"],
            "fingerprint": found["fingerprint"],
            "trust_level": "high",
            "identity_method": "mtls",
            "verified_by": ("pinned" if found["method"] == "pinned"
                            else f"anchor:{found['anchor_id']}"),
            "rule_id": found.get("rule_id"),
            "tenant_id": tenant_id,
        }
    except Exception as e:
        logger.warning(f"mTLS identity resolution failed: {e}")
        return None
