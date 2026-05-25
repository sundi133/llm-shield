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


class MTLSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Only run if mTLS is enabled
        if not os.environ.get("SHIELD_MTLS_ENABLED", "").lower() in ("true", "1", "yes"):
            return await call_next(request)

        # Check for client cert fingerprint in header (reverse proxy mode)
        fingerprint = request.headers.get("X-Client-Cert-Fingerprint", "").strip()
        cert_header_name = os.environ.get(
            "SHIELD_MTLS_CERT_HEADER", "X-Forwarded-Client-Cert"
        )

        if not fingerprint:
            # Try to extract from full cert header
            cert_pem = request.headers.get(cert_header_name, "").strip()
            if cert_pem:
                fingerprint = _compute_cert_fingerprint(cert_pem)

        if fingerprint:
            tenant_id = getattr(request.state, "tenant_id", "") or ""
            identity = _resolve_mtls_identity(tenant_id, fingerprint)
            if identity:
                request.state.mtls_identity = identity

        return await call_next(request)


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


def _resolve_mtls_identity(tenant_id: str, fingerprint: str) -> dict | None:
    """Resolve a cert fingerprint to an agent identity via cert_registry."""
    try:
        from guardrails.agentic.identity.cert_registry import (
            resolve_agent_by_cert,
            get_agent_trust,
        )

        agent_key = resolve_agent_by_cert(tenant_id, fingerprint)
        if not agent_key:
            logger.debug(f"mTLS: no agent registered for fingerprint {fingerprint[:16]}...")
            return None

        trust = get_agent_trust(tenant_id, agent_key)
        return {
            "agent_key": agent_key,
            "fingerprint": fingerprint,
            "trust_level": trust.get("trust_level", "high"),
            "identity_method": "mtls",
            "tenant_id": tenant_id,
        }
    except Exception as e:
        logger.warning(f"mTLS identity resolution failed: {e}")
        return None
