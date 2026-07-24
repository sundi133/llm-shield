"""Built-in workload-identity providers.

Each wraps an attestation method that already exists in the request path:
  - admin_key : the X-Admin-Key hmac check (unchanged from the legacy gate)
  - spiffe    : request.state.spiffe_identity, set by SPIFFEMiddleware
  - mtls      : request.state.mtls_identity, set by MTLSMiddleware

The spiffe/mtls providers only read identity the middleware already validated;
they add no verification of their own (and inherit its guarantees — see the
SPIFFE X.509 hardening note in docs/spec-modular-workload-identity.md).
"""

from __future__ import annotations

import hmac
import os
from typing import Optional

from starlette.requests import Request

from core.workload_identity.base import WorkloadIdentity


class AdminKeyProvider:
    """Shared-secret admin key via the X-Admin-Key header. trust: medium."""

    name = "admin_key"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        admin_key = os.environ.get("SHIELD_ADMIN_KEY", "")
        if not admin_key:
            return None  # unconfigured -> cannot verify; registry handles the 500 signal
        provided = request.headers.get("X-Admin-Key", "").strip()
        if provided and hmac.compare_digest(provided, admin_key):
            return WorkloadIdentity(provider=self.name, subject="admin-key", trust_level="medium")
        return None


class SpiffeProvider:
    """SPIFFE identity already validated by SPIFFEMiddleware. trust: high*."""

    name = "spiffe"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        ident = getattr(request.state, "spiffe_identity", None) if hasattr(request, "state") else None
        if not ident:
            return None
        subject = ident.get("user_sub") or ident.get("agent_id") or "spiffe-workload"
        return WorkloadIdentity(
            provider=self.name,
            subject=subject,
            trust_level=ident.get("trust_level", "high"),
            claims=dict(ident),
        )


class MTLSProvider:
    """mTLS identity already validated by MTLSMiddleware. trust: high."""

    name = "mtls"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        ident = getattr(request.state, "mtls_identity", None) if hasattr(request, "state") else None
        if not ident:
            return None
        subject = ident.get("subject") or ident.get("cn") or ident.get("agent_id") or "mtls-workload"
        return WorkloadIdentity(
            provider=self.name,
            subject=subject,
            trust_level=ident.get("trust_level", "high"),
            claims=dict(ident),
        )
