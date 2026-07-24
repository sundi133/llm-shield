"""Provider registry + resolver for workload identity.

Enabled providers and their order come from SHIELD_WORKLOAD_IDENTITY_PROVIDERS
(comma list). The default reproduces the legacy gate's behavior — accept an
admin key OR a SPIFFE identity — and adds mTLS (a no-op unless MTLSMiddleware
validated one).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from starlette.requests import Request

from core.workload_identity.base import WorkloadIdentity
from core.workload_identity.providers import (
    AdminKeyProvider,
    MTLSProvider,
    SpiffeProvider,
)

logger = logging.getLogger("votal.workload_identity")

# name -> provider factory
_REGISTRY = {
    "admin_key": AdminKeyProvider,
    "spiffe": SpiffeProvider,
    "mtls": MTLSProvider,
}

# Legacy-preserving default: admin key OR SPIFFE (mTLS added, inert unless present).
_DEFAULT = "admin_key,spiffe,mtls"


def enabled_providers() -> list:
    """Instantiate the configured providers in order.

    Unknown names are logged and skipped. If the list resolves empty (all
    unknown), fall back to admin_key so issuance is never left ungated by a typo.
    """
    raw = os.environ.get("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", _DEFAULT)
    names = [n.strip() for n in raw.split(",") if n.strip()]
    providers = []
    for n in names:
        factory = _REGISTRY.get(n)
        if factory is None:
            logger.warning("unknown workload-identity provider %r — skipping", n)
            continue
        providers.append(factory())
    if not providers:
        logger.warning("no valid workload-identity providers configured — falling back to admin_key")
        providers = [AdminKeyProvider()]
    return providers


def resolve_workload_identity(request: Request) -> Optional[WorkloadIdentity]:
    """First enabled provider to verify wins; None if none do.

    A provider that raises is treated as no-match — one broken provider can
    neither 500 the endpoint nor bypass the gate.
    """
    for provider in enabled_providers():
        try:
            identity = provider.verify(request)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("workload-identity provider %r errored: %s", getattr(provider, "name", "?"), exc)
            identity = None
        if identity is not None:
            return identity
    return None
