"""Modular workload-identity providers for agent-token issuance.

Token issuance (`/v1/shield/auth/agent-token`) is gated by a pluggable set of
workload-identity providers instead of a hardcoded admin-key-or-SPIFFE check.
Which providers are enabled — and their order — is config
(`SHIELD_WORKLOAD_IDENTITY_PROVIDERS`), so a deployment without SPIFFE can accept
the identity it *does* have (admin key, mTLS, and later an OIDC service account).

See docs/spec-modular-workload-identity.md.
"""

from core.workload_identity.base import WorkloadIdentity, WorkloadIdentityProvider
from core.workload_identity.registry import (
    enabled_providers,
    resolve_workload_identity,
)

__all__ = [
    "WorkloadIdentity",
    "WorkloadIdentityProvider",
    "enabled_providers",
    "resolve_workload_identity",
]
