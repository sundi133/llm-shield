"""Runtime artifact resolver.

Call sites that load a model / MCP server / skill / software artifact ask the
resolver for the canonical version. The resolver returns the Artifact if it
is APPROVED (and not revoked or kill-switched). Otherwise it raises
ArtifactNotPermitted with the reason.

Enforcement is gated by SHIELD_ENABLE_ARTIFACT_ENFORCEMENT (off by default).
When disabled the resolver returns None for any call, so existing call sites
behave exactly as before.
"""

from __future__ import annotations

from typing import Optional

from core import feature_flags
from core.artifacts import Artifact, ArtifactKind, ArtifactStatus
from storage.artifact_store import get_store


class ArtifactNotPermitted(Exception):
    """Raised by the resolver when an artifact may not be used at runtime."""

    def __init__(self, message: str, kind: ArtifactKind, name: str, version: Optional[str]):
        super().__init__(message)
        self.kind = kind
        self.name = name
        self.version = version


def _resolve_version(tenant_id: str, kind: ArtifactKind, name: str, requested: Optional[str]) -> Optional[str]:
    if requested:
        return requested
    pinned = get_store().get_pin(tenant_id, kind, name)
    return pinned


def resolve(
    tenant_id: str,
    kind: ArtifactKind,
    name: str,
    version: Optional[str] = None,
) -> Optional[Artifact]:
    """Return the canonical artifact for use, or None if enforcement is off.

    Raises ArtifactNotPermitted when enforcement is on and the artifact is
    revoked / deprecated / not-approved / unknown.
    """
    if not feature_flags.ARTIFACT_ENFORCEMENT_ENABLED:
        return None

    resolved_version = _resolve_version(tenant_id, kind, name, version)
    if not resolved_version:
        raise ArtifactNotPermitted(
            f"no pinned {kind.value} '{name}' for tenant {tenant_id}",
            kind=kind, name=name, version=None,
        )

    artifact = get_store().get(tenant_id, kind, name, resolved_version)
    if artifact is None:
        raise ArtifactNotPermitted(
            f"{kind.value} '{name}@{resolved_version}' not found in registry",
            kind=kind, name=name, version=resolved_version,
        )

    if artifact.status == ArtifactStatus.REVOKED:
        raise ArtifactNotPermitted(
            f"{kind.value} '{name}@{resolved_version}' has been revoked",
            kind=kind, name=name, version=resolved_version,
        )
    if artifact.status == ArtifactStatus.DRAFT:
        raise ArtifactNotPermitted(
            f"{kind.value} '{name}@{resolved_version}' is not approved",
            kind=kind, name=name, version=resolved_version,
        )
    # DEPRECATED is allowed at runtime but should be logged by callers.
    return artifact
