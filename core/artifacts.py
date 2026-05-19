"""Unified artifact catalog primitives for LLM Shield.

Covers four artifact kinds that all need the same governance treatment:

    model     — AI model weights, configs, fine-tunes, adapters
    mcp       — Model Context Protocol servers
    skill     — Agent skill bundles (instructions + helper files)
    software  — Traditional artifacts (container images, JARs, npm/PyPI, terraform)

The same Pydantic schema and lifecycle (draft → approved → deprecated → revoked)
applies to all four so a single registry, RBAC, audit, and policy story works
across them.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ArtifactKind(str, Enum):
    MODEL = "model"
    MCP = "mcp"
    SKILL = "skill"
    SOFTWARE = "software"


class ArtifactStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class Provenance(BaseModel):
    """Where an artifact came from and how we can verify it."""

    issuer: Optional[str] = None
    build_id: Optional[str] = None
    source_repo: Optional[str] = None
    source_commit: Optional[str] = None
    sbom_uri: Optional[str] = None
    signature: Optional[str] = None
    signature_status: str = "unverified"  # unverified|verified|invalid|absent
    license: Optional[str] = None


class Artifact(BaseModel):
    """A single versioned artifact in the registry."""

    kind: ArtifactKind
    name: str
    version: str
    tenant_id: str
    source_uri: str
    sha256: Optional[str] = None
    provenance: Provenance = Field(default_factory=Provenance)
    status: ArtifactStatus = ArtifactStatus.DRAFT
    scopes: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "unknown"
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    pinned: bool = False  # if True, version is the canonical one for (kind,name)

    @property
    def id(self) -> str:
        return artifact_id(self.tenant_id, self.kind, self.name, self.version)


def artifact_id(tenant_id: str, kind: ArtifactKind | str, name: str, version: str) -> str:
    """Stable identifier used as the storage key."""
    k = kind.value if isinstance(kind, ArtifactKind) else kind
    return f"{tenant_id}:{k}:{name}:{version}"
