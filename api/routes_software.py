"""Software artifact registry routes — containers, JARs, npm/PyPI, terraform."""

from core.artifacts import ArtifactKind
from api.routes_artifacts_common import build_registry_router

router = build_registry_router(
    ArtifactKind.SOFTWARE,
    prefix="/v1/shield/artifacts",
    tag="software-registry",
)
