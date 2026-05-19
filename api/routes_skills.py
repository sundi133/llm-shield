"""Agent skill registry routes — packaged instructions and helper files."""

from core.artifacts import ArtifactKind
from api.routes_artifacts_common import build_registry_router

router = build_registry_router(
    ArtifactKind.SKILL,
    prefix="/v1/shield/skills",
    tag="skill-registry",
)
