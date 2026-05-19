"""AI model registry routes — weights, configs, fine-tunes, adapters."""

from core.artifacts import ArtifactKind
from api.routes_artifacts_common import build_registry_router

router = build_registry_router(
    ArtifactKind.MODEL,
    prefix="/v1/shield/models",
    tag="model-registry",
)
