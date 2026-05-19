"""Enterprise feature flags — all disabled by default.

Enable features by setting environment variables:

    SHIELD_ENABLE_KILLSWITCH=true       — Tool kill switch
    SHIELD_ENABLE_DECISION_AUDIT=true   — Runtime decision audit trail
    SHIELD_ENABLE_WEBHOOKS=true         — Webhook event notifications
    SHIELD_ENABLE_TAINT_TRACKING=true   — Data taint tracking across tool chains
    SHIELD_ENABLE_GOAL_DRIFT=true       — Goal drift detection
    SHIELD_ENABLE_CERT_IDENTITY=true    — Certificate-based agent identity
    SHIELD_ENABLE_ARTIFACT_REGISTRY=true        — Unified artifact catalog APIs
    SHIELD_ENABLE_ARTIFACT_ENFORCEMENT=true     — Runtime resolver blocks revoked/unapproved artifacts

Or enable all at once:
    SHIELD_ENABLE_ENTERPRISE=true       — Enables all enterprise features
"""

import os


def _is_enabled(key: str) -> bool:
    """Check if a feature flag is enabled."""
    if os.environ.get("SHIELD_ENABLE_ENTERPRISE", "").lower() in ("true", "1", "yes"):
        return True
    return os.environ.get(key, "").lower() in ("true", "1", "yes")


KILLSWITCH_ENABLED = _is_enabled("SHIELD_ENABLE_KILLSWITCH")
DECISION_AUDIT_ENABLED = _is_enabled("SHIELD_ENABLE_DECISION_AUDIT")
WEBHOOKS_ENABLED = _is_enabled("SHIELD_ENABLE_WEBHOOKS")
TAINT_TRACKING_ENABLED = _is_enabled("SHIELD_ENABLE_TAINT_TRACKING")
GOAL_DRIFT_ENABLED = _is_enabled("SHIELD_ENABLE_GOAL_DRIFT")
CERT_IDENTITY_ENABLED = _is_enabled("SHIELD_ENABLE_CERT_IDENTITY")
ARTIFACT_REGISTRY_ENABLED = _is_enabled("SHIELD_ENABLE_ARTIFACT_REGISTRY")
ARTIFACT_ENFORCEMENT_ENABLED = _is_enabled("SHIELD_ENABLE_ARTIFACT_ENFORCEMENT")
