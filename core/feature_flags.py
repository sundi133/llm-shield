"""Enterprise feature flags — all disabled by default.

Enable features by setting environment variables:

    SHIELD_ENABLE_KILLSWITCH=true       — Tool kill switch
    SHIELD_ENABLE_DECISION_AUDIT=true   — Runtime decision audit trail
    SHIELD_ENABLE_WEBHOOKS=true         — Webhook event notifications
    SHIELD_ENABLE_TAINT_TRACKING=true   — Data taint tracking across tool chains
    SHIELD_ENABLE_GOAL_DRIFT=true       — Goal drift detection
    SHIELD_ENABLE_CERT_IDENTITY=true    — Certificate-based agent identity
    SHIELD_ENABLE_FLIGHT_RECORDER=true  — Forensic incident snapshots on block/kill

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


def flight_recorder_enabled() -> bool:
    """Forensic flight recorder — incident snapshots on containment events.

    Read live from the environment (not cached at import) so tests and rollout
    can flip it without a restart. Off by default; also turned on by the
    ``SHIELD_ENABLE_ENTERPRISE`` umbrella flag. Purely additive: when off,
    capture is a no-op and the retrieval routes 404 (secure-by-default,
    non-breaking — see docs/spec-flight-recorder.md).
    """
    return _is_enabled("SHIELD_ENABLE_FLIGHT_RECORDER")


def a2a_enforce_mode() -> str:
    """Resolve the A2A inter-agent authorization enforcement mode.

    Returns one of:
        "off"      — default; A2A runs only content guardrails (current behavior).
        "monitor"  — run delegation/RBAC/identity guards, log would-blocks to the
                     decision audit, but ALLOW the task (dry-run).
        "on"       — enforce; reject the task on an authz block verdict.

    Read live from the environment (not cached at import) so tests and rollout
    can flip it per request without a restart.

    Deliberately NOT auto-enabled by ``SHIELD_ENABLE_ENTERPRISE``: this guard
    sits on the A2A request path and turning it to "on" can reject inter-agent
    traffic that was previously allowed, so it must be opted into explicitly
    (secure-by-default but non-breaking — see the A2A enforcement spec).
    """
    val = os.environ.get("SHIELD_A2A_ENFORCE", "").strip().lower()
    if val in ("on", "enforce", "true", "1", "yes"):
        return "on"
    if val in ("monitor", "dry-run", "dryrun", "warn"):
        return "monitor"
    return "off"
