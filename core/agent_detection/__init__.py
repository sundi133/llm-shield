"""AI agent and fleet detection (docs/specs/agent-impersonation-defense.md).

Rev 8 builds tag-first. This package holds:

  sitekeys   public site keys for the tag: tenant, allowed origins, consent
  beacons    beacon schema v1: validation, clamping, the request block
  stream     the per-tenant beacon stream in Redis (both client flavours)
  collector  the public collector service (its own process, admin image)

Nothing here runs on the guard path (`/guardrails/*`, `cap/mint`,
`tools/call`) or in the data plane.
"""

from __future__ import annotations

import os

_OFF = ("off", "0", "false", "no")


def enabled() -> bool:
    """SHIELD_AGENT_DETECTION: off hides the admin routes and stops the worker."""
    return (os.environ.get("SHIELD_AGENT_DETECTION", "on") or "on").strip().lower() not in _OFF


def collector_enabled() -> bool:
    """SHIELD_AGENT_DETECTION_COLLECTOR: off makes the collector drop every
    beacon (still 204). Tier 1 is unaffected."""
    if not enabled():
        return False
    return (os.environ.get("SHIELD_AGENT_DETECTION_COLLECTOR", "on") or "on").strip().lower() not in _OFF


def hash_salt() -> str:
    """SHIELD_AGENT_DETECTION_HASH_SALT, required when the collector is on."""
    return (os.environ.get("SHIELD_AGENT_DETECTION_HASH_SALT", "") or "").strip()
