"""A self-serve trial's state (docs/specs/self-serve-signup.md, task 5).

Pure: reads the tenant config the caller already holds, so the data-plane
check costs a dict lookup and a clock read, no store round trip.
"""

from __future__ import annotations

import time
from typing import Optional

NONE, ACTIVE, EXPIRED, SUSPENDED = "none", "active", "expired", "suspended"


def status(tenant_config: Optional[dict], now: Optional[float] = None) -> str:
    """none (not a trial), active, expired, or suspended."""
    if not isinstance(tenant_config, dict) or tenant_config.get("plan") != "trial":
        return NONE
    trial = tenant_config.get("trial")
    if not isinstance(trial, dict):
        return NONE
    if trial.get("suspended_at"):
        return SUSPENDED
    expires_at = trial.get("expires_at")
    now = time.time() if now is None else now
    if isinstance(expires_at, (int, float)) and expires_at < now:
        return EXPIRED
    return ACTIVE


def refusal(tenant_config: Optional[dict], now: Optional[float] = None) -> Optional[tuple]:
    """(HTTP status, JSON body) refusing a key whose trial ended or was
    suspended, or None to let it through."""
    s = status(tenant_config, now)
    if s == EXPIRED:
        return 402, {"error": "trial_ended",
                     "detail": "This workspace's trial has ended. Contact Votal to continue; "
                               "your workspace and its settings are kept.",
                     "expired_at": tenant_config["trial"].get("expires_at")}
    if s == SUSPENDED:
        return 403, {"error": "workspace_suspended",
                     "detail": "This workspace has been suspended. Contact Votal."}
    return None
