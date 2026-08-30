"""The arm authority a flight controller already knows how to ask.

MAVLink has a standard mechanism for this and PX4 implements it. Set
`COM_ARM_AUTH_REQ=1` and `COM_ARM_AUTH_ID` to this component's system id, and the
flight controller asks permission before it arms. No SDK to adopt, no proxy to
route through, no change to anyone's planner: one parameter.

The decision is local, from a signed bundle, with no network in the path. That
is the whole point. An aircraft out of coverage is the normal case, not a
degraded one, and a product that grounds the fleet when the link drops gets
switched off rather than debugged.

    COM_ARM_AUTH_REQ = 1
    COM_ARM_AUTH_ID  = 10        <- must match system_id below

What this does NOT do, and must not be described as doing: authenticate the
request. Unsigned MAVLink lets anything on the network claim to be the
authorizer. This raises the bar on policy, not on link security.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .audit import OfflineAuditChain
from .policy import LocalPolicy, Verdict

logger = logging.getLogger("shield.mavlink.authorizer")


@dataclass(frozen=True)
class Rejection:
    """A refusal in the shape MAVLink carries it.

    `temporarily` is the field worth getting right. A pending approval may
    succeed on the next attempt, so the operator should retry. A mission that
    breaches the geofence will not, so telling them to retry wastes their time
    at the aircraft. PX4 and QGC surface the distinction.
    """
    reason: str            # a RejectionReason name, resolved late, see below
    temporarily: bool
    text: str              # prose for STATUSTEXT, because an enum tells a human nothing


#: Which rule family produced the refusal, mapped to what MAVLink can express.
#: Deliberately explicit rather than defaulting everything to GENERIC: an
#: operator reading INVALID_WAYPOINT in QGC learns where to look, and one
#: reading GENERIC learns only that something is wrong.
_FAMILY_TO_REASON = {
    "geofence":       ("INVALID_WAYPOINT", False),
    "allowed_values": ("INVALID_WAYPOINT", False),
    "max":            ("INVALID_WAYPOINT", False),
    "min":            ("INVALID_WAYPOINT", False),
    "required":       ("INVALID_WAYPOINT", False),
    "forbidden":      ("INVALID_WAYPOINT", False),
    "regex":          ("INVALID_WAYPOINT", False),
    "max_length":     ("INVALID_WAYPOINT", False),
    "numeric":        ("INVALID_WAYPOINT", False),
    "unknown_tool":   ("GENERIC", False),
    # Weather and airspace get their own codes where the field makes it obvious.
    "weather":        ("BAD_WEATHER", True),
    "airspace":       ("AIRSPACE_IN_USE", True),
    # Waiting on something that may yet arrive.
    "approval":       ("TIMEOUT", True),
    "bundle":         ("GENERIC", False),
}

#: Fields whose violation is better described by a weather or airspace code than
#: by INVALID_WAYPOINT. Mapping on the field rather than the family, because the
#: family only knows that a number was out of range.
_FIELD_OVERRIDES = {
    "wind_ms": "weather", "gust_ms": "weather", "visibility_m": "weather",
    "precipitation_mm": "weather",
    "local_hour": "airspace", "airspace_class": "airspace",
    "notam_active": "airspace",
}


def classify(verdict: Verdict) -> Rejection:
    """Turn a policy verdict into something PX4 and an operator both understand."""
    family = _FIELD_OVERRIDES.get(verdict.field, verdict.rule)
    reason, temporarily = _FAMILY_TO_REASON.get(family, ("GENERIC", False))
    return Rejection(reason=reason, temporarily=temporarily,
                     text=f"Shield: {verdict.reason}")


class ArmAuthorizer:
    """Answers arm requests from a verified bundle.

    Constructed with an already-verified policy. It does not read bundles or
    check signatures: that happened before this object existed, and keeping the
    responsibility out of here means there is no path by which an unverified
    bundle reaches a decision.
    """

    def __init__(
        self,
        policy: LocalPolicy,
        *,
        audit: OfflineAuditChain,
        aircraft_id: str,
        bundle_version: int,
        grant_valid_time_s: int = 60,
        context_provider: Optional[Callable[[], dict[str, Any]]] = None,
    ):
        self.policy = policy
        self.audit = audit
        self.aircraft_id = aircraft_id
        self.bundle_version = bundle_version
        self.grant_valid_time_s = grant_valid_time_s
        self._context = context_provider or (lambda: {})

    def decide(self, extra: Optional[dict[str, Any]] = None
               ) -> tuple[bool, Optional[Rejection]]:
        """Decide, and record. Recording is not optional.

        An unrecordable decision is one nobody can review afterwards, and the
        reviewability is the property being sold. If the log cannot be written
        the answer is no, which is why the append is not wrapped in a try.
        """
        params = {"aircraft_id": self.aircraft_id, **self._context(), **(extra or {})}

        if self.policy.requires_human("arm"):
            v = Verdict(False, "approval", "", "arming requires approval and no "
                                               "approver is reachable")
        else:
            v = self.policy.check("arm", params)

        rejection = None if v.allowed else classify(v)
        self.audit.append({
            "tool": "arm",
            "aircraft_id": self.aircraft_id,
            "bundle_version": self.bundle_version,
            "verdict": "allow" if v.allowed else "deny",
            "rule": v.rule, "field": v.field, "reason": v.reason,
            "mavlink_reason": rejection.reason if rejection else "NONE",
            "params": params,
        })
        return v.allowed, rejection

    # ── MAVLink loop ───────────────────────────────────────────────────────

    async def serve(self, drone, stop: Optional[asyncio.Event] = None) -> None:
        """Answer arm authorization requests until told to stop.

        `drone` is a connected mavsdk.System. Imported by the caller rather than
        here, so this module stays importable, and testable, without mavsdk.
        """
        from mavsdk.arm_authorizer_server import RejectionReason

        logger.info("arm authorizer ready: bundle v%s, %d tool policies",
                    self.bundle_version, len(self.policy))

        async for _request in drone.arm_authorizer_server.arm_authorization():
            allowed, rejection = self.decide()

            if allowed:
                await drone.arm_authorizer_server.accept_arm_authorization(
                    self.grant_valid_time_s)
                logger.info("arm ACCEPTED for %ss", self.grant_valid_time_s)
            else:
                await drone.arm_authorizer_server.reject_arm_authorization(
                    rejection.temporarily,
                    getattr(RejectionReason, rejection.reason, RejectionReason.GENERIC),
                    0,
                )
                logger.info("arm REJECTED (%s, temporary=%s): %s",
                            rejection.reason, rejection.temporarily, rejection.text)
                # The enum tells PX4 what happened; the sentence tells the person
                # standing next to the aircraft, in QGC's message panel. Both
                # are needed, and only the enum is load-bearing.
                try:
                    from mavsdk.server_utility import StatusTextType
                    await drone.server_utility.send_status_text(
                        StatusTextType.WARNING, rejection.text[:150])
                except Exception:
                    pass  # STATUSTEXT is a courtesy, never a precondition

            if stop is not None and stop.is_set():
                return
