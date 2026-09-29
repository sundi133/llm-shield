"""The guard a robot runs between its world/action model and its controller.

    guard = Guard.from_bundle("/etc/shield/embodied.bundle", pinned_key="/etc/shield/fleet.pub",
                              tenant="acme", fleet="hospital-east",
                              audit_dir="/var/lib/shield/audit")
    d = guard.check(action=model_output.action, state=robot.state_facts(), stage="plan")
    if d.verdict != "pass":
        controller.hold(d)     # your controlled stop; never a power cut

No network in the decision. The bundle is verified against a key pinned on
disk (shield-mavlink's format and verifier). Decisions are appended to
shield-mavlink's hash-chained audit log.
Spec: docs/specs/embodied-action-guard.md §7, §8.

Modes:
  normal               the bundle verified and has not expired
  degraded_expired     the bundle verified but has expired: only its own
                       degraded.allows actions, at its degraded speed cap
  degraded_unverified  no bundle, or one that does not verify: only the
                       built-in DEGRADED_DEFAULT below. Nothing from an
                       unverified file is trusted, and there is no fallback to
                       an older bundle (that is a downgrade primitive).

The model's output goes in `action` (or `report`); the robot's own facts go in
`state`. The model never writes `state`: that separation is the trust boundary.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from shield_embodied.evaluator import BLOCK, PASS, evaluate
from shield_embodied.model import ProfileError, profile_hash, validate_profile

try:
    from shield_mavlink.audit import OfflineAuditChain
    from shield_mavlink.bundle import BundleError, verify_bundle
except ImportError:                                        # running from a Shield checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shield-mavlink"))
    from shield_mavlink.audit import OfflineAuditChain
    from shield_mavlink.bundle import BundleError, verify_bundle

#: What a robot may do when it has no trustworthy policy at all.
DEGRADED_DEFAULT = {"allows": ["stop", "return_to_base", "dock"], "max_velocity_mps": 0.3}


@dataclass
class Decision:
    verdict: str
    rail: Optional[str]
    reasons: list = field(default_factory=list)
    message: str = ""
    mode: str = "normal"
    profile_hash: Optional[str] = None
    evaluated_us: float = 0.0
    audit_seq: Optional[int] = None
    rails: list = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == PASS


class Guard:
    def __init__(self, profile: Optional[dict], *, mode: str = "normal",
                 degraded: Optional[dict] = None, mode_reason: str = "",
                 audit_dir: Optional[str] = None, audit_passes: bool = False,
                 header: Optional[dict] = None):
        self.profile = profile
        self.mode = mode
        self.mode_reason = mode_reason
        self.degraded = degraded or DEGRADED_DEFAULT
        self.header = header or {}
        self.profile_hash = profile_hash(profile) if profile else None
        self.audit = OfflineAuditChain(audit_dir) if audit_dir else None
        self.audit_passes = audit_passes

    # ── construction ─────────────────────────────────────────────────

    @classmethod
    def from_bundle(cls, bundle_path: str, *, pinned_key: str, tenant: str, fleet: str,
                    audit_dir: Optional[str] = None, audit_passes: bool = False,
                    now: Optional[int] = None) -> "Guard":
        """Verify the bundle and pick the mode. Never raises for a bad bundle:
        a robot must always be able to decide, so a bad bundle means degraded."""
        key = pinned_key
        if os.path.exists(pinned_key):
            key = Path(pinned_key).read_text().strip()
        kw = dict(audit_dir=audit_dir, audit_passes=audit_passes)
        try:
            bundle = json.loads(Path(bundle_path).read_text())
            policy = verify_bundle(bundle, public_key_hex=key, expect_tenant=tenant,
                                   expect_fleet=fleet, now=now, allow_expired=True)
            profile = validate_profile(policy)
        except FileNotFoundError:
            return cls(None, mode="degraded_unverified", mode_reason="no bundle on disk", **kw)
        except (BundleError, ValueError, ProfileError) as e:
            return cls(None, mode="degraded_unverified", mode_reason=str(e)[:300], **kw)
        header = bundle["header"]
        ts = int(now if now is not None else time.time())
        if ts >= int(header.get("expires_at", 0)):
            return cls(profile, mode="degraded_expired", degraded=profile["degraded"],
                       mode_reason=f"bundle version {header.get('bundle_version')} expired",
                       header=header, **kw)
        return cls(profile, mode="normal", header=header, **kw)

    # ── deciding ─────────────────────────────────────────────────────

    def _degraded(self, event: dict) -> dict:
        action = event.get("proposed_action") if isinstance(event.get("proposed_action"),
                                                            dict) else {}
        tool = action.get("tool")
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        if tool not in self.degraded["allows"]:
            return {"verdict": BLOCK, "rail": "degraded_mode", "reasons": [self.mode],
                    "message": f"{self.mode_reason}; only {', '.join(self.degraded['allows'])} "
                               f"are allowed", "rails": []}
        v = params.get("velocity_mps")
        if isinstance(v, (int, float)) and not isinstance(v, bool) and \
                v > self.degraded["max_velocity_mps"]:
            return {"verdict": BLOCK, "rail": "degraded_mode", "reasons": ["degraded_speed_cap"],
                    "message": f"degraded mode caps speed at {self.degraded['max_velocity_mps']} "
                               f"m/s", "rails": []}
        return {"verdict": PASS, "rail": None, "reasons": [], "message": "allowed in degraded mode",
                "rails": []}

    def check(self, action: Optional[dict] = None, state: Optional[dict] = None, *,
              stage: str = "plan", report: Optional[dict] = None,
              perceived_text: Optional[dict] = None, human_instruction: Optional[dict] = None,
              run_id: str = "", step: Optional[int] = None) -> Decision:
        event: dict[str, Any] = {"stage": stage, "run_id": run_id, "step": step,
                                 "context": dict(state or {})}
        if action is not None:
            event["proposed_action"] = action
        if report is not None:
            event["proposed_report"] = report
        if perceived_text is not None:
            event["perceived_text"] = perceived_text
        if human_instruction is not None:
            event["human_instruction"] = human_instruction
        return self.check_event(event)

    def check_event(self, event: dict) -> Decision:
        t0 = time.perf_counter()
        out = evaluate(self.profile, event) if self.mode == "normal" else self._degraded(event)
        us = round((time.perf_counter() - t0) * 1e6, 1)
        d = Decision(verdict=out["verdict"], rail=out["rail"], reasons=list(out["reasons"]),
                     message=out["message"], mode=self.mode, profile_hash=self.profile_hash,
                     evaluated_us=us, rails=out.get("rails", []))
        if self.audit is not None and (d.verdict != PASS or self.audit_passes):
            try:
                rec = self.audit.append(self._audit_core(event, d))
                d.audit_seq = rec["seq"]
            except Exception as e:
                # An unrecordable decision is one nobody can review: refuse it.
                return Decision(verdict=BLOCK, rail="audit_unavailable",
                                reasons=["audit_unavailable"], mode=self.mode,
                                message=f"the decision could not be recorded: {e}",
                                profile_hash=self.profile_hash, evaluated_us=us)
        return d

    def _audit_core(self, event: dict, d: Decision) -> dict:
        action = event.get("proposed_action") if isinstance(event.get("proposed_action"),
                                                            dict) else {}
        return {"at": round(time.time(), 3), "run_id": event.get("run_id"),
                "step": event.get("step"), "stage": event.get("stage"),
                "tool": action.get("tool") or ("report" if event.get("proposed_report") else None),
                "verdict": d.verdict, "rail": d.rail, "reasons": d.reasons, "mode": d.mode,
                "profile_hash": d.profile_hash,
                "bundle_version": self.header.get("bundle_version")}
