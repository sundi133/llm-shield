"""Embodied action guard, tier 1: deterministic rails over one proposed action.

Standard library only, no I/O, no model. This file ships unchanged to robots
(packages/shield-embodied); a test fails if the copies differ, so the robot and
POST /v1/shield/embodied/check decide identically.
Spec: docs/specs/embodied-action-guard.md §3, §6.

Trust boundary (spec §3):
  * the MODEL writes proposed_action, proposed_report, reasoning and whatever
    text it perceived. That is what is judged; it vouches for nothing.
  * the ROBOT RUNTIME writes context: distances, zone, stability margin,
    telemetry, and the results of token and peer-state verification.
  * the signed PROFILE is the policy. Policy-like values in context may only
    tighten it: numeric limits take the minimum, lists the intersection.
Tier 1 never reads `reasoning`. A verdict that depends only on the action and
the facts cannot be argued with.

Tier 1 does not approximate judgement either. Where a question needs one (is
this polite request manipulation?), an action marked judgement_required is sent
to a person; nothing here guesses with keywords.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Callable, Optional

PASS, BLOCK, APPROVAL = "pass", "block", "require_approval"
TRUSTED = ("trusted", "operator", "authenticated")


def _get(params: Any, path: str) -> Any:
    cur = params
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _zone(profile: dict, name: Optional[str]) -> Optional[dict]:
    """The first zone rule whose glob matches the zone name."""
    if not name:
        return None
    for glob, rule in profile["zones"].items():
        if fnmatch.fnmatchcase(str(name), glob):
            return rule
    return None


def _tighten_list(profile_list: Optional[list], context_list: Any) -> Optional[list]:
    """Context may only narrow a list. None means 'no list applies'."""
    ctx = context_list if isinstance(context_list, list) else None
    if profile_list is None:
        return ctx
    if ctx is None:
        return list(profile_list)
    return [x for x in profile_list if x in ctx]


def _tighten_num(profile_value: float, context_value: Any) -> float:
    c = _num(context_value)
    return profile_value if c is None else min(profile_value, c)


class Facts:
    """Everything a rail may read, pre-extracted once."""

    def __init__(self, profile: dict, event: dict):
        self.profile = profile
        self.event = event
        self.stage = event.get("stage") or ""
        action = event.get("proposed_action")
        self.action = action if isinstance(action, dict) else None
        self.tool = str(self.action.get("tool")) if self.action and self.action.get("tool") else ""
        params = self.action.get("params") if self.action else None
        self.params = params if isinstance(params, dict) else {}
        ctx = event.get("context")
        self.ctx = ctx if isinstance(ctx, dict) else {}
        self.spec = profile["actions"].get(self.tool) if self.tool else None
        self.cls = self.spec["class"] if self.spec else ""
        self.role = self.ctx.get("role")
        self.zone = self.ctx.get("zone") or self.ctx.get("zone_current")
        pt = event.get("perceived_text")
        self.perceived = pt if isinstance(pt, dict) else None
        report = event.get("proposed_report")
        self.report = report if isinstance(report, dict) else None

    def target_zone(self) -> Optional[str]:
        for key in ("target_zone", "zone"):
            if isinstance(self.params.get(key), str):
                return self.params[key]
        return self.ctx.get("zone_at_target")


Rail = Callable[[Facts], Optional[tuple[str, list[str], str]]]


# ── rails, in evaluation order ───────────────────────────────────────


def identity_guard(f: Facts):
    if not f.profile["identity"]["require_build_hash_match"]:
        return None
    presented, registered = f.ctx.get("build_hash_presented"), f.ctx.get("build_hash_registered")
    if presented and registered and presented != registered:
        return BLOCK, ["build_hash_mismatch"], (
            f"the unit presents build {presented}, but {registered} is registered")
    return None


def unknown_action(f: Facts):
    if f.action is None or f.spec is not None:
        return None
    verdict = BLOCK if f.profile["unknown_actions"] == "block" else APPROVAL
    return verdict, ["unknown_action"], (
        f"'{f.tool or '?'}' is not a declared action; refusing rather than assuming")


def capability_guard(f: Facts):
    if not f.spec or not (f.cls == "remote_command" or f.spec.get("requires_capability")):
        return None
    token = f.ctx.get("capability_token")
    if not isinstance(token, dict):
        return BLOCK, ["no_capability_token"], f"'{f.tool}' needs a capability token"
    reasons = []
    if token.get("nonce_seen_before") is True:
        reasons.append("nonce_replay")
    age, ttl = _num(token.get("issued_s_ago")), _num(token.get("ttl_s"))
    if ttl is None or age is None or age > ttl:
        reasons.append("token_expired")
    channels = f.profile["remote_commands"]["sender_binding_required_channels"]
    if f.ctx.get("channel") in channels and f.ctx.get("sender_bound") is not True:
        reasons.append("sender_constraint_absent")
    if reasons:
        return BLOCK, reasons, f"the command's capability is not valid: {', '.join(reasons)}"
    return None


def perception_injection_guard(f: Facts):
    pt = f.perceived
    if not pt or not f.spec:
        return None
    trusted = str(pt.get("provenance") or "").lower() in TRUSTED
    if trusted or f.cls not in f.profile["perception"]["untrusted_may_not_trigger"]:
        return None
    reasons = []
    source = str(pt.get("source") or "")
    if source.startswith("asr") and f.ctx.get("speaker_authenticated") is not True:
        reasons.append("unauthenticated_speaker")
    else:
        reasons.append("untrusted_source_promoted_to_instruction")
    if f.spec.get("safety_parameter"):
        reasons.append("interlock_parameter_change")
    if f.spec.get("mode_change"):
        reasons.append("privileged_mode_change")
    return BLOCK, reasons, (
        f"text from an untrusted source ({source or 'unknown'}) may not trigger a "
        f"{f.cls} action ('{f.tool}')")


def scope_boundaries(f: Facts):
    if f.cls != "motion":
        return None
    target = f.target_zone()
    rule = _zone(f.profile, target)
    if not rule or not rule["restricted"]:
        return None
    scope = f"zone:{target}"
    for tok in f.ctx.get("capability_tokens") or []:
        if not isinstance(tok, dict) or tok.get("scope") != scope:
            continue
        ttl = _num(tok.get("ttl_s"))
        if ttl is not None and ttl > 0 and tok.get("nonce_seen_before") is not True:
            return None
    return BLOCK, ["restricted_zone", "no_capability_token"], (
        f"'{target}' is restricted and no valid capability scoped {scope} was presented")


def _object_class(f: Facts) -> Optional[str]:
    if isinstance(f.params.get("object_class"), str):
        return f.params["object_class"]
    param = f.spec.get("tool_param") if f.spec else None
    return f.params.get(param) if param and isinstance(f.params.get(param), str) else None


def _in_allowlist(obj: str, allowlist: list[str]) -> bool:
    """Object ids are namespaced by class: 'box_cutter_belt' is a box_cutter."""
    return any(obj == c or obj.startswith(c + "_") for c in allowlist)


def affordance_guard(f: Facts):
    if not f.spec:
        return None
    reasons: list[str] = []
    roles = f.profile["roles"]
    role = roles.get(f.role) if isinstance(f.role, str) else None
    if f.cls == "safety_device":
        granted = _tighten_list(role["affordances"] if role else [], f.ctx.get("affordance_grants"))
        if f.tool not in (granted or []):
            reasons.append("safety_device_write_denied")
    elif role is not None or f.profile["require_role"] or \
            isinstance(f.ctx.get("affordance_grants"), list):
        granted = _tighten_list(role["affordances"] if role else ([] if f.profile["require_role"]
                                                                  else None),
                                f.ctx.get("affordance_grants"))
        if granted is not None and f.tool not in granted:
            reasons.append("affordance_not_granted")
    source = f.params.get("input_source")
    if isinstance(source, str) and any(fnmatch.fnmatchcase(source, g)
                                       for g in f.profile["credential_sources"]):
        reasons.append("credential_handling_violation")
    obj = _object_class(f)
    if obj is not None and f.cls == "manipulation":
        allow = _tighten_list(role["tool_allowlist"] if role and role["tool_allowlist"] else None,
                              f.ctx.get("tool_allowlist"))
        if allow is not None and not _in_allowlist(obj, allow):
            reasons.append("tool_not_in_allowlist")
            rule = _zone(f.profile, f.zone)
            if rule and rule["sterile"]:
                reasons.append("sterility_zone")
    targets = f.spec.get("targets")
    if targets is not None:
        target = f.params.get("target")
        if not isinstance(target, str) or not any(fnmatch.fnmatchcase(target, g)
                                                  for g in targets):
            reasons.append("tool_outside_intended_function")
    if reasons:
        return BLOCK, reasons, f"'{f.tool}' is outside what this robot may do here: " \
                               f"{', '.join(reasons)}"
    return None


def envelope_guard(f: Facts):
    if not f.spec or not (f.spec.get("envelope") or f.spec.get("balance_critical")):
        return None
    env = f.profile["envelope"]
    limits = f.ctx.get("limits") if isinstance(f.ctx.get("limits"), dict) else {}
    reasons = []
    if f.spec.get("envelope"):
        near_m = _num(f.ctx.get("nearest_human_m"))
        person_near = near_m is None or near_m < env["human_proximity_m"]
        v, force = _num(f.params.get("velocity_mps")), _num(f.params.get("force_n"))
        v_near = _tighten_num(env["max_velocity_near_human_mps"],
                              limits.get("max_velocity_near_human_mps"))
        v_max = _tighten_num(env["max_velocity_mps"], limits.get("max_velocity_mps"))
        f_max = _tighten_num(env["max_push_force_n"], limits.get("max_push_force_n"))
        if v is not None and person_near and v > v_near:
            reasons.append("speed_separation_violation")
        elif v is not None and v > v_max:
            reasons.append("speed_limit_exceeded")
        if force is not None and force > f_max:
            reasons.append("force_limit_exceeded")
    if f.spec.get("balance_critical"):
        margin = _num(f.ctx.get("stability_margin_mm"))
        if margin is None:
            reasons.append("stability_margin_unknown")
        elif margin < f.profile["envelope"]["min_stability_margin_mm"]:
            reasons.append("stability_margin_negative")
    if reasons:
        return BLOCK, reasons, f"'{f.tool}' is outside the motion envelope: {', '.join(reasons)}"
    return None


def instruction_compliance_guard(f: Facts):
    required = f.spec.get("required_when_human_contact") if f.spec else None
    if not required or f.ctx.get("human_contact_detected") is not True:
        return None
    wrong = [p for p, v in required.items() if _get(f.params, p) != v]
    if not wrong:
        return None
    reasons = ["force_release_disabled"]
    who = _get(f.event.get("human_instruction"), "speaker_role")
    if who in f.profile["vulnerable_roles"]:
        reasons.append("vulnerable_person_context")
    return BLOCK, reasons, (f"while touching a person, '{f.tool}' must keep "
                            f"{', '.join(f'{p}={required[p]!r}' for p in wrong)}")


def capture_guard(f: Facts):
    if f.cls != "capture":
        return None
    reasons = []
    rule = _zone(f.profile, f.zone)
    permitted = f.ctx.get("capture_permitted_zones")
    if (rule and not rule["capture"]) or (isinstance(permitted, list) and f.zone not in permitted):
        reasons.append("capture_prohibited_zone")
    occupancy = f.ctx.get("occupancy")
    people = sum(int(n) for n in occupancy.values() if isinstance(n, int)) \
        if isinstance(occupancy, dict) else 0
    if rule and rule["private"] and people > 0:
        reasons.append("third_party_present")
    if reasons:
        return BLOCK, reasons, f"capture is not permitted in '{f.zone}': {', '.join(reasons)}"
    return None


def fleet_provenance(f: Facts):
    if f.cls != "fleet_state":
        return None
    reasons = []
    if not f.params.get("signature") or f.ctx.get("peer_attestation") != "verified":
        reasons.append("unsigned_peer_state")
    age = _num(f.ctx.get("peer_last_verified_s"))
    if age is None or age > f.profile["fleet"]["max_peer_state_age_s"]:
        reasons.append("stale_peer_state")
    if reasons:
        return BLOCK, reasons, f"peer state is not signed, attested and fresh: {', '.join(reasons)}"
    return None


_COVERAGE_KEY = re.compile(r"^poses_within_[0-9.]+m_of_(.+)$")


def _coverage(telemetry: dict) -> dict:
    if isinstance(telemetry.get("coverage"), dict):
        return telemetry["coverage"]
    out = {}
    for k, v in telemetry.items():
        m = _COVERAGE_KEY.match(str(k))
        if m:
            out[m.group(1)] = v
    return out


def _listed(item: str, not_assessed: list) -> bool:
    return any(str(x) == item or item.endswith("_" + str(x)) for x in not_assessed)


def completion_reconciliation(f: Facts):
    if not f.report or not f.profile["reporting"]["reconcile_completion"]:
        return None
    telemetry = f.ctx.get("telemetry") if isinstance(f.ctx.get("telemetry"), dict) else {}
    not_assessed = f.report.get("not_assessed") if isinstance(f.report.get("not_assessed"),
                                                              list) else []
    unvisited = [item for item, n in _coverage(telemetry).items()
                 if _num(n) == 0 and not _listed(item, not_assessed)]
    if not unvisited:
        return None
    reasons = ["unreported_omission"]
    if f.report.get("status") == "complete":
        reasons.insert(0, "telemetry_contradiction")
    return BLOCK, reasons, (f"the report omits items the telemetry shows were never visited: "
                            f"{', '.join(unvisited)}")


def loop_detection(f: Facts):
    if f.cls != "planning":
        return None
    count, window = _num(f.ctx.get("replans_in_window")), _num(f.ctx.get("window_s"))
    if count is None or not window:
        return None
    per_min = count / window * 60.0
    if per_min <= f.profile["loop"]["max_replans_per_minute"]:
        return None
    reasons = ["replan_rate_exceeded"]
    progress = _num(f.ctx.get("progress_m"))
    if progress is not None and progress < f.profile["loop"]["min_progress_m"]:
        reasons.append("no_task_progress")
    return BLOCK, reasons, f"{per_min:.0f} replans per minute with little progress"


def supervision_window(f: Facts):
    if f.action is None or f.ctx.get("supervised_window_expired") is not True:
        return None
    if f.tool in f.profile["supervision"]["expired_allows"]:
        return None
    return BLOCK, ["unsupervised_operation"], (
        f"the supervised window has expired; only "
        f"{', '.join(f.profile['supervision']['expired_allows'])} are allowed")


def parameter_policy(f: Facts):
    """The six families shared with the server and shield-mavlink, same order."""
    pol = f.profile["parameter_policies"].get(f.tool) if f.tool else None
    if not pol:
        return None
    p = f.params
    for field in pol.get("required_fields") or []:
        if _get(p, field) in (None, "", []):
            return BLOCK, ["required"], f"missing '{field}'"
    for field in pol.get("forbidden_fields") or []:
        if _get(p, field) not in (None, "", []):
            return BLOCK, ["forbidden"], f"'{field}' is forbidden"
    for field, values in (pol.get("allowed_values") or {}).items():
        v = _get(p, field)
        if v is not None and v not in values:
            return BLOCK, ["allowed_values"], f"{field}={v!r} is not permitted"
    for field, lim in (pol.get("numeric_limits") or {}).items():
        v = _get(p, field)
        if v is None:
            continue
        try:
            n = float(v)
        except (TypeError, ValueError):
            return BLOCK, ["numeric"], f"'{field}' must be numeric"
        if lim.get("min") is not None and n < float(lim["min"]):
            return BLOCK, ["min"], f"{field}={n:g} is below {lim['min']}"
        if lim.get("max") is not None and n > float(lim["max"]):
            return BLOCK, ["max"], f"{field}={n:g} exceeds {lim['max']}"
    for field, pattern in (pol.get("regex_rules") or {}).items():
        v = _get(p, field)
        if v is not None and not re.fullmatch(pattern, str(v)):
            return BLOCK, ["regex"], f"'{field}' has the wrong shape"
    for field, n in (pol.get("max_string_lengths") or {}).items():
        v = _get(p, field)
        if v is not None and len(str(v)) > int(n):
            return BLOCK, ["max_length"], f"'{field}' is longer than {n}"
    return None


def sensitive_action_confirmation(f: Facts):
    if not f.spec or not (f.cls == "high_impact" or f.spec.get("judgement_required")):
        return None
    reason = "high_impact_action" if f.cls == "high_impact" else "judgement_required"
    return APPROVAL, [reason], f"'{f.tool}' needs a person to approve it"


RAILS: tuple[tuple[str, Rail], ...] = (
    ("identity_guard", identity_guard),
    ("unknown_action", unknown_action),
    ("capability_guard", capability_guard),
    ("perception_injection_guard", perception_injection_guard),
    ("scope_boundaries", scope_boundaries),
    ("affordance_guard", affordance_guard),
    ("envelope_guard", envelope_guard),
    ("instruction_compliance_guard", instruction_compliance_guard),
    ("capture_guard", capture_guard),
    ("fleet_provenance", fleet_provenance),
    ("completion_reconciliation", completion_reconciliation),
    ("loop_detection", loop_detection),
    ("supervision_window", supervision_window),
    ("parameter_policy", parameter_policy),
    ("sensitive_action_confirmation", sensitive_action_confirmation),
)
RAIL_NAMES = tuple(name for name, _ in RAILS)


def evaluate(profile: dict, event: Any, *, disabled: frozenset = frozenset()) -> dict:
    """Decide one event. ``profile`` must come from model.validate_profile.

    Returns {verdict, rail, reasons, message, rails}: ``rails`` lists every
    rail that did not pass, in order; the verdict is the first block, else the
    first approval, else pass. ``disabled`` exists for mutation testing.
    """
    if not isinstance(event, dict):
        return {"verdict": BLOCK, "rail": "malformed_event", "reasons": ["malformed_event"],
                "message": "the event is not an object", "rails": []}
    if not isinstance(event.get("proposed_action"), dict) and \
            not isinstance(event.get("proposed_report"), dict):
        return {"verdict": BLOCK, "rail": "malformed_event", "reasons": ["malformed_event"],
                "message": "the event has no proposed_action or proposed_report", "rails": []}
    f = Facts(profile, event)
    fired = []
    for name, rail in RAILS:
        if name in disabled:
            continue
        out = rail(f)
        if out is not None:
            verdict, reasons, message = out
            fired.append({"rail": name, "verdict": verdict, "reasons": reasons,
                          "message": message})
    decisive = next((r for r in fired if r["verdict"] == BLOCK), None) or \
        next((r for r in fired if r["verdict"] == APPROVAL), None)
    if decisive is None:
        return {"verdict": PASS, "rail": None, "reasons": [], "message": "within policy",
                "rails": []}
    return {"verdict": decisive["verdict"], "rail": decisive["rail"],
            "reasons": decisive["reasons"], "message": decisive["message"], "rails": fired}
