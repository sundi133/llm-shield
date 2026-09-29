"""Action profile: the policy a robot's proposed actions are checked against.

Standard library only. This file ships unchanged to robots
(packages/shield-embodied); a test fails if the copies differ.
Spec: docs/specs/embodied-action-guard.md §5.1.

Validation is strict, as for runtime profiles: an unknown field, a misspelled
rail setting or a malformed pattern is rejected with every error listed. A
safety rule that is silently ignored is a rule that silently never applies.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

#: What kind of thing an action does. Rails key off the class.
CLASSES = ("motion", "manipulation", "privileged", "safety_device", "high_impact", "capture",
           "remote_command", "fleet_state", "planning", "speech", "inspection", "other")
#: The six deterministic parameter families shared with the server and shield-mavlink.
PARAM_FAMILIES = ("required_fields", "forbidden_fields", "allowed_values", "numeric_limits",
                  "regex_rules", "max_string_lengths")

MAX_LIST = 200
MAX_PROFILES = 100
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.:*?\[\]-]{1,128}$")

_TOP = {"description", "unknown_actions", "require_role", "actions", "parameter_policies",
        "roles", "zones", "envelope", "perception", "fleet", "remote_commands", "identity",
        "loop", "supervision", "reporting", "degraded", "credential_sources",
        "vulnerable_roles"}
_ACTION = {"class", "description", "envelope", "balance_critical", "tool_param", "targets",
           "requires_capability", "required_when_human_contact", "safety_parameter",
           "mode_change", "judgement_required"}
_ROLE = {"affordances", "tool_allowlist", "description"}
_ZONE = {"restricted", "capture", "private", "sterile", "description"}

DEFAULTS: dict[str, dict] = {
    "envelope": {"human_proximity_m": 2.0, "max_velocity_near_human_mps": 0.5,
                 "max_velocity_mps": 1.5, "max_push_force_n": 150.0,
                 "min_stability_margin_mm": 0.0},
    "perception": {"untrusted_may_not_trigger": ["privileged", "safety_device", "high_impact",
                                                 "remote_command"]},
    "fleet": {"max_peer_state_age_s": 60.0},
    "remote_commands": {"sender_binding_required_channels": []},
    "identity": {"require_build_hash_match": True},
    "loop": {"max_replans_per_minute": 30.0, "min_progress_m": 1.0},
    "supervision": {"expired_allows": ["stop", "return_to_base", "dock"]},
    "reporting": {"reconcile_completion": True},
    "degraded": {"allows": ["stop", "return_to_base", "dock"], "max_velocity_mps": 0.3},
}
_NUMERIC = {"envelope": set(DEFAULTS["envelope"]), "fleet": {"max_peer_state_age_s"},
            "loop": {"max_replans_per_minute", "min_progress_m"},
            "degraded": {"max_velocity_mps"}}


class ProfileError(ValueError):
    """A profile failed validation. ``errors`` lists every problem."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def valid_name(name: str) -> bool:
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def profile_hash(profile: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(profile)).hexdigest()


# ── primitives ───────────────────────────────────────────────────────


def _obj(v: Any, where: str, errors: list[str]) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        errors.append(f"{where}: must be an object")
        return {}
    return v


def _unknown(obj: dict, allowed: set, where: str, errors: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errors.append(f"{where}: unknown field '{k}' (allowed: {', '.join(sorted(allowed))})")


def _bool(v: Any, default: bool, where: str, errors: list[str]) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    errors.append(f"{where}: must be true or false")
    return default


def _strs(v: Any, where: str, errors: list[str]) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        errors.append(f"{where}: must be a list of strings")
        return []
    if len(v) > MAX_LIST:
        errors.append(f"{where}: more than {MAX_LIST} entries")
    out = []
    for i, s in enumerate(v[:MAX_LIST]):
        if not isinstance(s, str) or not s.strip() or len(s) > 200:
            errors.append(f"{where}[{i}]: must be a non-empty string of at most 200 characters")
            continue
        out.append(s.strip())
    return out


def _num(v: Any, where: str, errors: list[str]) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        errors.append(f"{where}: must be a number")
        return 0.0
    if v != v or v in (float("inf"), float("-inf")):
        errors.append(f"{where}: must be finite")
        return 0.0
    return float(v)


def _key(k: Any, where: str, errors: list[str]) -> bool:
    if not isinstance(k, str) or not _KEY_RE.match(k):
        errors.append(f"{where}: key {k!r} must be 1 to 128 of letters, digits, _ . : - and globs")
        return False
    return True


# ── sections ─────────────────────────────────────────────────────────


def _actions(raw: Any, errors: list[str]) -> dict:
    out = {}
    for name, a in _obj(raw, "actions", errors).items():
        where = f"actions.{name}"
        if not _key(name, "actions", errors):
            continue
        a = _obj(a, where, errors)
        _unknown(a, _ACTION, where, errors)
        cls = a.get("class")
        if cls not in CLASSES:
            errors.append(f"{where}.class: must be one of {', '.join(CLASSES)}")
            continue
        entry = {"class": cls}
        for flag in ("envelope", "balance_critical", "requires_capability", "safety_parameter",
                     "mode_change", "judgement_required"):
            if _bool(a.get(flag), False, f"{where}.{flag}", errors):
                entry[flag] = True
        if a.get("tool_param") is not None:
            if not isinstance(a["tool_param"], str) or not a["tool_param"]:
                errors.append(f"{where}.tool_param: must be a parameter name")
            else:
                entry["tool_param"] = a["tool_param"]
        if a.get("targets") is not None:
            entry["targets"] = _strs(a["targets"], f"{where}.targets", errors)
        req = a.get("required_when_human_contact")
        if req is not None:
            req = _obj(req, f"{where}.required_when_human_contact", errors)
            for p, v in req.items():
                if isinstance(v, (dict, list)):
                    errors.append(f"{where}.required_when_human_contact.{p}: must be a scalar")
            entry["required_when_human_contact"] = {p: v for p, v in req.items()
                                                    if not isinstance(v, (dict, list))}
        if isinstance(a.get("description"), str):
            entry["description"] = a["description"][:500]
        out[name] = entry
    return out


def _param_policies(raw: Any, actions: dict, errors: list[str]) -> dict:
    out = {}
    for name, pol in _obj(raw, "parameter_policies", errors).items():
        where = f"parameter_policies.{name}"
        if name not in actions:
            errors.append(f"{where}: '{name}' is not a declared action")
            continue
        pol = _obj(pol, where, errors)
        _unknown(pol, set(PARAM_FAMILIES), where, errors)
        entry: dict = {}
        for fam in ("required_fields", "forbidden_fields"):
            if pol.get(fam) is not None:
                entry[fam] = _strs(pol[fam], f"{where}.{fam}", errors)
        if pol.get("allowed_values") is not None:
            av = _obj(pol["allowed_values"], f"{where}.allowed_values", errors)
            bad = [f for f, vals in av.items() if not isinstance(vals, list)]
            for f in bad:
                errors.append(f"{where}.allowed_values.{f}: must be a list")
            entry["allowed_values"] = {f: vals for f, vals in av.items() if isinstance(vals, list)}
        if pol.get("numeric_limits") is not None:
            nl = {}
            for f, lim in _obj(pol["numeric_limits"], f"{where}.numeric_limits", errors).items():
                lim = _obj(lim, f"{where}.numeric_limits.{f}", errors)
                _unknown(lim, {"min", "max"}, f"{where}.numeric_limits.{f}", errors)
                nl[f] = {k: _num(lim[k], f"{where}.numeric_limits.{f}.{k}", errors)
                         for k in ("min", "max") if lim.get(k) is not None}
            entry["numeric_limits"] = nl
        if pol.get("regex_rules") is not None:
            rr = {}
            for f, pat in _obj(pol["regex_rules"], f"{where}.regex_rules", errors).items():
                try:
                    re.compile(pat)
                    rr[f] = pat
                except (re.error, TypeError):
                    errors.append(f"{where}.regex_rules.{f}: not a valid regular expression")
            entry["regex_rules"] = rr
        if pol.get("max_string_lengths") is not None:
            ml = {}
            for f, n in _obj(pol["max_string_lengths"], f"{where}.max_string_lengths",
                             errors).items():
                if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                    errors.append(f"{where}.max_string_lengths.{f}: must be a non-negative integer")
                else:
                    ml[f] = n
            entry["max_string_lengths"] = ml
        out[name] = entry
    return out


def _roles(raw: Any, actions: dict, errors: list[str]) -> dict:
    out = {}
    for role, r in _obj(raw, "roles", errors).items():
        where = f"roles.{role}"
        if not _key(role, "roles", errors):
            continue
        r = _obj(r, where, errors)
        _unknown(r, _ROLE, where, errors)
        out[role] = {"affordances": _strs(r.get("affordances"), f"{where}.affordances", errors),
                     "tool_allowlist": _strs(r.get("tool_allowlist"), f"{where}.tool_allowlist",
                                             errors)}
    return out


def _zones(raw: Any, errors: list[str]) -> dict:
    out = {}
    for glob, z in _obj(raw, "zones", errors).items():
        where = f"zones.{glob}"
        if not _key(glob, "zones", errors):
            continue
        z = _obj(z, where, errors)
        _unknown(z, _ZONE, where, errors)
        out[glob] = {"restricted": _bool(z.get("restricted"), False, f"{where}.restricted", errors),
                     "capture": _bool(z.get("capture"), True, f"{where}.capture", errors),
                     "private": _bool(z.get("private"), False, f"{where}.private", errors),
                     "sterile": _bool(z.get("sterile"), False, f"{where}.sterile", errors)}
    return out


def _settings(raw: dict, errors: list[str]) -> dict:
    out = {}
    for section, defaults in DEFAULTS.items():
        given = _obj(raw.get(section), section, errors)
        _unknown(given, set(defaults), section, errors)
        merged = copy.deepcopy(defaults)
        for k, v in given.items():
            if k not in defaults:
                continue
            if k in _NUMERIC.get(section, set()):
                merged[k] = _num(v, f"{section}.{k}", errors)
            elif isinstance(defaults[k], bool):
                merged[k] = _bool(v, defaults[k], f"{section}.{k}", errors)
            else:
                merged[k] = _strs(v, f"{section}.{k}", errors)
        out[section] = merged
    bad = [c for c in out["perception"]["untrusted_may_not_trigger"] if c not in CLASSES]
    if bad:
        errors.append(f"perception.untrusted_may_not_trigger: {bad} are not action classes")
    return out


def validate_profile(raw: Any) -> dict:
    """The normalized profile. Raises ProfileError listing every problem."""
    errors: list[str] = []
    raw = _obj(raw, "profile", errors)
    _unknown(raw, _TOP, "profile", errors)
    actions = _actions(raw.get("actions"), errors)
    if not actions:
        errors.append("actions: declare at least one action; undeclared actions are refused")
    unknown = raw.get("unknown_actions", "block")
    if unknown not in ("block", "require_approval"):
        errors.append("unknown_actions: must be 'block' or 'require_approval'")
    profile = {
        "description": raw["description"][:500] if isinstance(raw.get("description"), str) else "",
        "unknown_actions": unknown,
        "require_role": _bool(raw.get("require_role"), False, "require_role", errors),
        "actions": actions,
        "parameter_policies": _param_policies(raw.get("parameter_policies"), actions, errors),
        "roles": _roles(raw.get("roles"), actions, errors),
        "zones": _zones(raw.get("zones"), errors),
        "credential_sources": _strs(raw.get("credential_sources"), "credential_sources", errors),
        "vulnerable_roles": _strs(raw.get("vulnerable_roles"), "vulnerable_roles", errors)
        if raw.get("vulnerable_roles") is not None else ["resident", "patient", "child"],
        **_settings(raw, errors),
    }
    if errors:
        raise ProfileError(errors)
    return profile
