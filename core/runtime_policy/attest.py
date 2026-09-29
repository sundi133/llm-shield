"""Runtime attestation: is this agent running inside the boundary its profile
says it should be?

The broker that starts a sandbox from a verified runtime bundle mints the
agent's token with ``runtime_profile_hash`` = the bundle's profile hash. At
cap/mint Shield compares that claim with the profile's CURRENT hash:

  off      nothing (default)
  warn     mismatch -> decision-audit row + drift record, the cap is minted
  enforce  mismatch -> 403 until the sandbox restarts on the current bundle

Mismatches (and tokens with no claim at all) are kept per instance, so the
drift endpoint can list sandboxes still running an old policy. Only a
mismatch writes; a matching token costs a comparison.
Spec: docs/specs/infra-guardrails.md §4.3, task 6.

Live updates (docs/specs/runtime-live-policy.md §4.3, §6): the sync sidecar
applies a new profile to a RUNNING sandbox and reports it, so the token's
claim goes stale while the sandbox is current. Those reports are kept per
instance in ``rtapplied:{tenant}:{profile}``. On a mismatch only, one read of
that record lets the mint through when the report is TRUSTED (posted with an
admin-scoped key, never an agent's own) and says the instance runs the
current hash. SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED=0 turns that off.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Optional

from core.runtime_policy.check import profile_for

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DRIFT_TTL = 7 * 86400
APPLIED_TTL = 7 * 86400
#: What the sidecar reports (event detail.op) -> the instance's state.
APPLY_OPS = {"applied": "current", "reverted": "reverted", "restart_required":
             "restart_required", "tampered": "tampered", "apply_failed": "apply_failed"}
#: States in which the instance runs the policy its record names.
_RUNNING_STATES = ("current", "reverted")
_mem: dict[str, dict[str, str]] = {}
_applied_mem: dict[str, dict[str, str]] = {}


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant_id: str, profile: str) -> str:
    return f"rtdrift:{tenant_id}:{profile}"


def _akey(tenant_id: str, profile: str) -> str:
    return f"rtapplied:{tenant_id}:{profile}"


def _loads(v) -> Optional[dict]:
    try:
        rec = json.loads(v.decode() if isinstance(v, (bytes, bytearray)) else v)
    except (ValueError, TypeError, AttributeError):
        return None
    return rec if isinstance(rec, dict) else None


def accept_applied() -> bool:
    return os.environ.get("SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED", "1").strip() != "0"


# ── applied state (reported by the sync sidecar) ─────────────────────


def record_applied(tenant_id: str, profile: str, instance: str, *, op: str,
                   profile_hash: str, runtime_hash: str = "", runtime_version=None,
                   target_hash: str = "", lock: str = "", reconcile: str = "",
                   detail: str = "", trusted: bool = False, at: Optional[float] = None) -> None:
    """Best effort. ``profile_hash`` is the policy the instance RUNS now (for
    restart_required that is still the old one; ``target_hash`` is the one it
    could not take)."""
    if op not in APPLY_OPS or not instance or not profile:
        return
    rec = json.dumps({"instance": instance, "state": APPLY_OPS[op], "profile_hash": profile_hash,
                      "runtime_hash": runtime_hash, "runtime_version": runtime_version,
                      "target_hash": target_hash, "lock": lock, "reconcile": reconcile,
                      "detail": detail[:500], "trusted": bool(trusted),
                      "at": at if at is not None else time.time()})
    try:
        r = _redis()
        if r is None:
            _applied_mem.setdefault(_akey(tenant_id, profile), {})[instance] = rec
        else:
            r.hset(_akey(tenant_id, profile), instance, rec)
            r.expire(_akey(tenant_id, profile), APPLIED_TTL)
    except Exception:
        pass


def applied_for(tenant_id: str, profile: str, instance: str) -> Optional[dict]:
    try:
        r = _redis()
        if r is None:
            raw = _applied_mem.get(_akey(tenant_id, profile), {}).get(instance)
        else:
            raw = r.hget(_akey(tenant_id, profile), instance)
    except Exception:
        return None
    return _loads(raw) if raw is not None else None


def list_applied(tenant_id: str, profile: str) -> list[dict]:
    try:
        r = _redis()
        raw = (_applied_mem.get(_akey(tenant_id, profile), {}) if r is None
               else r.hgetall(_akey(tenant_id, profile)) or {})
    except Exception:
        return []
    out = [rec for rec in (_loads(v) for v in raw.values()) if rec]
    return sorted(out, key=lambda r: r.get("at") or 0, reverse=True)


def runs_current(rec: Optional[dict], current_hash: str) -> bool:
    """A trusted report says this instance runs ``current_hash``."""
    return bool(rec and rec.get("trusted") and rec.get("state") in _RUNNING_STATES
                and rec.get("profile_hash") == current_hash)


def instances(tenant_id: str, profile: str, current_hash: str) -> list[dict]:
    """Every instance Shield has heard about for this profile, from the
    sidecar's reports and from attestation at cap/mint, merged per instance."""
    merged: dict[str, dict] = {}
    for rec in list_applied(tenant_id, profile):
        merged[rec["instance"]] = {**rec, "attested_hash": None, "attested_at": None}
    for rec in _drift_records(tenant_id, profile):
        name = rec.get("instance") or rec.get("agent_id") or "unknown"
        entry = merged.setdefault(name, {"instance": name, "state": None, "profile_hash": None,
                                         "trusted": False, "at": None})
        entry["attested_hash"] = rec.get("attested_hash")
        entry["attested_at"] = rec.get("at")
        entry.setdefault("agent_id", rec.get("agent_id"))
    for entry in merged.values():
        entry["on_current"] = runs_current(entry, current_hash) or \
            entry.get("attested_hash") == current_hash
    return sorted(merged.values(), key=lambda e: e.get("at") or e.get("attested_at") or 0,
                  reverse=True)


def record_drift(tenant_id: str, profile: str, *, instance: str, agent_id: str,
                 got: str, expected: str) -> None:
    rec = json.dumps({"agent_id": agent_id, "instance": instance, "attested_hash": got,
                      "expected_hash": expected, "at": time.time()})
    field = instance or agent_id or "unknown"
    try:
        r = _redis()
        if r is None:
            _mem.setdefault(_key(tenant_id, profile), {})[field] = rec
        else:
            r.hset(_key(tenant_id, profile), field, rec)
            r.expire(_key(tenant_id, profile), DRIFT_TTL)
    except Exception:
        pass


def _drift_records(tenant_id: str, profile: str) -> list[dict]:
    r = _redis()
    if r is None:
        raw = _mem.get(_key(tenant_id, profile), {})
    else:
        raw = r.hgetall(_key(tenant_id, profile)) or {}
    return [rec for rec in (_loads(v) for v in raw.values()) if rec]


def list_drift(tenant_id: str, profile: str, current_hash: str) -> list[dict]:
    """Instances seen attesting a hash other than the current one, except
    those a trusted sidecar report says were since updated in place."""
    applied = ({rec["instance"]: rec for rec in list_applied(tenant_id, profile)}
               if accept_applied() else {})
    out = []
    for rec in _drift_records(tenant_id, profile):
        if rec.get("attested_hash") == current_hash:
            continue
        if runs_current(applied.get(rec.get("instance") or ""), current_hash):
            continue
        rec["expected_hash"] = current_hash
        out.append(rec)
    return sorted(out, key=lambda r: r.get("at") or 0, reverse=True)


def reset_memory() -> None:
    _mem.clear()
    _applied_mem.clear()


def check_attestation(tenant_id: Optional[str], *, agent_id: str, instance_id: str,
                      claims: dict) -> Optional[dict]:
    """None when there is nothing to report; otherwise
    {mode: warn|enforce, profile, expected, got, reason}."""
    cp = profile_for(tenant_id, agent_id)
    if cp is None:
        return None
    mode = cp.raw["identity"].get("require_attestation", "off")
    if mode == "off":
        return None
    got = str(claims.get("runtime_profile_hash") or "")
    if got == cp.hash:
        return None
    # The token was minted before a live update. One read, only on this path.
    if instance_id and accept_applied() and \
            runs_current(applied_for(tenant_id, cp.name, instance_id), cp.hash):
        return None
    if not got:
        reason = (f"runtime attestation: the agent token carries no runtime_profile_hash; "
                  f"profile '{cp.name}' requires one")
    else:
        reason = (f"runtime attestation: this sandbox runs profile hash {got[:19]}..., the "
                  f"current '{cp.name}' is {cp.hash[:19]}...; restart it on the current bundle")
    record_drift(tenant_id, cp.name, instance=instance_id, agent_id=agent_id, got=got,
                 expected=cp.hash)
    return {"mode": mode, "profile": cp.name, "expected": cp.hash, "got": got,
            "reason": reason}


def identity_requirement(tenant_id: Optional[str], agent_key: Optional[str],
                         agent_verified: bool) -> Optional[dict]:
    """A blocking result when the agent's profile requires a verified identity
    (agent token, mTLS or OIDC) and this call's identity was only asserted."""
    cp = profile_for(tenant_id, agent_key)
    if cp is None or not cp.raw["identity"].get("require_agent_token") or agent_verified:
        return None
    return {"guardrail": "runtime_boundary", "passed": False, "action": "block",
            "message": (f"Runtime boundary ({cp.name}): this agent must present a verified "
                        f"identity (agent token, mTLS or OIDC); the agent key was only "
                        f"asserted"),
            "details": {"profile": cp.name, "profile_hash": cp.hash,
                        "violations": [{"kind": "identity", "value": "",
                                        "reason": "verified agent identity required"}]},
            "latency_ms": 0.0}
