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
"""

from __future__ import annotations

import json
import re
import time
from typing import Optional

from core.runtime_policy.check import profile_for

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DRIFT_TTL = 7 * 86400
_mem: dict[str, dict[str, str]] = {}


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant_id: str, profile: str) -> str:
    return f"rtdrift:{tenant_id}:{profile}"


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


def list_drift(tenant_id: str, profile: str, current_hash: str) -> list[dict]:
    """Instances seen attesting a hash other than the current one."""
    r = _redis()
    if r is None:
        raw = _mem.get(_key(tenant_id, profile), {})
    else:
        raw = r.hgetall(_key(tenant_id, profile)) or {}
    out = []
    for v in raw.values():
        try:
            rec = json.loads(v.decode() if isinstance(v, (bytes, bytearray)) else v)
        except (ValueError, TypeError):
            continue
        if rec.get("attested_hash") != current_hash:
            rec["expected_hash"] = current_hash
            out.append(rec)
    return sorted(out, key=lambda r: r.get("at") or 0, reverse=True)


def reset_memory() -> None:
    _mem.clear()


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
