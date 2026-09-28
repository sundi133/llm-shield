"""Tenant-scoped storage for runtime profiles.

One Redis hash per tenant, ``rtprofile:{tenant_id}``: field = profile name,
value = the normalized profile JSON. Reads validate again, so a hand-edited or
corrupt record is reported, never enforced. Without Redis (dev and tests) an
in-process dict holds the same shape.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from core.runtime_policy.model import MAX_PROFILES, ProfileError, profile_hash, validate_profile

_mem: dict[str, dict[str, str]] = {}


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant_id: str) -> str:
    return f"rtprofile:{tenant_id}"


def _decode(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _all_raw(tenant_id: str) -> dict[str, str]:
    r = _redis()
    if r is None:
        return dict(_mem.get(_key(tenant_id), {}))
    raw = r.hgetall(_key(tenant_id)) or {}
    if isinstance(raw, (list, tuple)):
        raw = {raw[i]: raw[i + 1] for i in range(0, len(raw) - 1, 2)}
    return {_decode(k): _decode(v) for k, v in raw.items()}


def _parse(raw: str) -> dict:
    record = json.loads(raw)
    record["profile"] = validate_profile(record.get("profile"))
    return record


def list_profiles(tenant_id: str) -> dict[str, dict]:
    """name -> {profile, hash, updated_at} or {error} for a record that no
    longer validates."""
    out: dict[str, dict] = {}
    for name, raw in sorted(_all_raw(tenant_id).items()):
        try:
            rec = _parse(raw)
            out[name] = {**rec, "hash": profile_hash(rec["profile"])}
        except (ProfileError, ValueError, TypeError) as e:
            out[name] = {"error": getattr(e, "errors", None) or [str(e)]}
    return out


def get_profile(tenant_id: str, name: str) -> Optional[dict]:
    """The normalized profile, or None. Raises ProfileError if the stored
    record no longer validates."""
    raw = _all_raw(tenant_id).get(name)
    if raw is None:
        return None
    return _parse(raw)["profile"]


def save_profile(tenant_id: str, name: str, profile: dict, actor: str = "") -> dict:
    """Validate (raises ProfileError) and store. Returns the normalized profile."""
    normalized = validate_profile(profile)
    existing = _all_raw(tenant_id)
    if name not in existing and len(existing) >= MAX_PROFILES:
        raise ProfileError([f"at most {MAX_PROFILES} runtime profiles per tenant"])
    record = json.dumps({"profile": normalized, "updated_at": int(time.time()),
                         "updated_by": actor[:200]}, separators=(",", ":"))
    r = _redis()
    if r is None:
        _mem.setdefault(_key(tenant_id), {})[name] = record
    else:
        r.hset(_key(tenant_id), name, record)
    return normalized


def delete_profile(tenant_id: str, name: str) -> bool:
    r = _redis()
    if r is None:
        return _mem.get(_key(tenant_id), {}).pop(name, None) is not None
    return bool(r.hdel(_key(tenant_id), name))


def reset_memory() -> None:
    """Test helper."""
    _mem.clear()
