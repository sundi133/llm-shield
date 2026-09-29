"""Tenant-scoped storage for runtime profiles.

One Redis hash per tenant, ``rtprofile:{tenant_id}``: field = profile name,
value = the normalized profile JSON. Reads validate again, so a hand-edited or
corrupt record is reported, never enforced. Without Redis (dev and tests) an
in-process dict holds the same shape.

Every save also pushes the version onto ``rtprofile_hist:{tenant_id}:{name}``
(newest first, last HISTORY_MAX kept), so the portal can diff versions and
preview whether a change applies to running sandboxes.
Spec: docs/specs/runtime-live-policy.md §4.1.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from core.runtime_policy.model import MAX_PROFILES, ProfileError, profile_hash, validate_profile

HISTORY_MAX = 20

_mem: dict[str, dict[str, str]] = {}
_hist_mem: dict[str, list[str]] = {}


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant_id: str) -> str:
    return f"rtprofile:{tenant_id}"


def _hist_key(tenant_id: str, name: str) -> str:
    return f"rtprofile_hist:{tenant_id}:{name}"


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


def save_profile(tenant_id: str, name: str, profile: dict, actor: str = "",
                 reason: str = "put") -> dict:
    """Validate (raises ProfileError), store, and record the version in the
    profile's history. Returns the normalized profile."""
    normalized = validate_profile(profile)
    existing = _all_raw(tenant_id)
    if name not in existing and len(existing) >= MAX_PROFILES:
        raise ProfileError([f"at most {MAX_PROFILES} runtime profiles per tenant"])
    now = int(time.time())
    record = json.dumps({"profile": normalized, "updated_at": now,
                         "updated_by": actor[:200]}, separators=(",", ":"))
    r = _redis()
    if r is None:
        _mem.setdefault(_key(tenant_id), {})[name] = record
    else:
        r.hset(_key(tenant_id), name, record)
    _push_history(tenant_id, name, normalized, actor=actor, reason=reason, at=now)
    return normalized


def _push_history(tenant_id: str, name: str, profile: dict, *, actor: str, reason: str,
                  at: int) -> None:
    """Best effort: history is for review, never a reason to fail a save.
    Saving the same content twice records one version."""
    phash = profile_hash(profile)
    head = history(tenant_id, name, limit=1)
    if head and head[0].get("hash") == phash:
        return
    entry = json.dumps({"hash": phash, "profile": profile, "at": at,
                        "actor": actor[:200], "reason": reason[:100]},
                       separators=(",", ":"))
    try:
        r = _redis()
        if r is None:
            lst = _hist_mem.setdefault(_hist_key(tenant_id, name), [])
            lst.insert(0, entry)
            del lst[HISTORY_MAX:]
        else:
            r.lpush(_hist_key(tenant_id, name), entry)
            r.ltrim(_hist_key(tenant_id, name), 0, HISTORY_MAX - 1)
    except Exception:
        pass


def history(tenant_id: str, name: str, limit: int = HISTORY_MAX) -> list[dict]:
    """Saved versions, newest first: {hash, profile, at, actor, reason}.
    Unreadable entries are skipped."""
    limit = max(1, min(limit, HISTORY_MAX))
    try:
        r = _redis()
        if r is None:
            raw = _hist_mem.get(_hist_key(tenant_id, name), [])[:limit]
        else:
            raw = r.lrange(_hist_key(tenant_id, name), 0, limit - 1) or []
    except Exception:
        return []
    out = []
    for v in raw:
        try:
            entry = json.loads(_decode(v))
        except (ValueError, TypeError):
            continue
        if isinstance(entry, dict) and isinstance(entry.get("profile"), dict):
            out.append(entry)
    return out


def delete_profile(tenant_id: str, name: str) -> bool:
    r = _redis()
    if r is None:
        _hist_mem.pop(_hist_key(tenant_id, name), None)
        return _mem.get(_key(tenant_id), {}).pop(name, None) is not None
    r.delete(_hist_key(tenant_id, name))
    return bool(r.hdel(_key(tenant_id), name))


def reset_memory() -> None:
    """Test helper."""
    _mem.clear()
    _hist_mem.clear()
