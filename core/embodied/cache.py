"""Per-replica cache of action profiles for POST /v1/shield/embodied/check.

One store read per (tenant, profile) every SHIELD_EMBODIED_CACHE_S seconds
(default 5), like runtime profiles. When the store cannot be read, a profile
already cached (even past its TTL) keeps being used; with none cached the
caller blocks. A physical action fails safe, unlike cross-app flow, which fails
open. Spec: docs/specs/embodied-action-guard.md §4, §10.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

from core.embodied import store as em_store
from core.embodied.model import ProfileError, profile_hash

_lock = threading.Lock()
_cache: dict[tuple[str, str], tuple[float, Optional[dict], str]] = {}


class Unavailable(Exception):
    """The store could not be read and nothing is cached."""


def _ttl() -> float:
    try:
        return max(0.0, float(os.environ.get("SHIELD_EMBODIED_CACHE_S", "5")))
    except ValueError:
        return 5.0


def get(tenant_id: str, name: str) -> Optional[tuple[dict, str]]:
    """(profile, hash), None when the profile does not exist. Raises
    ProfileError for a stored profile that no longer validates, and
    Unavailable when the store is down and nothing is cached."""
    key = (tenant_id, name)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
    if hit and hit[0] > now:
        return None if hit[1] is None else (hit[1], hit[2])
    try:
        profile = em_store.get_profile(tenant_id, name)
    except ProfileError:
        raise
    except Exception as e:
        if hit and hit[1] is not None:
            return hit[1], hit[2]
        raise Unavailable(str(e)) from e
    entry = (now + _ttl(), profile, profile_hash(profile) if profile else "")
    with _lock:
        _cache[key] = entry
    return None if profile is None else (profile, entry[2])


def invalidate(tenant_id: Optional[str] = None) -> None:
    with _lock:
        if tenant_id is None:
            _cache.clear()
        else:
            for k in [k for k in _cache if k[0] == tenant_id]:
                _cache.pop(k, None)
