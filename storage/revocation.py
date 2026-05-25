"""Revocation lists for agent tokens and capability tokens.

Three independent revocation axes:
  - agent_instance_id : kills one running agent process (AuthN)
  - user_sub          : kills everything a compromised user did (AuthN)
  - jti / cap_id      : kills one specific token (AuthN or AuthZ)

Backed by Redis when available, falling back to the in-process
_fallback_store dict (same pattern as tenant_store / cert_registry).

Entries auto-expire via TTL slightly longer than the maximum token
lifetime so the set stays bounded.
"""

from __future__ import annotations

import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

# TTL must be > MAX_TOKEN_TTL_SECONDS (15m) for agent tokens and
# CAP_MAX_TTL_SECONDS (60s) for caps. Use 1 hour to be safe.
DEFAULT_REVOKE_TTL = 3600

_INSTANCE_KEY = "shield:revoke:instance:"
_JTI_KEY = "shield:revoke:jti:"
_USER_KEY = "shield:revoke:user:"


def _set(key: str, ttl: int) -> None:
    r = _get_redis()
    if r:
        try:
            r.set(key, "1", ex=ttl)
            return
        except Exception:
            pass
    _fallback_store[key] = str(int(time.time()) + ttl)


def _exists(key: str) -> bool:
    r = _get_redis()
    if r:
        try:
            return bool(r.get(key))
        except Exception:
            pass
    val = _fallback_store.get(key)
    if not val:
        return False
    try:
        if int(val) < int(time.time()):
            _fallback_store.pop(key, None)
            return False
    except ValueError:
        return False
    return True


def revoke_instance(agent_instance_id: str, ttl: int = DEFAULT_REVOKE_TTL) -> None:
    _set(_INSTANCE_KEY + agent_instance_id, ttl)


def revoke_jti(jti: str, ttl: int = DEFAULT_REVOKE_TTL) -> None:
    _set(_JTI_KEY + jti, ttl)


def revoke_user(user_sub: str, ttl: int = DEFAULT_REVOKE_TTL) -> None:
    _set(_USER_KEY + user_sub, ttl)


def is_instance_revoked(agent_instance_id: str) -> bool:
    return _exists(_INSTANCE_KEY + agent_instance_id)


def is_jti_revoked(jti: str) -> bool:
    return _exists(_JTI_KEY + jti)


def is_user_revoked(user_sub: str) -> bool:
    return _exists(_USER_KEY + user_sub)


def clear_all_for_tests() -> None:
    """Wipe revocation entries from the fallback store. Tests only."""
    keys = [
        k for k in list(_fallback_store.keys())
        if k.startswith(_INSTANCE_KEY) or k.startswith(_JTI_KEY) or k.startswith(_USER_KEY)
    ]
    for k in keys:
        _fallback_store.pop(k, None)
