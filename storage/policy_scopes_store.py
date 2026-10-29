"""Persistence for policy scopes (docs/specs/policy-scopes.md, task 2).

``policy_scopes`` lives inside the tenant record, next to the global
``input_guardrails`` / ``output_guardrails``, so the guard path reads it from
the tenant config it already caches and never makes a call of its own.

Every write is read-modify-write of that one field: copy, change, bump
``version``, validate, save. ``get_tenant`` returns the store's shared cached
dict, so nothing here touches it before :func:`update_tenant` replaces the
field. ``expected_version`` gives callers optimistic concurrency; without it
the last writer wins, as for every other tenant config write.
"""

from __future__ import annotations

import copy
import logging
import os
import threading
import time
from typing import Callable, Optional

from core.policy_scopes import validate_scopes
from storage.tenant_store import get_tenant, list_tenant_api_keys, update_tenant

logger = logging.getLogger("votal.policy_scopes")

FIELD = "policy_scopes"


class TenantNotFound(Exception):
    pass


class VersionConflict(Exception):
    def __init__(self, current: int):
        super().__init__(f"policy scopes changed since version {current}")
        self.current = current


class InvalidScopes(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class KeyPrefixNotFound(Exception):
    pass


class AmbiguousKeyPrefix(Exception):
    pass


def empty_scopes() -> dict:
    """What a tenant that never configured scopes reads as. Off."""
    return {"version": 0, "enabled": False, "selectors": [], "missing": "global",
            "rules": [], "key_bindings": {}}


def _tenant(tenant_id: str) -> dict:
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise TenantNotFound(tenant_id)
    return tenant


def _scopes_of(tenant: dict) -> dict:
    stored = tenant.get(FIELD)
    return copy.deepcopy(stored) if isinstance(stored, dict) else empty_scopes()


def get_scopes(tenant_id: str) -> tuple[dict, dict]:
    """``(tenant_config, policy_scopes)``. The scopes are a private copy."""
    tenant = _tenant(tenant_id)
    return tenant, _scopes_of(tenant)


def stale_warnings(tenant: dict, scopes: dict) -> list[str]:
    """Rules that no longer pass against the *current* global policy.

    Writes only check the rule they touch, so a global edit can leave an older
    rule asking for something global now forbids. The merge already ignores
    that part at runtime; this tells the admin so they can fix the rule.
    """
    return validate_scopes(scopes, tenant)


def change_scopes(
    tenant_id: str,
    mutate: Callable[[dict], None],
    expected_version: Optional[int] = None,
    only_rules: Optional[set] = None,
    check_unmatched: bool = False,
) -> dict:
    """Apply ``mutate`` to a copy of the tenant's scopes, validate, save.

    ``only_rules`` / ``check_unmatched`` say which local policies this write
    touched; those are checked against the global policy, everything else only
    for shape and limits (see ``core.policy_scopes.validate_rule``). ``mutate``
    may raise ``LookupError`` for a missing rule; it propagates unchanged.
    """
    tenant = _tenant(tenant_id)
    scopes = _scopes_of(tenant)
    current = int(scopes.get("version") or 0)
    if expected_version is not None and expected_version != current:
        raise VersionConflict(current)
    mutate(scopes)
    scopes["version"] = current + 1
    errors = validate_scopes(scopes, tenant, only_rules=only_rules or set(),
                             check_unmatched=check_unmatched)
    if errors:
        raise InvalidScopes(errors)
    update_tenant(tenant_id, {FIELD: scopes})
    return copy.deepcopy(scopes)


def resolve_key_prefix(tenant_id: str, prefix: str) -> str:
    """Check a key-binding prefix names exactly one of this tenant's keys.

    The prefix is the first 12 characters the portal already shows for each
    key. Binding a prefix that matches none would bind nothing; one that
    matches two would bind a key the admin didn't mean.
    """
    matches = [k for k in list_tenant_api_keys(tenant_id) if k.get("prefix") == prefix]
    if not matches:
        raise KeyPrefixNotFound(prefix)
    if len(matches) > 1:
        raise AmbiguousKeyPrefix(prefix)
    return prefix


# ---------------------------------------------------------------------------
# Discovery: which header values the guard path has seen (task 4)
# ---------------------------------------------------------------------------
#
# Tenants don't know their teams' header values in advance, so Shield records
# every value it sees and the portal lists them before any rule exists.
#
# On the guard path: one dict update under a lock, no I/O (the pattern of
# core/discovery/guarded.py). A background thread flushes at most every
# SHIELD_POLICY_SCOPE_FLUSH_SECONDS into three hashes per tenant, TTL 30 days:
#
#   policy_scope_seen:{tenant}         value -> request count (HINCRBY)
#   policy_scope_seen_first:{tenant}   value -> first seen, epoch s (HSETNX)
#   policy_scope_seen_last:{tenant}    value -> "{epoch s}|{header}"
#
# At most SEEN_CAP values per tenant; requests carrying further new values
# count under OVERFLOW, so a caller spraying random values can't grow the
# store. Best effort throughout: a lost flush loses counts, never a request.

SEEN_CAP = 2000
SEEN_TTL_S = 30 * 86400
OVERFLOW = "(overflow)"
_BUF_CAP = 50_000

_seen_buf: dict[tuple[str, str], list] = {}   # (tenant, value) -> [count, first, last, header]
_seen_lock = threading.Lock()
_seen_last_flush = 0.0
_seen_busy = False


def discovery_enabled() -> bool:
    return os.environ.get("SHIELD_POLICY_SCOPE_DISCOVERY", "on").strip().lower() \
        not in ("off", "0", "false", "no")


def _flush_interval() -> float:
    try:
        return max(1.0, float(os.environ.get("SHIELD_POLICY_SCOPE_FLUSH_SECONDS", "15")))
    except (TypeError, ValueError):
        return 15.0


def record_seen(tenant_id: str, value: str, header: Optional[str]) -> None:
    """Count one request's header value. Never raises, never does I/O."""
    if not tenant_id or not value or not discovery_enabled():
        return
    try:
        now = int(time.time())
        with _seen_lock:
            entry = _seen_buf.get((tenant_id, value))
            if entry is not None:
                entry[0] += 1
                entry[2] = now
                if header:
                    entry[3] = header
            elif len(_seen_buf) < _BUF_CAP:
                _seen_buf[(tenant_id, value)] = [1, now, now, header or ""]
        _maybe_flush_seen()
    except Exception:
        pass


def _maybe_flush_seen() -> None:
    global _seen_last_flush, _seen_busy
    now = time.time()
    if now - _seen_last_flush < _flush_interval() or _seen_busy:
        return
    _seen_last_flush, _seen_busy = now, True
    threading.Thread(target=_flush_seen_thread, daemon=True).start()


def _flush_seen_thread() -> None:
    global _seen_busy
    try:
        flush_seen()
    finally:
        _seen_busy = False


def _keys(tenant_id: str) -> tuple[str, str, str]:
    return (f"policy_scope_seen:{tenant_id}", f"policy_scope_seen_first:{tenant_id}",
            f"policy_scope_seen_last:{tenant_id}")


def _decode(v):
    return v.decode() if isinstance(v, bytes) else v


def flush_seen() -> int:
    """Write the buffered counts. Returns how many (tenant, value) pairs."""
    with _seen_lock:
        batch = dict(_seen_buf)
        _seen_buf.clear()
    if not batch:
        return 0
    by_tenant: dict[str, dict[str, list]] = {}
    for (tenant_id, value), entry in batch.items():
        by_tenant.setdefault(tenant_id, {})[value] = entry
    try:
        from storage.tenant_store import _fallback_store, _get_redis
        r = _get_redis()
        for tenant_id, values in by_tenant.items():
            if r:
                _flush_tenant_redis(r, tenant_id, values)
            else:
                _flush_tenant_memory(_fallback_store, tenant_id, values)
        return len(batch)
    except Exception as e:      # noqa: BLE001
        logger.warning("policy scopes: dropped %d discovery counts: %s", len(batch), e)
        return 0


def _fold_overflow(values: dict[str, list], known: set, room: int) -> dict[str, list]:
    """Keep known values and up to ``room`` new ones; fold the rest into OVERFLOW."""
    out: dict[str, list] = {}
    for value, entry in sorted(values.items(), key=lambda kv: -kv[1][0]):
        if value in known or value == OVERFLOW:
            out[value] = entry
        elif room > 0:
            out[value] = entry
            room -= 1
        else:
            o = out.setdefault(OVERFLOW, [0, entry[1], entry[2], ""])
            o[0] += entry[0]
            o[1], o[2] = min(o[1], entry[1]), max(o[2], entry[2])
    return out


def _flush_tenant_redis(r, tenant_id: str, values: dict[str, list]) -> None:
    counts, first, last = _keys(tenant_id)
    names = list(values)
    pipe = r.pipeline()
    pipe.hlen(counts)
    for v in names:
        pipe.hexists(counts, v)
    res = pipe.execute()
    known = {v for v, hit in zip(names, res[1:]) if hit}
    values = _fold_overflow(values, known, SEEN_CAP - int(res[0] or 0))
    pipe = r.pipeline()
    for value, (count, f, l, header) in values.items():
        pipe.hincrby(counts, value, count)
        pipe.hsetnx(first, value, f)
        pipe.hset(last, value, f"{l}|{header}")
    for key in (counts, first, last):
        pipe.expire(key, SEEN_TTL_S)
    pipe.execute()


def _flush_tenant_memory(store: dict, tenant_id: str, values: dict[str, list]) -> None:
    counts, first, last = (store.setdefault(k, {}) for k in _keys(tenant_id))
    values = _fold_overflow(values, set(counts), SEEN_CAP - len(counts))
    for value, (count, f, l, header) in values.items():
        counts[value] = int(counts.get(value, 0)) + count
        first.setdefault(value, f)
        last[value] = f"{l}|{header}"


def read_seen(tenant_id: str) -> list[dict]:
    """Every value seen in the last 30 days, most requests first.

    Flushes this process's buffer first, so a value just seen here shows up.
    Other processes flush on their own interval.
    """
    flush_seen()
    from storage.tenant_store import _fallback_store, _get_redis
    r = _get_redis()
    counts_key, first_key, last_key = _keys(tenant_id)
    if r:
        counts, first, last = (r.hgetall(k) or {} for k in (counts_key, first_key, last_key))
    else:
        counts, first, last = (dict(_fallback_store.get(k) or {})
                               for k in (counts_key, first_key, last_key))
    first = {_decode(k): v for k, v in first.items()}
    last = {_decode(k): _decode(v) for k, v in last.items()}
    out = []
    for value, count in counts.items():
        value = _decode(value)
        seen_at, _, header = str(last.get(value) or "").partition("|")
        try:
            out.append({"value": value, "count": int(count),
                        "first_seen": int(first.get(value) or 0),
                        "last_seen": int(seen_at or 0), "header": header or None})
        except (TypeError, ValueError):
            continue
    out.sort(key=lambda e: (-e["count"], e["value"]))
    return out


def reset_seen_for_tests() -> None:
    global _seen_last_flush, _seen_busy
    with _seen_lock:
        _seen_buf.clear()
    _seen_last_flush, _seen_busy = 0.0, False
