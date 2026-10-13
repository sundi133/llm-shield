"""Persisted delegations: who an agent acted for, auditable and revocable.

core/delegation.py verifies a user token presented with X-On-Behalf-Of (an agent
acting for a person). Verification alone leaves no trail and nothing to revoke.
This records each verified delegation so an operator can see who an agent acted
for and cut a specific delegation off — reusing the existing jti revocation axis
(storage.revocation), the same one that revokes a Shield access token.

Keys (mirroring storage.principal_store conventions — per-tenant, no secrets):
    delegation:{tenant_id}:{jti}   -> the record
    delegations:{tenant_id}        -> [jti, ...] index, newest appended

Recording is opt-in and best-effort (see core.delegation.delegation_persist_enabled)
because resolve_delegation is on the guard path. Revocation works whether or not
a record exists, since it is keyed on the jti.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from storage.revocation import is_jti_revoked, revoke_jti
from storage.tenant_store import kv_get, kv_set

logger = logging.getLogger("votal.delegation_store")

_REC_PREFIX = "delegation:"
_IDX_PREFIX = "delegations:"
_MAX_INDEX = 2000
_GRACE = 86400          # keep the record a day past expiry to explain it


def _now() -> int:
    return int(time.time())


def _rec_key(tenant_id: str, jti: str) -> str:
    return f"{_REC_PREFIX}{tenant_id}:{jti}"


def _idx_key(tenant_id: str) -> str:
    return f"{_IDX_PREFIX}{tenant_id}"


def _mark_revoked(rec: dict, jti: str) -> dict:
    rec = dict(rec)
    rec["revoked"] = bool(rec.get("revoked")) or is_jti_revoked(jti)
    return rec


def record_delegation(tenant_id: str, *, jti: str, issuer: str = "",
                      user_sub: str = "", agent: str = "", roles=(),
                      expires_at: int = 0) -> None:
    """Record a verified delegation, first-seen only (deduped by jti). TTL'd to
    the token's expiry plus a grace day. Best-effort — never raises."""
    if not tenant_id or not jti:
        return
    try:
        key = _rec_key(tenant_id, jti)
        if kv_get(key) is not None:
            return          # already recorded; one write per jti, not per call
        now = _now()
        exp = int(expires_at or 0)
        record = {
            "jti": jti, "issuer": issuer, "user_sub": user_sub, "agent": agent,
            "roles": list(roles or []), "issued_at": now,
            "expires_at": exp, "revoked": False,
        }
        ttl = (exp - now + _GRACE) if exp > now else None
        kv_set(key, record, ttl=ttl)
        ids = [i for i in (kv_get(_idx_key(tenant_id)) or []) if isinstance(i, str)]
        if jti not in ids:
            ids.append(jti)
            kv_set(_idx_key(tenant_id), ids[-_MAX_INDEX:])
    except Exception as e:       # noqa: BLE001
        logger.debug("delegation record not written: %s", e)


def list_delegations(tenant_id: str) -> list:
    """Every recorded delegation for a tenant, newest first, each flagged with
    its live revoked state."""
    out = []
    for jti in [i for i in (kv_get(_idx_key(tenant_id)) or []) if isinstance(i, str)]:
        rec = kv_get(_rec_key(tenant_id, jti))
        if isinstance(rec, dict):
            out.append(_mark_revoked(rec, jti))
    out.sort(key=lambda r: r.get("issued_at") or 0, reverse=True)
    return out


def get_delegation(tenant_id: str, jti: str) -> Optional[dict]:
    rec = kv_get(_rec_key(tenant_id, jti))
    return _mark_revoked(rec, jti) if isinstance(rec, dict) else None


def revoke_delegation(tenant_id: str, jti: str) -> bool:
    """Revoke a delegation by jti: the delegated token is refused from the next
    verify. Works even if no record exists (the jti axis is authoritative);
    returns True when a record was also found and flagged."""
    if not jti:
        return False
    rec = kv_get(_rec_key(tenant_id, jti))
    # Revoke for at least the token's remaining life (plus grace) so the block
    # outlasts the token rather than the revocation store's short default.
    ttl = None
    if isinstance(rec, dict):
        exp = int(rec.get("expires_at") or 0)
        if exp > _now():
            ttl = exp - _now() + _GRACE
    revoke_jti(jti, ttl) if ttl else revoke_jti(jti)
    if isinstance(rec, dict):
        rec = dict(rec)
        rec["revoked"] = True
        kv_set(_rec_key(tenant_id, jti), rec)
        return True
    return False
