"""Admin-plane credentials: many named, expiring, revocable admin keys.

The admin plane has historically authenticated with ONE shared secret,
SHIELD_ADMIN_KEY (core/auth.py). Every holder is interchangeable and anonymous,
so a partner such as Rafay could only be given the platform root secret — which
cannot be attributed, expired, or revoked without rotating it for everyone.

This is the storage half of fixing that. An operator mints a named credential
(shadm_...), hands it out, and every admin action made with it is attributable
to its stable id and revocable on its own. SHIELD_ADMIN_KEY stays as the root /
break-glass credential and the bootstrap for minting the first managed one.

Keys:
    admincred:{sha256(secret)}  → the credential record (resolve-by-secret, O(1))
    admincred_id:{id}           → sha256(secret), so revoke/rotate find the hash
    admincreds                  → [id, ...] listing index

Platform-level, NOT tenant-scoped: an admin credential governs the platform.
Expiry is checked here (the single choke point), mirroring
storage.principal_store.resolve_principal_key. The secret is returned only at
mint; listings carry a prefix, never the secret or its full hash. Nothing here
runs on the guard path.

Spec: docs/specs/admin-partner-credentials.md (Task 1).
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from typing import Optional

from storage.tenant_store import kv_delete, kv_get, kv_set

logger = logging.getLogger("votal.admin_credentials")

_SECRET_PREFIX = "shadm_"
_CRED_PREFIX = "admincred:"
_ID_PREFIX = "admincred_id:"
_INDEX_KEY = "admincreds"

_PREFIX_LEN = 14              # shadm_ + 8 hex, enough to recognise, not to use
_MAX_NAME_LEN = 128
_MAX_CREDENTIALS = 1000       # a sane ceiling; the index is a single list
_PUBLIC_FIELDS = ("id", "name", "prefix", "created_at", "created_by",
                  "expires_at", "disabled", "last_used", "scope")


def _now() -> int:
    return int(time.time())


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _cred_key(key_hash: str) -> str:
    return f"{_CRED_PREFIX}{key_hash}"


def _id_key(cred_id: str) -> str:
    return f"{_ID_PREFIX}{cred_id}"


def _public(record: dict) -> dict:
    """A record safe to return from a read endpoint: no secret, no full hash."""
    return {k: record.get(k) for k in _PUBLIC_FIELDS if k in record}


def _index() -> list:
    return [i for i in (kv_get(_INDEX_KEY) or []) if isinstance(i, str)]


def create_credential(name: str, *, expires_in_days: Optional[int] = None,
                      created_by: str = "", scope=None):
    """Mint a credential. Returns (secret, public_record).

    The secret is shown HERE only — only its hash is stored. Raises ValueError
    for an empty/overlong name or a non-positive expiry (a key that expired in
    the past never worked; a 400 now beats a 401 an hour later).
    """
    name = str(name or "").strip()
    if not name:
        raise ValueError("a credential needs a name")
    if len(name) > _MAX_NAME_LEN:
        raise ValueError(f"name must be at most {_MAX_NAME_LEN} characters")
    if expires_in_days is not None:
        if not isinstance(expires_in_days, int) or isinstance(expires_in_days, bool):
            raise ValueError("expires_in_days must be an integer")
        if expires_in_days <= 0:
            raise ValueError("expires_in_days must be greater than zero")

    ids = _index()
    if len(ids) >= _MAX_CREDENTIALS:
        raise ValueError(f"at most {_MAX_CREDENTIALS} admin credentials")

    secret = _SECRET_PREFIX + secrets.token_hex(20)
    cred_id = "akid_" + secrets.token_hex(6)
    now = _now()
    record = {
        "id": cred_id,
        "name": name,
        "prefix": secret[:_PREFIX_LEN],
        "created_at": now,
        "created_by": str(created_by or ""),
        "expires_at": (now + expires_in_days * 86400) if expires_in_days else None,
        "disabled": False,
        "last_used": None,
        "scope": scope,              # Task 2; None = full admin (unscoped)
    }
    key_hash = _hash(secret)
    kv_set(_cred_key(key_hash), record)
    kv_set(_id_key(cred_id), key_hash)
    ids.append(cred_id)
    kv_set(_INDEX_KEY, ids[-_MAX_CREDENTIALS:])
    return secret, _public(record)


def resolve_admin_credential(secret: str) -> Optional[dict]:
    """The record for this secret, or None if unknown, disabled or expired.

    On success the returned dict carries an ephemeral ``key_hash`` (not
    persisted) so the caller can stamp last_used without re-hashing.
    """
    if not secret or not isinstance(secret, str):
        return None
    key_hash = _hash(secret)
    record = kv_get(_cred_key(key_hash))
    if not isinstance(record, dict):
        return None
    if record.get("disabled"):
        return None
    expires_at = record.get("expires_at")
    if isinstance(expires_at, int) and _now() >= expires_at:
        return None
    record = dict(record)
    record["key_hash"] = key_hash
    return record


def record_last_used(key_hash: str) -> None:
    """Best-effort stamp. Losing it must never fail an admin request."""
    if not key_hash:
        return
    try:
        record = kv_get(_cred_key(key_hash))
        if not isinstance(record, dict):
            return
        record.pop("key_hash", None)
        record["last_used"] = _now()
        kv_set(_cred_key(key_hash), record)
    except Exception as e:                      # noqa: BLE001
        logger.debug("admin credential last_used not recorded: %s", e)


def list_credentials() -> list:
    """Every credential, newest first. Never the secret or full hash."""
    out = []
    for cred_id in _index():
        key_hash = kv_get(_id_key(cred_id))
        if not isinstance(key_hash, str):
            continue
        record = kv_get(_cred_key(key_hash))
        if isinstance(record, dict):
            out.append(_public(record))
    out.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
    return out


def get_credential(cred_id: str) -> Optional[dict]:
    """One credential's public record, or None."""
    if not cred_id:
        return None
    key_hash = kv_get(_id_key(cred_id))
    if not isinstance(key_hash, str):
        return None
    record = kv_get(_cred_key(key_hash))
    return _public(record) if isinstance(record, dict) else None


def revoke_credential(cred_id: str) -> bool:
    """Delete a credential; it is refused from the next call. Idempotent-ish:
    returns False if the id is unknown."""
    if not cred_id:
        return False
    key_hash = kv_get(_id_key(cred_id))
    if isinstance(key_hash, str):
        kv_delete(_cred_key(key_hash))
    kv_delete(_id_key(cred_id))
    ids = [i for i in _index() if i != cred_id]
    kv_set(_INDEX_KEY, ids)
    return isinstance(key_hash, str)
