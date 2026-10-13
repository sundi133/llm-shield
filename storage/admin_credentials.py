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

# The coarse operation groups a credential's scope may allow (Task 2). A scope
# narrows the platform-wide authority of an admin credential; it never widens
# it. The gateway/handlers name these exact strings when they call
# core.auth.require_admin_scope, so this is the single source of the vocabulary.
ADMIN_OPERATIONS = (
    "tenants:read",     # read tenants, usage, audit, dashboard, hierarchy
    "tenants:write",    # create/update/delete tenants, tenant API keys, parent
    "oidc:read",        # read a tenant's trusted OIDC providers
    "oidc:write",       # register/remove a tenant's OIDC providers
    "principals:read",  # list/read principals (people, service accounts) cross-tenant
    "principals:write", # suspend/reactivate a principal (operator incident response)
    "delegations:read", # list recorded agent-for-user delegations
    "delegations:write",# revoke a delegation
    "policy:read",      # read/validate/simulate a tenant's authorization policy
    "policy:write",     # edit the draft, publish, roll back
)


def _now() -> int:
    return int(time.time())


def normalize_scope(scope):
    """Validate and normalise a credential scope, or None for full admin.

    Shape: {"operations": [<group>|"*", ...], "tenants": [<id>|"*", ...]}.
    operations is a required non-empty allowlist; "*" means all operations.
    tenants is optional — empty (or containing "*") means all tenants.
    Raises ValueError on a bad shape or an unknown operation, so an operator is
    told at mint time rather than discovering a typo as a silent 403 later.
    """
    if scope is None:
        return None
    if not isinstance(scope, dict):
        raise ValueError("scope must be an object with 'operations' and optional 'tenants'")

    ops_in = scope.get("operations")
    if not isinstance(ops_in, list) or not ops_in:
        raise ValueError("scope.operations must be a non-empty list")
    operations = []
    for raw in ops_in:
        op = str(raw).strip()
        if op == "*":
            operations = ["*"]
            break
        if op not in ADMIN_OPERATIONS:
            raise ValueError(
                f"unknown operation {op!r}; valid: {', '.join(ADMIN_OPERATIONS)} or '*'")
        if op not in operations:
            operations.append(op)

    tenants_in = scope.get("tenants") or []
    if not isinstance(tenants_in, list):
        raise ValueError("scope.tenants must be a list of tenant ids")
    tenants = []
    for raw in tenants_in:
        tid = str(raw).strip()
        if tid and tid not in tenants:
            tenants.append(tid)

    return {"operations": operations, "tenants": tenants}


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

    scope = normalize_scope(scope)

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


def rotate_credential(cred_id: str, *, expires_in_days: Optional[int] = None):
    """Mint a replacement carrying the old credential's name and scope, then
    revoke the old one. Returns (secret, public_record). Raises ValueError if
    the id is unknown. The new secret is the caller's to show once.

    expires_in_days None keeps the credential non-expiring (it does NOT inherit
    the old deadline — rotation is a fresh issue; pass a window to set one).
    """
    key_hash = kv_get(_id_key(cred_id))
    if not isinstance(key_hash, str):
        raise ValueError("no such credential")
    old = kv_get(_cred_key(key_hash))
    if not isinstance(old, dict):
        raise ValueError("no such credential")
    name = old.get("name", "")
    scope = old.get("scope")
    created_by = old.get("created_by", "")
    secret, record = create_credential(
        name, expires_in_days=expires_in_days, created_by=created_by, scope=scope)
    revoke_credential(cred_id)
    return secret, record


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
