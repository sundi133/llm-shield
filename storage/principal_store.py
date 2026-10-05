"""Principals: the people and service accounts that call the MCP gateway.

A principal is who is calling, verified. A person comes from the tenant's
identity provider (created at first sign-in, or ahead of time by SCIM); a
service account is created by an admin for a headless agent. Either one is what
a verified caller resolves to, and what the audit trail names.

    principal:{tenant}:{pid}                          the record, no TTL
    principal_idx:{tenant}:{sha256(iss|sub)[:24]}     -> pid, no TTL
    principals:{tenant}                               SET of pid
    principalkey:{sha256(key)}                        a principal's API key

**Principal keys are deliberately NOT tenant keys.** They live in their own
namespace, so `resolve_tenant_by_api_key` never sees them and a key handed to
one agent cannot call the guard endpoints, the admin API or another tenant's
route. Only the gateway's caller resolution reads them. The key itself is never
stored; only its hash.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§3.1, §3.2)
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis

TYPE_USER = "user"
TYPE_SERVICE_ACCOUNT = "service_account"
TYPES = (TYPE_USER, TYPE_SERVICE_ACCOUNT)

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_DEPROVISIONED = "deprovisioned"
STATUSES = (STATUS_ACTIVE, STATUS_SUSPENDED, STATUS_DEPROVISIONED)

SOURCES = ("jit", "scim", "admin")

#: A principal key is recognisable on sight, so a leaked one can be reported
#: and so the gateway only looks one up when the prefix says it might be one.
KEY_PREFIX = "shk_"
_KEY_PREFIX_LEN = 12

_ID_PREFIX = {TYPE_USER: "usr_", TYPE_SERVICE_ACCOUNT: "sa_"}


def _key(tenant_id: str, pid: str) -> str:
    return f"principal:{tenant_id}:{pid}"


def _index_key(tenant_id: str, issuer: str, sub: str) -> str:
    digest = hashlib.sha256(f"{issuer}|{sub}".encode()).hexdigest()[:24]
    return f"principal_idx:{tenant_id}:{digest}"


def _set_key(tenant_id: str) -> str:
    return f"principals:{tenant_id}"


def _pkey_key(key_hash: str) -> str:
    return f"principalkey:{key_hash}"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _decode(raw: Any) -> Optional[dict]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


def _get(key: str) -> Any:
    r = _get_redis()
    return r.get(key) if r else _fallback_store.get(key)


def _put(key: str, value: str) -> None:
    r = _get_redis()
    if r:
        r.set(key, value)
    else:
        _fallback_store[key] = value


def _add_member(set_key: str, member: str) -> None:
    r = _get_redis()
    if r:
        r.sadd(set_key, member)
        return
    members = set(json.loads(_fallback_store.get(set_key) or "[]"))
    members.add(member)
    _fallback_store[set_key] = json.dumps(sorted(members))


def _members(set_key: str) -> list[str]:
    r = _get_redis()
    if r:
        return sorted(m.decode() if isinstance(m, bytes) else m
                      for m in (r.smembers(set_key) or []))
    return json.loads(_fallback_store.get(set_key) or "[]")


def new_principal_id(ptype: str) -> str:
    if ptype not in TYPES:
        raise ValueError(f"unknown principal type: {ptype}")
    return _ID_PREFIX[ptype] + secrets.token_hex(6)


def _clean_groups(groups: Any) -> list[str]:
    if not isinstance(groups, (list, tuple)):
        return []
    return sorted({str(g) for g in groups if str(g).strip()})


# ── records ──────────────────────────────────────────────────────────


def get_principal(tenant_id: str, pid: str) -> Optional[dict]:
    if not tenant_id or not pid:
        return None
    return _decode(_get(_key(tenant_id, pid)))


def _save(tenant_id: str, doc: dict) -> dict:
    _put(_key(tenant_id, doc["id"]), json.dumps(doc))
    _add_member(_set_key(tenant_id), doc["id"])
    return doc


def find_user(tenant_id: str, issuer: str, sub: str) -> Optional[dict]:
    """The person this IdP subject already maps to, if any."""
    pid = _get(_index_key(tenant_id, issuer, sub))
    if isinstance(pid, bytes):
        pid = pid.decode()
    return get_principal(tenant_id, pid) if pid else None


def upsert_user(tenant_id: str, *, issuer: str, sub: str, email: str = "",
                name: str = "", groups: Any = None, source: str = "jit") -> dict:
    """Create the person for (issuer, sub), or refresh what the IdP says about them.

    Identity is (issuer, sub), never email: an email can be reassigned to a
    different person, a subject cannot. Status is never changed here, so a
    suspended person who signs in again stays suspended.
    """
    if not tenant_id or not issuer or not sub:
        raise ValueError("tenant_id, issuer and sub are required")
    if source not in SOURCES:
        raise ValueError(f"unknown source: {source}")
    now = int(time.time())
    doc = find_user(tenant_id, issuer, sub)
    if doc is None:
        doc = {
            "id": new_principal_id(TYPE_USER), "type": TYPE_USER,
            "issuer": issuer, "sub": sub, "roles": [],
            "status": STATUS_ACTIVE, "source": source,
            "created_at": now, "status_changed_at": now, "last_seen_at": 0,
        }
        _put(_index_key(tenant_id, issuer, sub), doc["id"])
    doc.update(email=email or doc.get("email", ""), name=name or doc.get("name", ""),
               groups=_clean_groups(groups) if groups is not None else doc.get("groups", []),
               updated_at=now)
    return _save(tenant_id, doc)


def create_service_account(tenant_id: str, *, name: str, roles: Any = None,
                           created_by: str = "") -> dict:
    if not tenant_id or not (name or "").strip():
        raise ValueError("tenant_id and name are required")
    now = int(time.time())
    doc = {
        "id": new_principal_id(TYPE_SERVICE_ACCOUNT), "type": TYPE_SERVICE_ACCOUNT,
        "name": name.strip(), "email": "", "groups": [],
        "roles": _clean_groups(roles), "status": STATUS_ACTIVE, "source": "admin",
        "created_by": created_by, "created_at": now, "status_changed_at": now,
        "last_seen_at": 0, "updated_at": now,
    }
    return _save(tenant_id, doc)


def set_status(tenant_id: str, pid: str, status: str) -> Optional[dict]:
    if status not in STATUSES:
        raise ValueError(f"unknown status: {status}")
    doc = get_principal(tenant_id, pid)
    if doc is None:
        return None
    if doc.get("status") != status:
        doc["status"] = status
        doc["status_changed_at"] = int(time.time())
        _save(tenant_id, doc)
    return doc


def list_principals(tenant_id: str) -> list[dict]:
    out = []
    for pid in _members(_set_key(tenant_id)):
        doc = get_principal(tenant_id, pid)
        if doc:
            out.append(doc)
    return out


def is_active(doc: Optional[dict]) -> bool:
    return bool(doc) and doc.get("status") == STATUS_ACTIVE


# ── principal keys ───────────────────────────────────────────────────


def looks_like_principal_key(value: str) -> bool:
    return bool(value) and value.startswith(KEY_PREFIX)


def create_principal_key(tenant_id: str, pid: str, *, label: str = "") -> tuple[str, dict]:
    """Mint a key for one principal. Returns (key, public record); the key is
    shown once and never stored."""
    if get_principal(tenant_id, pid) is None:
        raise ValueError("unknown principal")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    record = {
        "key_id": "pk_" + secrets.token_hex(6),
        "tenant_id": tenant_id, "principal_id": pid,
        "label": label, "prefix": key[:_KEY_PREFIX_LEN],
        "created_at": int(time.time()),
    }
    _put(_pkey_key(_hash(key)), json.dumps(record))
    return key, dict(record)


def resolve_principal_key(key: str) -> Optional[dict]:
    """The key's record ({tenant_id, principal_id, ...}) or None. One read."""
    if not looks_like_principal_key(key):
        return None
    return _decode(_get(_pkey_key(_hash(key))))


def revoke_principal_key(key: str) -> bool:
    k = _pkey_key(_hash(key))
    r = _get_redis()
    if r:
        return bool(r.delete(k))
    return _fallback_store.pop(k, None) is not None
