"""Per-person upstream grants: each person's own OAuth tokens for one MCP server.

A route with `credential_scope: per_user` (task B2) sends each caller's own
token upstream, never a shared one. This module stores those tokens.

    mcp_grant:{tenant}:{route}:{pid}     one grant: status + encrypted tokens, no TTL
    mcp_grants:{tenant}:{route}          SET of pid connected to the route
    mcp_grants_by_pid:{tenant}:{pid}     SET of routes the person connected

**One key per grant**, holding the status and the sealed tokens together:
- a write never leaves a status pointing at missing or stale tokens;
- the gateway reads a person's grant in one GET;
- concurrent refreshes by different people never touch each other's key. (The
  tenant vault is one JSON list rewritten on every write, which loses updates
  under exactly that load, so per-person tokens do not go there.)

**Sealing.** The same key-encryption key as the vault (core/secret_vault), with
a fresh data key per token and AES-GCM whose associated data names the tenant,
route, person and token kind. A sealed token copied into another person's grant
therefore fails to open instead of letting one person act as another.

**Release.** Each token is bound to the host it may be sent to (the access
token to the upstream, the refresh token to the token endpoint) and is released
only for that destination, with the vault's matching rules.

Sealed material never leaves this module: `public_view` is all callers get,
apart from the token release functions themselves.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§3.5, task B1)
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis

STATUS_CONNECTED = "connected"
STATUS_NEEDS_CONSENT = "needs_consent"
STATUS_ERROR = "error"
STATUSES = (STATUS_CONNECTED, STATUS_NEEDS_CONSENT, STATUS_ERROR)

ACCESS = "access"
REFRESH = "refresh"

_SEALED = ("access", "refresh")
_PUBLIC = ("route", "principal_id", "status", "upstream_account", "scopes",
           "expires_at", "refresh_token_held", "connected_at", "last_refresh_at",
           "last_error", "updated_at")


class GrantError(Exception):
    """A grant cannot be used. `reason` is machine-readable."""

    def __init__(self, reason: str, message: str = ""):
        super().__init__(message or reason)
        self.reason = reason


def _key(tenant_id: str, route: str, pid: str) -> str:
    return f"mcp_grant:{tenant_id}:{route}:{pid}"


def _route_set(tenant_id: str, route: str) -> str:
    return f"mcp_grants:{tenant_id}:{route}"


def _pid_set(tenant_id: str, pid: str) -> str:
    return f"mcp_grants_by_pid:{tenant_id}:{pid}"


def _require(tenant_id: str, route: str, pid: str) -> None:
    if not (tenant_id and route and pid):
        raise ValueError("tenant_id, route and principal id are required")


# ── storage primitives (Redis or the in-process fallback) ────────────


def _get_doc(key: str) -> Optional[dict]:
    r = _get_redis()
    raw = r.get(key) if r else _fallback_store.get(key)
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


def _put_doc(key: str, doc: dict) -> None:
    r = _get_redis()
    if r:
        r.set(key, json.dumps(doc))
    else:
        _fallback_store[key] = json.dumps(doc)


def _delete(key: str) -> bool:
    r = _get_redis()
    if r:
        return bool(r.delete(key))
    return _fallback_store.pop(key, None) is not None


def _sadd(key: str, member: str) -> None:
    r = _get_redis()
    if r:
        r.sadd(key, member)
        return
    members = set(json.loads(_fallback_store.get(key) or "[]"))
    members.add(member)
    _fallback_store[key] = json.dumps(sorted(members))


def _srem(key: str, member: str) -> None:
    r = _get_redis()
    if r:
        r.srem(key, member)
        return
    members = set(json.loads(_fallback_store.get(key) or "[]"))
    members.discard(member)
    _fallback_store[key] = json.dumps(sorted(members))


def _smembers(key: str) -> list[str]:
    r = _get_redis()
    if r:
        return sorted(m.decode() if isinstance(m, bytes) else m for m in (r.smembers(key) or []))
    return json.loads(_fallback_store.get(key) or "[]")


# ── sealing ──────────────────────────────────────────────────────────


def _aad(tenant_id: str, route: str, pid: str, kind: str) -> bytes:
    return f"shield-mcp-grant:v1:{tenant_id}:{route}:{pid}:{kind}".encode()


def _seal(value: str, aad: bytes, bindings: list[str]) -> dict:
    from core.secret_vault.keyprovider import get_key_provider, vault_enabled
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not vault_enabled():
        raise GrantError("vault_disabled",
                         "per-person credentials need the secret vault (SECRET_VAULT_ENABLED)")
    dek, nonce = os.urandom(32), os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, value.encode("utf-8"), aad)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_dek": base64.b64encode(get_key_provider().wrap_dek(dek)).decode(),
        "bindings": [b for b in bindings if b],
    }


def _open(envelope: dict, aad: bytes) -> str:
    """Raises on tamper, a swapped envelope or a wrong key: callers fail closed."""
    from core.secret_vault.keyprovider import unwrap_dek_cached
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    dek = unwrap_dek_cached(base64.b64decode(envelope["wrapped_dek"]))
    return AESGCM(dek).decrypt(base64.b64decode(envelope["nonce"]),
                               base64.b64decode(envelope["ciphertext"]), aad).decode("utf-8")


# ── grants ───────────────────────────────────────────────────────────


def public_view(doc: Optional[dict]) -> Optional[dict]:
    if doc is None:
        return None
    return {k: doc.get(k) for k in _PUBLIC if k in doc}


def get_grant(tenant_id: str, route: str, pid: str) -> Optional[dict]:
    """The grant's public fields, or None. Never includes token material."""
    if not (tenant_id and route and pid):
        return None
    return public_view(_get_doc(_key(tenant_id, route, pid)))


def store_tokens(tenant_id: str, route: str, pid: str, *, access_token: str,
                 access_bindings: list[str], refresh_token: str = "",
                 refresh_bindings: Optional[list[str]] = None, expires_at: int = 0,
                 scopes: Any = None, upstream_account: str = "") -> dict:
    """Store (or renew) one person's tokens for one route; marks it connected.

    An empty `refresh_token` keeps the stored one: providers that do not rotate
    refresh tokens return none on renewal. Returns the public view.
    """
    _require(tenant_id, route, pid)
    if not access_token:
        raise ValueError("access_token is required")
    key = _key(tenant_id, route, pid)
    now = int(time.time())
    doc = _get_doc(key) or {"route": route, "principal_id": pid, "connected_at": now}
    doc["access"] = _seal(access_token, _aad(tenant_id, route, pid, ACCESS), access_bindings)
    if refresh_token:
        doc["refresh"] = _seal(refresh_token, _aad(tenant_id, route, pid, REFRESH),
                               refresh_bindings or [])
    doc.update(status=STATUS_CONNECTED, expires_at=int(expires_at or 0), last_error="",
               refresh_token_held="refresh" in doc, last_refresh_at=now, updated_at=now)
    if scopes is not None:
        doc["scopes"] = [str(s) for s in scopes] if isinstance(scopes, (list, tuple)) \
            else str(scopes).split()
    if upstream_account:
        doc["upstream_account"] = upstream_account
    _put_doc(key, doc)
    _sadd(_route_set(tenant_id, route), pid)
    _sadd(_pid_set(tenant_id, pid), route)
    return public_view(doc)


def set_status(tenant_id: str, route: str, pid: str, status: str, *, error: str = "") -> Optional[dict]:
    if status not in STATUSES:
        raise ValueError(f"unknown status: {status}")
    key = _key(tenant_id, route, pid)
    doc = _get_doc(key)
    if doc is None:
        return None
    doc.update(status=status, last_error=error[:300], updated_at=int(time.time()))
    _put_doc(key, doc)
    return public_view(doc)


def _release(tenant_id: str, route: str, pid: str, kind: str, destination: str) -> str:
    from core.secret_vault.materialize import _binding_matches
    doc = _get_doc(_key(tenant_id, route, pid))
    if doc is None:
        raise GrantError("not_connected", "this person has not connected this server")
    if kind == ACCESS and doc.get("status") == STATUS_NEEDS_CONSENT:
        raise GrantError("needs_consent", "this person must connect this server again")
    envelope = doc.get(kind)
    if not envelope:
        raise GrantError("not_connected" if kind == ACCESS else "no_refresh_token")
    if not _binding_matches(destination or "", envelope.get("bindings") or []):
        raise GrantError("binding_mismatch",
                         f"the {kind} token is not bound to {destination!r}")
    try:
        return _open(envelope, _aad(tenant_id, route, pid, kind))
    except Exception as e:      # noqa: BLE001 - tamper, swap or key change
        raise GrantError("unreadable", "the stored token could not be opened") from e


def access_for_call(tenant_id: str, route: str, pid: str, destination: str) -> tuple[str, dict]:
    """(access token, public view) for one call, from ONE read. GrantError if
    the person has no usable grant. The view carries `expires_at`, so the
    caller can decide on refresh without a second read."""
    from core.secret_vault.materialize import _binding_matches
    doc = _get_doc(_key(tenant_id, route, pid))
    if doc is None:
        raise GrantError("not_connected", "this person has not connected this server")
    if doc.get("status") == STATUS_NEEDS_CONSENT:
        raise GrantError("needs_consent", "this person must connect this server again")
    envelope = doc.get(ACCESS)
    if not envelope:
        raise GrantError("not_connected")
    if not _binding_matches(destination or "", envelope.get("bindings") or []):
        raise GrantError("binding_mismatch", f"the access token is not bound to {destination!r}")
    try:
        return _open(envelope, _aad(tenant_id, route, pid, ACCESS)), public_view(doc)
    except Exception as e:      # noqa: BLE001
        raise GrantError("unreadable", "the stored token could not be opened") from e


def access_token_for(tenant_id: str, route: str, pid: str, destination: str) -> str:
    """This person's access token for `destination`, or GrantError. One read."""
    return _release(tenant_id, route, pid, ACCESS, destination)


def refresh_token_for(tenant_id: str, route: str, pid: str, destination: str) -> str:
    return _release(tenant_id, route, pid, REFRESH, destination)


def delete_grant(tenant_id: str, route: str, pid: str) -> bool:
    existed = _delete(_key(tenant_id, route, pid))
    _srem(_route_set(tenant_id, route), pid)
    _srem(_pid_set(tenant_id, pid), route)
    return existed


def principals_for_route(tenant_id: str, route: str) -> list[str]:
    return _smembers(_route_set(tenant_id, route))


def list_grants(tenant_id: str, route: str) -> list[dict]:
    out = []
    for pid in principals_for_route(tenant_id, route):
        g = get_grant(tenant_id, route, pid)
        if g:
            out.append(g)
    return out


def routes_for_principal(tenant_id: str, pid: str) -> list[str]:
    return _smembers(_pid_set(tenant_id, pid))
