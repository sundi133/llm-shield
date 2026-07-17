"""Secret vault storage — envelope-encrypted secrets per tenant in Redis.

Redis key: vault:{tenant_id} → JSON list of entries. Each entry holds only
ciphertext (never the plaintext value or the raw DEK):

    {
        "ref": "stripe_key",              # stable name the operator chooses
        "token": "svlt_9f3a…",            # opaque handle for tier-2 tokenization
        "ciphertext": "<b64>",            # AES-GCM sealed value
        "nonce": "<b64>",
        "wrapped_dek": "<b64>",           # per-secret DEK, wrapped by the KEK
        "bindings": ["api.stripe.com"],   # allowed egress destinations (mandatory)
        "mode": "inject" | "token",
        "tool_ids": ["stripe.createCharge"],
        "created_at": 1720000000, "updated_at": 1720000000,
    }

The plaintext value is recoverable only via resolve_secret_value(), which is for
server-side egress materialization. There is deliberately no function (and no API)
that returns a decrypted value to an external caller.
"""

import json
import logging
import secrets
import time

from core.secret_vault.crypto import decrypt_entry_cached, encrypt_value
from core.secret_vault.keyprovider import get_key_provider

logger = logging.getLogger("votal.vault_store")

_CRYPTO_FIELDS = ("ciphertext", "nonce", "wrapped_dek")
_MAX_VALUE_BYTES = 8192  # reject oversized/binary blobs at registration


def _get_redis():
    from storage.tenant_store import _get_redis as _gr
    return _gr()


def _key(tenant_id: str) -> str:
    return f"vault:{tenant_id}"


def _write_entries(tenant_id: str, entries: list[dict]) -> None:
    """Persist the entry list to Redis, or the in-memory fallback if Redis is down."""
    from storage.tenant_store import _fallback_store
    payload = json.dumps(entries)
    r = _get_redis()
    if r:
        r.set(_key(tenant_id), payload)
    else:
        _fallback_store[_key(tenant_id)] = payload


def get_vault_entries(tenant_id: str) -> list[dict]:
    """Return all raw entries (including ciphertext) for a tenant. Internal use."""
    from storage.tenant_store import _fallback_store
    try:
        r = _get_redis()
        raw = r.get(_key(tenant_id)) if r else _fallback_store.get(_key(tenant_id))
        if not raw:
            return []
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.debug(f"vault_store get failed: {e}")
        return []


def _public_view(entry: dict) -> dict:
    """Strip crypto material — safe to return from the admin API."""
    return {k: v for k, v in entry.items() if k not in _CRYPTO_FIELDS}


def list_vault_entries(tenant_id: str) -> list[dict]:
    """Metadata-only listing for the admin API (no ciphertext, no value)."""
    return [_public_view(e) for e in get_vault_entries(tenant_id)]


def create_vault_entry(
    tenant_id: str,
    name: str,
    value: str,
    bindings: list[str],
    mode: str = "inject",
    tool_ids: list[str] | None = None,
) -> dict:
    """Register (or replace, by name) an encrypted secret. Returns the public view.

    Raises ValueError on invalid input and VaultConfigError (fail-closed) if the
    key backend is misconfigured. Encryption happens here; the plaintext is not
    persisted.
    """
    if not name:
        raise ValueError("secret name is required")
    if not value:
        raise ValueError("secret value is required")
    if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise ValueError(f"secret value exceeds {_MAX_VALUE_BYTES} bytes")
    if not bindings:
        # Binding is the anti-exfil control; an unbound secret is unusable, so we
        # refuse to store one rather than create a footgun.
        raise ValueError("at least one binding (allowed destination) is required")
    from core.secret_vault.materialize import is_self_host
    for b in bindings:
        # A secret is materialized on the leg out of Shield to the real upstream,
        # never on the leg into a Shield plane. Binding to a Shield host is a
        # misconfiguration (or exfil bait), so refuse it.
        if is_self_host(b):
            raise ValueError(
                f"cannot bind a secret to a Shield plane ('{b}'); "
                "bind it to the real upstream host instead")
    if mode not in ("inject", "token"):
        raise ValueError("mode must be 'inject' or 'token'")

    provider = get_key_provider()
    enc = encrypt_value(value, provider)
    now = int(time.time())

    entries = get_vault_entries(tenant_id)
    existing = next((e for e in entries if e.get("ref") == name), None)
    token = existing.get("token") if existing else "svlt_" + secrets.token_hex(8)

    entry = {
        "ref": name,
        "token": token,
        **enc,
        "bindings": list(bindings),
        "mode": mode,
        "tool_ids": list(tool_ids or []),
        "created_at": existing.get("created_at", now) if existing else now,
        "updated_at": now,
    }

    entries = [e for e in entries if e.get("ref") != name]
    entries.append(entry)
    _write_entries(tenant_id, entries)
    return _public_view(entry)


def delete_vault_entry(tenant_id: str, ref: str) -> bool:
    """Delete a secret by ref. Returns True if it existed."""
    entries = get_vault_entries(tenant_id)
    remaining = [e for e in entries if e.get("ref") != ref]
    if len(remaining) == len(entries):
        return False
    _write_entries(tenant_id, remaining)
    return True


def resolve_secret_value(tenant_id: str, ref: str) -> str | None:
    """Decrypt and return a secret value for server-side egress materialization.

    NOT for external callers — no API surfaces this. Returns None if the ref is
    unknown. Raises (fail-closed) if the key backend cannot unwrap the DEK.
    """
    entry = next((e for e in get_vault_entries(tenant_id) if e.get("ref") == ref), None)
    if entry is None:
        return None
    return decrypt_entry_cached(entry)


def resolve_binding(tenant_id: str, ref_or_token: str) -> tuple[str, list[str], list[str]] | None:
    """Resolve a `ref` or opaque `token` to (plaintext value, bindings, tool_ids).

    Server-side only, for egress materialization. `tool_ids` (when non-empty)
    scopes the secret to specific tools (tier-1). Returns None for an unknown
    reference. Raises (fail-closed) if the DEK cannot be unwrapped.
    """
    for e in get_vault_entries(tenant_id):
        if e.get("ref") == ref_or_token or e.get("token") == ref_or_token:
            return (
                decrypt_entry_cached(e),
                list(e.get("bindings", [])),
                list(e.get("tool_ids", [])),
            )
    return None


def reveal_all(tenant_id: str) -> list[tuple[str, str]]:
    """Return [(plaintext_value, ref)] for every secret — for ingress re-tokenization.

    Server-side only. Decrypts all entries; callers should treat the result as
    highly sensitive and never log it.
    """
    out: list[tuple[str, str]] = []
    for e in get_vault_entries(tenant_id):
        try:
            out.append((decrypt_entry_cached(e), e.get("ref", "")))
        except Exception as ex:  # one bad entry must not break the batch
            logger.debug(f"reveal_all skip {e.get('ref')}: {ex}")
    return out
