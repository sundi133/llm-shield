"""Redis-backed storage for OAuth 2.1 authorization server.

Stores OAuth clients, authorization codes, and refresh tokens.
Falls back to in-memory storage when Redis is unavailable (dev/on-prem).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger("votal.oauth_store")

# In-memory fallback stores
_clients: dict[str, dict] = {}
_auth_codes: dict[str, dict] = {}
_refresh_tokens: dict[str, dict] = {}


def _get_redis():
    """Get Redis client, or None if unavailable."""
    try:
        from storage.tenant_store import _get_redis as _gr
        return _gr()
    except Exception:
        return None


# ── OAuth Client ────────────────────────────────────────────────────────


@dataclass
class OAuthClient:
    """Registered OAuth client."""
    client_id: str
    client_name: str = ""
    client_secret_hash: str = ""  # Empty for public clients
    redirect_uris: list[str] = field(default_factory=list)
    grant_types: list[str] = field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    token_endpoint_auth_method: str = "none"  # "none" for public, "client_secret_post"
    scope: str = "shield"
    tenant_id: str = ""
    created_at: int = 0


def hash_client_secret(secret: str) -> str:
    """SHA-256 hash a client secret for storage."""
    return hashlib.sha256(secret.encode()).hexdigest()


async def save_client(client: OAuthClient) -> None:
    """Save an OAuth client."""
    data = asdict(client)
    r = _get_redis()
    if r:
        try:
            r.set(f"shield:oauth:client:{client.client_id}", json.dumps(data))
            if client.tenant_id:
                r.sadd(
                    f"shield:oauth:clients_by_tenant:{client.tenant_id}",
                    client.client_id,
                )
            return
        except Exception as e:
            logger.warning(f"Redis save_client failed: {e}")
    _clients[client.client_id] = data


async def get_client(client_id: str) -> Optional[OAuthClient]:
    """Retrieve an OAuth client by ID."""
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"shield:oauth:client:{client_id}")
            if raw:
                return OAuthClient(**json.loads(raw))
        except Exception as e:
            logger.warning(f"Redis get_client failed: {e}")
    data = _clients.get(client_id)
    if data:
        return OAuthClient(**data)
    return None


async def list_clients(tenant_id: str) -> list[OAuthClient]:
    """List all OAuth clients for a tenant."""
    r = _get_redis()
    if r:
        try:
            client_ids = r.smembers(f"shield:oauth:clients_by_tenant:{tenant_id}")
            clients = []
            for cid in client_ids:
                c = await get_client(cid if isinstance(cid, str) else cid.decode())
                if c:
                    clients.append(c)
            return clients
        except Exception as e:
            logger.warning(f"Redis list_clients failed: {e}")
    return [
        OAuthClient(**d)
        for d in _clients.values()
        if d.get("tenant_id") == tenant_id
    ]


async def delete_client(client_id: str) -> bool:
    """Delete an OAuth client. Returns True if it existed."""
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"shield:oauth:client:{client_id}")
            if raw:
                data = json.loads(raw)
                r.delete(f"shield:oauth:client:{client_id}")
                if data.get("tenant_id"):
                    r.srem(
                        f"shield:oauth:clients_by_tenant:{data['tenant_id']}",
                        client_id,
                    )
                return True
            return False
        except Exception as e:
            logger.warning(f"Redis delete_client failed: {e}")
    return _clients.pop(client_id, None) is not None


# ── Authorization Code ──────────────────────────────────────────────────


@dataclass
class AuthorizationCode:
    """OAuth authorization code (short-lived)."""
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    tenant_id: str
    user_sub: str
    created_at: int = 0


async def save_auth_code(auth_code: AuthorizationCode, ttl: int = 600) -> None:
    """Save an authorization code with TTL."""
    data = asdict(auth_code)
    r = _get_redis()
    if r:
        try:
            r.set(
                f"shield:oauth:code:{auth_code.code}",
                json.dumps(data),
                ex=ttl,
            )
            return
        except Exception as e:
            logger.warning(f"Redis save_auth_code failed: {e}")
    data["_expires_at"] = int(time.time()) + ttl
    _auth_codes[auth_code.code] = data


async def consume_auth_code(code: str) -> Optional[AuthorizationCode]:
    """Consume (read and delete) an authorization code. Returns None if not found or expired."""
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"shield:oauth:code:{code}")
            if raw:
                r.delete(f"shield:oauth:code:{code}")
                return AuthorizationCode(**json.loads(raw))
            return None
        except Exception as e:
            logger.warning(f"Redis consume_auth_code failed: {e}")

    data = _auth_codes.pop(code, None)
    if data is None:
        return None
    if data.get("_expires_at", 0) < int(time.time()):
        return None  # Expired
    data.pop("_expires_at", None)
    return AuthorizationCode(**data)


# ── Refresh Token ───────────────────────────────────────────────────────


@dataclass
class RefreshTokenRecord:
    """Stored refresh token metadata."""
    token_hash: str
    client_id: str
    scope: str
    tenant_id: str
    user_sub: str
    created_at: int = 0


async def save_refresh_token(
    record: RefreshTokenRecord, ttl: int = 86400
) -> None:
    """Save a refresh token record with TTL."""
    data = asdict(record)
    r = _get_redis()
    if r:
        try:
            r.set(
                f"shield:oauth:refresh:{record.token_hash}",
                json.dumps(data),
                ex=ttl,
            )
            return
        except Exception as e:
            logger.warning(f"Redis save_refresh_token failed: {e}")
    data["_expires_at"] = int(time.time()) + ttl
    _refresh_tokens[record.token_hash] = data


async def consume_refresh_token(
    token_hash: str,
) -> Optional[RefreshTokenRecord]:
    """Consume a refresh token (rotation: old token is invalidated)."""
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"shield:oauth:refresh:{token_hash}")
            if raw:
                r.delete(f"shield:oauth:refresh:{token_hash}")
                return RefreshTokenRecord(**json.loads(raw))
            return None
        except Exception as e:
            logger.warning(f"Redis consume_refresh_token failed: {e}")

    data = _refresh_tokens.pop(token_hash, None)
    if data is None:
        return None
    if data.get("_expires_at", 0) < int(time.time()):
        return None
    data.pop("_expires_at", None)
    return RefreshTokenRecord(**data)


async def revoke_refresh_token(token_hash: str) -> bool:
    """Revoke a refresh token. Returns True if it existed."""
    r = _get_redis()
    if r:
        try:
            deleted = r.delete(f"shield:oauth:refresh:{token_hash}")
            return bool(deleted)
        except Exception:
            pass
    return _refresh_tokens.pop(token_hash, None) is not None


def clear_all_for_tests() -> None:
    """Clear all in-memory stores. For tests only."""
    _clients.clear()
    _auth_codes.clear()
    _refresh_tokens.clear()
