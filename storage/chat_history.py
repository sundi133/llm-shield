"""Persistent chat history storage backed by Redis.

Key schema
----------
Each chat session is stored as a Redis LIST under a composite key that
encodes tenant isolation, agent scope, and a stable session hash:

    chat:{tenant_id}:{agent_id}:{bucket}:{session_id}

Components:
    tenant_id   — hard tenant boundary (data never leaks across tenants)
    agent_id    — per-agent conversation isolation within a tenant
    bucket      — hash(session_id) % NUM_BUCKETS  (default 64)
                  distributes keys across Redis hash-slots for even
                  cluster distribution and enables efficient scan/cleanup
    session_id  — caller-provided or auto-generated conversation ID

Index keys (for listing / cleanup):
    chat_idx:{tenant_id}              — ZSET of session keys scored by last-update ts
    chat_idx:{tenant_id}:{agent_id}   — ZSET scoped to one agent

Why the bucket?
    With thousands of concurrent sessions, a flat keyspace creates hotspots
    on a single Redis cluster slot.  hash % N spreads keys across N slots
    so SCAN-based cleanup and TTL expiry parallelize naturally.

TTL:
    Every key gets a configurable TTL (default 24 h).  Each append resets
    the TTL so active conversations stay alive; idle ones expire silently.

Redis keys:
    chat:{tenant_id}:{agent_id}:{bucket}:{session_id}   LIST of JSON messages
    chat_idx:{tenant_id}                                 ZSET session_key → ts
    chat_idx:{tenant_id}:{agent_id}                      ZSET session_key → ts
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.chat_history")

# ── Config ──────────────────────────────────────────────────
NUM_BUCKETS = int(os.environ.get("CHAT_HISTORY_BUCKETS", "64"))
DEFAULT_TTL = int(os.environ.get("CHAT_HISTORY_TTL", str(24 * 3600)))  # 24h
MAX_MESSAGES = int(os.environ.get("CHAT_HISTORY_MAX_MESSAGES", "200"))


# ── Key helpers ─────────────────────────────────────────────

def _bucket(session_id: str) -> int:
    """Deterministic bucket from session_id for cluster-slot distribution."""
    h = int(hashlib.sha256(session_id.encode()).hexdigest(), 16)
    return h % NUM_BUCKETS


def _chat_key(tenant_id: str, agent_id: str, session_id: str) -> str:
    b = _bucket(session_id)
    return f"chat:{tenant_id}:{agent_id}:{b}:{session_id}"


def _index_key(tenant_id: str, agent_id: str | None = None) -> str:
    if agent_id:
        return f"chat_idx:{tenant_id}:{agent_id}"
    return f"chat_idx:{tenant_id}"


def generate_session_id() -> str:
    """Generate a new unique session ID."""
    return str(uuid.uuid4())


# ── Public API ──────────────────────────────────────────────

def append_message(
    tenant_id: str,
    agent_id: str,
    session_id: str,
    message: dict[str, Any],
    ttl: int | None = None,
) -> int:
    """Append a message to a chat session.  Returns new list length.

    message should be OpenAI-format: {"role": "user"|"assistant"|"system", "content": "..."}
    Extra fields (tool_calls, name, etc.) are preserved.
    """
    key = _chat_key(tenant_id, agent_id, session_id)
    payload = json.dumps(message)
    ttl = ttl or DEFAULT_TTL
    now = time.time()

    r = _get_redis()
    if r:
        r.rpush(key, payload)
        # Trim to cap — keep last MAX_MESSAGES entries
        r.ltrim(key, -MAX_MESSAGES, -1)
        r.expire(key, ttl)
        # Update indexes
        for idx_key in (_index_key(tenant_id), _index_key(tenant_id, agent_id)):
            r.zadd(idx_key, {key: now})
            r.expire(idx_key, ttl)
        length = r.llen(key)
    else:
        # In-memory fallback
        history = json.loads(_fallback_store.get(key, "[]"))
        history.append(message)
        if len(history) > MAX_MESSAGES:
            history = history[-MAX_MESSAGES:]
        _fallback_store[key] = json.dumps(history)
        length = len(history)

    return length


def append_messages(
    tenant_id: str,
    agent_id: str,
    session_id: str,
    messages: list[dict[str, Any]],
    ttl: int | None = None,
) -> int:
    """Append multiple messages in one call.  Returns new list length."""
    key = _chat_key(tenant_id, agent_id, session_id)
    ttl = ttl or DEFAULT_TTL
    now = time.time()

    r = _get_redis()
    if r:
        payloads = [json.dumps(m) for m in messages]
        r.rpush(key, *payloads)
        r.ltrim(key, -MAX_MESSAGES, -1)
        r.expire(key, ttl)
        for idx_key in (_index_key(tenant_id), _index_key(tenant_id, agent_id)):
            r.zadd(idx_key, {key: now})
            r.expire(idx_key, ttl)
        length = r.llen(key)
    else:
        history = json.loads(_fallback_store.get(key, "[]"))
        history.extend(messages)
        if len(history) > MAX_MESSAGES:
            history = history[-MAX_MESSAGES:]
        _fallback_store[key] = json.dumps(history)
        length = len(history)

    return length


def get_history(
    tenant_id: str,
    agent_id: str,
    session_id: str,
    last_n: int | None = None,
) -> list[dict[str, Any]]:
    """Retrieve chat history for a session.

    Returns list of message dicts in chronological order.
    Pass last_n to only retrieve the most recent N messages.
    """
    key = _chat_key(tenant_id, agent_id, session_id)

    r = _get_redis()
    if r:
        if last_n:
            raw = r.lrange(key, -last_n, -1)
        else:
            raw = r.lrange(key, 0, -1)
        messages = []
        for item in raw or []:
            if isinstance(item, bytes):
                item = item.decode()
            messages.append(json.loads(item))
        return messages
    else:
        history = json.loads(_fallback_store.get(key, "[]"))
        if last_n:
            return history[-last_n:]
        return history


def delete_session(
    tenant_id: str,
    agent_id: str,
    session_id: str,
) -> bool:
    """Delete a chat session.  Returns True if it existed."""
    key = _chat_key(tenant_id, agent_id, session_id)

    r = _get_redis()
    if r:
        deleted = r.delete(key)
        # Remove from indexes
        for idx_key in (_index_key(tenant_id), _index_key(tenant_id, agent_id)):
            r.zrem(idx_key, key)
        return bool(deleted)
    else:
        existed = key in _fallback_store
        _fallback_store.pop(key, None)
        return existed


def list_sessions(
    tenant_id: str,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List chat sessions for a tenant (optionally filtered by agent_id).

    Returns list of {session_key, last_updated} sorted by most recent first.
    """
    idx_key = _index_key(tenant_id, agent_id)

    r = _get_redis()
    if not r:
        return []

    # ZREVRANGEBYSCORE — newest first
    results = r.zrevrange(idx_key, offset, offset + limit - 1, withscores=True)
    sessions = []
    for key_bytes, score in results or []:
        k = key_bytes.decode() if isinstance(key_bytes, bytes) else key_bytes
        # Parse tenant:agent:bucket:session from key
        parts = k.split(":")
        sessions.append({
            "session_key": k,
            "tenant_id": parts[1] if len(parts) > 1 else "",
            "agent_id": parts[2] if len(parts) > 2 else "",
            "session_id": parts[4] if len(parts) > 4 else "",
            "last_updated": score,
        })
    return sessions


def cleanup_expired(tenant_id: str, agent_id: str | None = None) -> int:
    """Remove index entries whose underlying keys have expired.

    Call periodically (e.g., from a background task) to keep indexes clean.
    Returns number of stale entries removed.
    """
    idx_key = _index_key(tenant_id, agent_id)
    r = _get_redis()
    if not r:
        return 0

    removed = 0
    cursor = 0
    while True:
        # Scan through the index in batches
        entries = r.zrange(idx_key, cursor, cursor + 99, withscores=True)
        if not entries:
            break
        for key_bytes, _ in entries:
            k = key_bytes.decode() if isinstance(key_bytes, bytes) else key_bytes
            if not r.exists(k):
                r.zrem(idx_key, k)
                removed += 1
        cursor += 100
        if len(entries) < 100:
            break

    return removed
