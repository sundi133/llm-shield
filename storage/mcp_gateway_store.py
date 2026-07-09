"""Per-tenant MCP gateway upstream config store.

Maps ``(tenant_id, route) -> upstream config`` so one gateway deployment fronts
many customers/servers by config alone. Redis-backed with an in-memory fallback
for dev/tests, mirroring the other storage modules.

Keys:
    mcp_gateway:upstream:{tenant_id}:{route}   JSON upstream config
    mcp_gateway:routes:{tenant_id}             set/list of route names (index)

Config values may contain upstream credentials (headers/env) — never log them;
the API layer redacts them on read.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis


def _key(tenant_id: str, route: str) -> str:
    return f"mcp_gateway:upstream:{tenant_id}:{route}"


def _index_key(tenant_id: str) -> str:
    return f"mcp_gateway:routes:{tenant_id}"


def _decode(raw: Any) -> Optional[dict]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


def set_upstream(tenant_id: str, route: str, config: dict) -> dict:
    """Create/replace the upstream config for (tenant, route). Returns it."""
    payload = json.dumps(config)
    r = _get_redis()
    if r:
        r.set(_key(tenant_id, route), payload)
        r.sadd(_index_key(tenant_id), route)
    else:
        _fallback_store[_key(tenant_id, route)] = payload
        idx = json.loads(_fallback_store.get(_index_key(tenant_id), "[]"))
        if route not in idx:
            idx.append(route)
            _fallback_store[_index_key(tenant_id)] = json.dumps(idx)
    return config


def get_upstream(tenant_id: str, route: str) -> Optional[dict]:
    r = _get_redis()
    raw = r.get(_key(tenant_id, route)) if r else _fallback_store.get(_key(tenant_id, route))
    return _decode(raw)


def list_upstreams(tenant_id: str) -> list[dict]:
    r = _get_redis()
    if r:
        members = r.smembers(_index_key(tenant_id)) or set()
        routes = [m.decode() if isinstance(m, bytes) else m for m in members]
    else:
        routes = json.loads(_fallback_store.get(_index_key(tenant_id), "[]"))
    out = []
    for route in sorted(routes):
        cfg = get_upstream(tenant_id, route)
        if cfg:
            out.append(cfg)
    return out


def delete_upstream(tenant_id: str, route: str) -> bool:
    """Remove a route. Returns True if it existed."""
    existed = get_upstream(tenant_id, route) is not None
    r = _get_redis()
    if r:
        r.delete(_key(tenant_id, route))
        r.srem(_index_key(tenant_id), route)
    else:
        _fallback_store.pop(_key(tenant_id, route), None)
        idx = json.loads(_fallback_store.get(_index_key(tenant_id), "[]"))
        if route in idx:
            idx.remove(route)
            _fallback_store[_index_key(tenant_id)] = json.dumps(idx)
    return existed
