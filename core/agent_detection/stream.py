"""The per-tenant beacon stream, `agd:{tenant}:beacons` (spec section 8).

Both Redis clients Shield runs on are supported: redis-py on-prem and the
Upstash REST client in the cloud. Their XADD signatures differ, so every
write goes through `append`. Without Redis (tests, a laptop) an in-memory
deque stands in.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from typing import Optional

MAXLEN = 200_000

_lock = threading.Lock()
_mem: dict[str, deque] = {}


def key(tenant: str) -> str:
    return f"agd:{tenant}:beacons"


def _r():
    from storage import tenant_store
    return tenant_store._get_redis()


def _is_upstash(r) -> bool:
    return type(r).__module__.split(".")[0] == "upstash_redis"


def append(tenant: str, entry: dict, r=None) -> Optional[str]:
    """XADD the entry (as JSON in field `b`), trimmed to about MAXLEN. Returns
    the stream id, or None when it went to the in-memory stand-in."""
    data = {"b": json.dumps(entry, separators=(",", ":"))}
    r = _r() if r is None else r
    if r is None:
        with _lock:
            _mem.setdefault(key(tenant), deque(maxlen=MAXLEN)).append(data)
        return None
    if _is_upstash(r):
        out = r.xadd(key(tenant), "*", data, maxlen=MAXLEN, approximate_trim=True)
    else:
        out = r.xadd(key(tenant), data, maxlen=MAXLEN, approximate=True)
    return out.decode() if isinstance(out, (bytes, bytearray)) else out


def memory_entries(tenant: str) -> list[dict]:
    """The in-memory stand-in's entries, decoded (tests and local runs)."""
    with _lock:
        return [json.loads(d["b"]) for d in _mem.get(key(tenant), ())]


def _reset_memory_for_tests() -> None:
    with _lock:
        _mem.clear()
