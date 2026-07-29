"""Per-route MCP onboarding scan reports.

A scan report is kept OFF the route document on purpose. The route config is read
once per guarded call (core/mcp/gateway.py::_load_cfg), and a full report carries
findings with evidence strings — putting it there would inflate every hot-path
read to carry data only the console ever looks at. The route document holds a
three-field summary; the report itself lives here.

Keys:
    mcp_scan:{tenant_id}:{route}   JSON scan report

Findings quote text from the *upstream*, which for a poisoned server is attacker
controlled. It is stored verbatim for evidence and must be escaped by whatever
renders it.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis


def _key(tenant_id: str, route: str) -> str:
    return f"mcp_scan:{tenant_id}:{route}"


def _decode(raw: Any) -> Optional[dict]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


def set_scan_report(tenant_id: str, route: str, report: dict) -> dict:
    """Store (replacing) the scan report for one route."""
    payload = json.dumps(report)
    r = _get_redis()
    if r:
        r.set(_key(tenant_id, route), payload)
    else:
        _fallback_store[_key(tenant_id, route)] = payload
    return report


def get_scan_report(tenant_id: str, route: str) -> Optional[dict]:
    r = _get_redis()
    key = _key(tenant_id, route)
    return _decode(r.get(key) if r else _fallback_store.get(key))


def delete_scan_report(tenant_id: str, route: str) -> bool:
    """Drop a route's report. Returns True if one existed.

    Called when a route is removed: a stale report keyed to a route name that is
    later reused would otherwise show the previous server's findings against the
    new one.
    """
    existed = get_scan_report(tenant_id, route) is not None
    r = _get_redis()
    if r:
        r.delete(_key(tenant_id, route))
    else:
        _fallback_store.pop(_key(tenant_id, route), None)
    return existed
