"""Silence alerts for device agents (opt-in), on the admin plane.

Spec: docs/specs/device-block-and-stop-alerts.md (R2, task 3). Every other
agent health alert is decided when a heartbeat arrives (device_alerts); only
"silent" needs someone to look while a device is quiet. It is off unless a
tenant sets alerts.silent_after_s (laptops sleep every night).

A daemon thread started by admin_app sweeps once a minute. One replica does the
work per minute (a counter keyed by the minute). It reads only tenants that
turned silence alerts on (the device_watch_tenants set, kept by the policy
save), and only their quiet devices (the last-seen index; a full read when the
index is not usable). A device alerts once per silent spell: the episode is
stored as `health` on its last-heartbeat record, and its next heartbeat sends
`returned`. More than MAX_PER_SWEEP in a tenant become one summary.

SHIELD_DEVICE_WATCH=off (or SHIELD_DEVICE_ALERTS=off) stops the sweep.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Optional

from core.dlp import device_alerts
from core.dlp import devices as dv

log = logging.getLogger("votal.devices")

TENANTS_KEY = "device_watch_tenants"
SWEEP_S = 60
MAX_PER_SWEEP = 50
_started = False
_start_lock = threading.Lock()


def enabled() -> bool:
    off = ("off", "0", "false", "no")
    return ((os.environ.get("SHIELD_DEVICE_WATCH", "on") or "on").strip().lower() not in off
            and device_alerts.enabled())


def note_policy(tenant_id: str, policy: dict) -> None:
    """Keep the set of tenants with silence alerts on (called on policy save)."""
    from core.dlp import device_index as dix
    on = int(((policy or {}).get("alerts") or {}).get("silent_after_s") or 0) > 0
    try:
        if on:
            dix._sadd(TENANTS_KEY, [tenant_id])
        else:
            r = dv._redis()
            if r is None:
                dv._mem_sets.get(TENANTS_KEY, set()).discard(tenant_id)
            else:
                r.srem(TENANTS_KEY, tenant_id)
    except Exception:
        log.warning("device watch: could not update the tenant set", exc_info=True)


def _quiet_devices(tenant_id: str, cutoff: int) -> list[str]:
    from core.dlp import device_index as dix
    if dix._usable(tenant_id):
        return dix._zbelow(dix._last_key(tenant_id), cutoff, 0, 10000)
    seen = dv._hgetall(dv._seen_key(tenant_id))
    return [did for did, s in seen.items() if int(s.get("at") or 0) < cutoff]


def sweep_tenant(tenant_id: str, now: Optional[int] = None) -> list[dict]:
    """The silent alerts for one tenant, with their episodes opened."""
    from core.dlp import device_store
    now = int(now or time.time())
    alerts_cfg = device_store.get_policy(tenant_id).get("alerts") or {}
    after = int(alerts_cfg.get("silent_after_s") or 0)
    if after <= 0 or alerts_cfg.get("tamper", True) is False:
        return []
    out = []
    for did in _quiet_devices(tenant_id, now - after):
        s = dv._hget(dv._seen_key(tenant_id), did)
        if not s or s.get("health"):              # never reported, or already in an episode
            continue
        record = dv._hget(dv._devices_key(tenant_id), did) or {}
        s["health"] = {"reason": "silent", "since": now}
        dv._hset(dv._seen_key(tenant_id), did, s)
        out.append(device_alerts.health_payload(did, record, "silent", now, s.get("at", 0),
                                                f"no heartbeat for {now - int(s.get('at', 0))} s"))
    if len(out) > MAX_PER_SWEEP:
        out = [{"reason": "silent", "count": len(out), "summary": True, "since": now,
                "device_ids": [p["device_id"] for p in out[:100]]}]
    return out


def sweep(now: Optional[int] = None) -> int:
    """One pass over every watched tenant. Returns alerts sent. Never raises."""
    from core.dlp import device_index as dix
    now = int(now or time.time())
    try:
        if dv._incr(f"device_watch_lock:{now // SWEEP_S}", 2 * SWEEP_S) > 1:
            return 0                               # another replica has this minute
        sent = 0
        for tenant_id in sorted(dix._smembers(TENANTS_KEY)):
            try:
                ps = sweep_tenant(tenant_id, now)
                if ps:
                    sent += asyncio.run(device_alerts.deliver(tenant_id, device_alerts.EVENT_HEALTH, ps))
            except Exception:
                log.warning("device watch: tenant %s skipped", tenant_id, exc_info=True)
        return sent
    except Exception:
        log.warning("device watch: sweep skipped", exc_info=True)
        return 0


def start() -> bool:
    """Start the sweep thread once per process (admin plane)."""
    global _started
    if not enabled():
        return False
    with _start_lock:
        if _started:
            return False
        _started = True

    def loop():
        while True:
            time.sleep(SWEEP_S)
            sweep()
    threading.Thread(target=loop, name="device-watch", daemon=True).start()
    return True
