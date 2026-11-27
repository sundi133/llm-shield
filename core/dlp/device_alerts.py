"""Alerts for device DLP blocks (and, in task 3, stopped agents).

Spec: docs/specs/device-block-and-stop-alerts.md (R2). Delivered through the
tenant's webhooks (core/webhook_dispatcher.dispatch_event), never on the guard
path: block alerts are raised in the background task that ingests a laptop's
audit batch (POST /v1/shield/runtime/events with a device key).

device_dlp_blocked
  One per device and category per window (SHIELD_DEVICE_DLP_ALERT_WINDOW_S,
  default 300 s); later blocks in the window are only counted. A block the
  agent pushes twice (same record_hash) never alerts twice. At most
  SHIELD_DEVICE_DLP_ALERTS_PER_MINUTE (default 60) per tenant per minute; the
  overflow becomes one summary with reason "more". Never the prompt: hashes,
  lengths and names only (the agent's masked excerpt only when the tenant
  turned on privacy.capture_excerpt, which is the only way the agent sends it).

Keys (fixed time buckets, so a window is the same in Redis and in memory):
  device_dlp_seen:{tenant}:{record_hash}                  7 days
  device_dlp_alert:{tenant}:{device}:{category}:{bucket}  2 windows
  device_dlp_rate:{tenant}:{epoch_minute}                 120 s

SHIELD_DEVICE_ALERTS=off stops every device alert.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Iterable, Optional

from core.dlp import devices as dv

log = logging.getLogger("votal.devices")

EVENT_BLOCK = "device_dlp_blocked"
SEEN_TTL_S = 7 * 86400
DELAYED_AFTER_S = 120
PAYLOAD_KEYS = ("destination", "app", "category", "rule_ids", "mode", "bundle_version",
                "prompt_sha256", "prompt_len")


def enabled() -> bool:
    if (os.environ.get("SHIELD_DEVICE_ALERTS", "on") or "on").strip().lower() in ("off", "0", "false", "no"):
        return False
    try:
        from core.feature_flags import WEBHOOKS_ENABLED
        return bool(WEBHOOKS_ENABLED)
    except Exception:
        return True


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except ValueError:
        return default


def window_s() -> int:
    return _int_env("SHIELD_DEVICE_DLP_ALERT_WINDOW_S", 300, 10, 86400)


def per_minute() -> int:
    return _int_env("SHIELD_DEVICE_DLP_ALERTS_PER_MINUTE", 60, 1, 10000)


def _policy_alerts(tenant_id: str) -> dict:
    try:
        from core.dlp import device_store
        return device_store.get_policy(tenant_id).get("alerts") or {}
    except Exception:
        return {}


def block_payloads(tenant_id: str, device_id: str, events: Iterable[dict], *,
                   now: Optional[float] = None) -> list[dict]:
    """The device_dlp_blocked payloads for one device's audit batch, after
    dedupe, the per-device window and the tenant cap."""
    now = float(now if now is not None else time.time())
    blocks = [e for e in events or () if e.get("kind") == "dlp" and e.get("decision") == "deny"]
    if not blocks or _policy_alerts(tenant_id).get("dlp_blocks", True) is False:
        return []
    record = dv._hget(dv._devices_key(tenant_id), device_id) or {}
    win = window_s()
    out, overflow = [], 0
    for ev in blocks:
        d = ev.get("detail") or {}
        rh = d.get("record_hash")
        if rh and dv._incr(f"device_dlp_seen:{tenant_id}:{rh}", SEEN_TTL_S) > 1:
            continue                                   # pushed again: already handled
        category = str(d.get("category") or d.get("rule_id") or "rule")[:64]
        bucket = int(now // win)
        if dv._incr(f"device_dlp_alert:{tenant_id}:{device_id}:{category}:{bucket}", 2 * win) > 1:
            continue                                   # counted, not alerted, in this window
        if dv._incr(f"device_dlp_rate:{tenant_id}:{int(now // 60)}", 120) > per_minute():
            overflow += 1
            continue
        at = float(ev.get("at") or now)
        p = {"device_id": device_id, "hostname": record.get("hostname", ""),
             "fleet": record.get("fleet", ""), "at": at,
             "delayed": now - at > DELAYED_AFTER_S, "window_s": win,
             **{k: d[k] for k in PAYLOAD_KEYS if d.get(k) not in (None, "", [])}}
        if d.get("excerpt"):
            p["excerpt"] = d["excerpt"]
        out.append(p)
    if overflow:
        out.append({"reason": "more", "count": overflow, "device_id": device_id,
                    "hostname": record.get("hostname", ""), "at": now})
    return out


async def on_device_events(tenant_id: str, device_id: str, events: list[dict]) -> int:
    """Background task after a device's audit batch: raise and deliver block
    alerts. Never raises."""
    if not enabled():
        return 0
    try:
        ps = block_payloads(tenant_id, device_id, events)
    except Exception:
        log.warning("device alerts: block alerts skipped for %s", device_id, exc_info=True)
        return 0
    if not ps:
        return 0
    from core.webhook_dispatcher import dispatch_event
    await asyncio.gather(*(dispatch_event(tenant_id, EVENT_BLOCK, p) for p in ps),
                         return_exceptions=True)
    return len(ps)
