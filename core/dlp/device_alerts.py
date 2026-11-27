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


# ── agent health (task 3) ─────────────────────────────────────────────
#
# device_agent_alert {device_id, hostname, fleet, reason, since, last_seen, detail}
#   restarted_without_reboot  the agent started again, the machine did not
#                             reboot, and it never said it was stopping (killed)
#   stopped                   it said it was stopping, the machine kept running,
#                             and it was down longer than the grace period
#   capture_disabled          the system proxy no longer points at the agent
#   silent                    opt-in: no heartbeat for alerts.silent_after_s
#   returned                  the device is healthy again after stopped,
#                             capture_disabled or silent
#
# Decided when a heartbeat arrives (comparing it with the previous one), never
# while the device is quiet: a laptop shut down for the night also says it is
# stopping and then goes quiet, and only its next heartbeat shows the reboot.
# The open episode is kept on the device's last-heartbeat record as `health`,
# so the fleet view shows it with no extra read.

EVENT_HEALTH = "device_agent_alert"
SAME_BOOT_S = 120          # booted_at from two heartbeats within this: same boot
NEW_START_S = 60           # agent_started_at moved by more than this: a new start


def stop_grace_s() -> int:
    return _int_env("SHIELD_DEVICE_STOP_GRACE_S", 900, 60, 86400)


def _was_stop(s: Optional[dict]) -> bool:
    ls = (s or {}).get("last_stop") or {}
    return bool(ls) and ls.get("at") == (s or {}).get("at")


def _same_boot(a: dict, b: dict) -> bool:
    return (a.get("booted_at") is not None and b.get("booted_at") is not None
            and abs(int(a["booted_at"]) - int(b["booted_at"])) <= SAME_BOOT_S)


def health_payload(device_id: str, record: dict, reason: str, since: int, last_seen: int,
                   detail: str = "") -> dict:
    return {"device_id": device_id, "hostname": (record or {}).get("hostname", ""),
            "fleet": (record or {}).get("fleet", ""), "reason": reason, "since": int(since),
            "last_seen": int(last_seen), "detail": detail[:200]}


def classify_heartbeat(device_id: str, record: dict, prev: Optional[dict], seen: dict,
                       policy_alerts: Optional[dict] = None) -> list[dict]:
    """Compare this heartbeat with the previous one. Sets seen["health"] (the
    open episode, or None) and returns the alerts to send."""
    pa = policy_alerts or {}
    tamper = pa.get("tamper", True) is not False
    prev = prev or {}
    now = int(seen["at"])
    health = prev.get("health")
    out: list[dict] = []

    def alert(reason, since, detail=""):
        if tamper or reason == "returned":
            out.append(health_payload(device_id, record, reason, since, prev.get("at", now), detail))

    if _was_stop(seen):                       # this heartbeat says it is stopping: decide on return
        seen["health"] = health
        return out
    if prev.get("at"):
        new_start = (prev.get("agent_started_at") is not None and seen.get("agent_started_at") is not None
                     and int(seen["agent_started_at"]) - int(prev["agent_started_at"]) > NEW_START_S)
        same_boot = _same_boot(prev, seen)
        same_version = prev.get("agent_version") == seen.get("agent_version")
        if new_start and same_boot:
            if _was_stop(prev):
                down = int(seen["agent_started_at"]) - int(prev["at"])
                if down > stop_grace_s() and same_version:
                    alert("stopped", prev["at"], f"agent down {down} s while the machine kept running")
                    if tamper:
                        alert("returned", now, "after stopped")
            elif same_version:
                alert("restarted_without_reboot", prev.get("at", now),
                      "the agent started again without saying it was stopping; the machine did not reboot")
    cap_now = (seen.get("capture") or {}).get("state")
    cap_prev = (prev.get("capture") or {}).get("state")
    if health is None and cap_prev == "ok" and cap_now in ("missing", "overridden"):
        eff = (seen.get("capture") or {}).get("effective", "")
        health = {"reason": "capture_disabled", "since": now}
        alert("capture_disabled", now, f"proxy setting {cap_now}" + (f": {eff}" if eff else ""))
    elif health and (health.get("reason") != "capture_disabled" or cap_now in ("ok", None)):
        alert("returned", now, f"after {health.get('reason')}")
        health = None
    seen["health"] = health
    return out


async def deliver(tenant_id: str, event: str, payloads: list[dict]) -> int:
    if not payloads or not enabled():
        return 0
    from core.webhook_dispatcher import dispatch_event
    await asyncio.gather(*(dispatch_event(tenant_id, event, p) for p in payloads),
                         return_exceptions=True)
    return len(payloads)
