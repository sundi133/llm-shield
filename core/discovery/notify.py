"""The `ai_discovered` webhook. Spec: docs/specs/ai-discovery.md, section 4.2.

Raised for a new entry that is not governed, and for an entry marked
unsanctioned that is seen again. Shield's own evidence (source "shield") never
raises it: those are things already passing through Shield, and shadow agents
have their own `shadow_agent_detected` event. At most MAX_PER_BATCH events per
batch; the rest are summed in one more event, so a large import is one burst,
not thousands.
"""

from __future__ import annotations

import asyncio
import logging

EVENT = "ai_discovered"
MAX_PER_BATCH = 20
log = logging.getLogger("votal.discovery")


def payloads(events: list) -> list[dict]:
    out = []
    for e in events or []:
        if e.get("source") == "shield":
            continue
        if e.get("type") == "new" and e.get("governed") is not True:
            out.append({"reason": "new_ungoverned", **{k: e.get(k) for k in
                        ("entry_id", "name", "kind", "governed", "source", "at")}})
        elif e.get("type") == "unsanctioned_seen":
            out.append({"reason": "unsanctioned_seen", **{k: e.get(k) for k in
                        ("entry_id", "name", "source", "at")}})
    if len(out) > MAX_PER_BATCH:
        rest = out[MAX_PER_BATCH:]
        out = out[:MAX_PER_BATCH] + [{"reason": "more", "count": len(rest),
                                      "entry_ids": [p["entry_id"] for p in rest[:100]]}]
    return out


def _enabled() -> bool:
    from core.feature_flags import WEBHOOKS_ENABLED
    return bool(WEBHOOKS_ENABLED)


async def dispatch(tenant_id: str, events: list) -> int:
    """From a request: schedules delivery and returns at once."""
    ps = payloads(events)
    if not ps or not _enabled():
        return 0
    from core.webhook_dispatcher import dispatch_event
    for p in ps:
        asyncio.get_running_loop().create_task(dispatch_event(tenant_id, EVENT, p))
    return len(ps)


def dispatch_sync(tenant_id: str, events: list) -> int:
    """From a worker thread (log imports), which has no event loop."""
    ps = payloads(events)
    if not ps or not _enabled():
        return 0
    from core.webhook_dispatcher import dispatch_event

    async def _all():
        await asyncio.gather(*(dispatch_event(tenant_id, EVENT, p) for p in ps), return_exceptions=True)
    try:
        asyncio.run(_all())
    except Exception:
        log.warning("ai_discovered webhooks not delivered", exc_info=True)
    return len(ps)
