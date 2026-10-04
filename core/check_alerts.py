"""One alert when a tool policy check could not run, not one per call.

A model outage fails every guarded tool call at once. Dispatching a webhook per
failure would flood the tenant's endpoint and their SIEM, so failures are
counted per (tenant, side) in this process and an alert goes out at most once
per window, carrying how many failures it covers. The first failure alerts
straight away; the ones after it inside the window are folded into the next
alert. Each worker keeps its own window, so a deployment with N workers sends
up to N alerts per window during an outage.

Guard path: called only after a check has already failed, costs one dict
lookup, and dispatches with create_task. Stdlib only at module load (the
webhook dispatcher is imported when an alert is actually sent).
Spec: docs/specs/tool-policy-fail-safe.md, task 2.
"""
import asyncio
import logging
import threading
import time

logger = logging.getLogger(__name__)

EVENT = "check_unavailable"
WINDOW_SECONDS = 300

#: (tenant_id, side) -> [monotonic time of the last alert, failures since it]
_state: dict = {}
_lock = threading.Lock()
# Strong references: asyncio only holds weak ones, and an unreferenced task
# can be collected mid-send.
_TASKS: set = set()


def _take(tenant_id: str, side: str, now: float):
    """Record one failure. Returns the count to alert with, or None."""
    with _lock:
        entry = _state.get((tenant_id, side))
        if entry is None or now - entry[0] >= WINDOW_SECONDS:
            count = (entry[1] if entry else 0) + 1
            _state[(tenant_id, side)] = [now, 0]
            return count
        entry[1] += 1
        return None


def note_unchecked(tenant_id: str, side: str, tool: str, blocked: bool, error: str) -> None:
    """A check on `side` ("tool_call" or "tool_result") could not run.

    `error` is an exception class name. Never pass arguments, results or a
    model reply: this payload leaves the deployment.
    """
    if not tenant_id:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # no loop, nowhere to send from; the metric still counts it
    count = _take(tenant_id, side, time.monotonic())
    if count is None:
        return
    payload = {"side": side, "tool": tool,
               "decision": "blocked" if blocked else "let_through",
               "error": error, "count": count, "window_seconds": WINDOW_SECONDS}

    async def _send():
        try:
            from core.webhook_dispatcher import dispatch_event
            await dispatch_event(tenant_id, EVENT, payload)
        except Exception as e:  # noqa: BLE001 - an alert must never fail a call
            logger.debug("check_unavailable alert not sent: %s", e)

    task = loop.create_task(_send())
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)


def _reset() -> None:
    """Tests only."""
    with _lock:
        _state.clear()
