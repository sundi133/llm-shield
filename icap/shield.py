"""Tier 2: the authoritative screen against Shield, plus telemetry.

Task 4 of docs/spec-swg-icap-adapter.md.

Tier 1 decides; this decides *later*. A cloud text screen measures 14 to 20
seconds, which no ICAP transaction can absorb, so by default the screen is
submitted to a bounded background queue and the request is forwarded
immediately. What it buys is not inline enforcement but visibility: injection
and jailbreak detection, and every AI-bound prompt landing in the tenant's
telemetry with a device and a destination attached.

`SHIELD_ICAP_SYNC_SCREEN=1` makes it inline for operators who accept the
latency. Off by default, and the spec is explicit about why.

**Availability never blocks browsing in the default configuration.** Shield
being unreachable degrades this tier to nothing and leaves Tier 1 enforcing
from its cached bundle. `SHIELD_ICAP_FAIL_OPEN` only has teeth in sync mode,
where the operator has already chosen to put Shield on the request path.

One honest limitation. The tenant audit record is written by
`/guardrails/input` from its own verdict, so a Tier 1 block shows up in the
console as the server's re-derivation of the same prompt, not as the adapter's
local rule id. Correlating the two needs a server-side change and is out of
scope for v1.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from icap.config import IcapConfig
from icap.server import IcapRequest, Verdict

log = logging.getLogger("shield.icap")

SCREEN_PATH = "/guardrails/input"


class ShieldClient:
    """Calls /guardrails/input, inline or in the background."""

    def __init__(self, config: IcapConfig, client: Optional[httpx.AsyncClient] = None):
        self.cfg = config
        self._client = client
        self._owned: Optional[httpx.AsyncClient] = None
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.telemetry_queue)
        self._workers: list[asyncio.Task] = []
        self.dropped = 0
        self.submitted = 0

    # -- lifecycle -----------------------------------------------------------

    def _http(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        if self._owned is None:
            self._owned = httpx.AsyncClient(timeout=self.cfg.screen_timeout_s)
        return self._owned

    def start(self) -> None:
        if self._workers:
            return
        self._workers = [
            asyncio.ensure_future(self._worker()) for _ in range(self.cfg.telemetry_workers)
        ]

    async def aclose(self) -> None:
        for task in self._workers:
            task.cancel()
        self._workers = []
        if self._owned is not None:
            await self._owned.aclose()
            self._owned = None

    async def drain(self) -> None:
        """Wait for the queue to empty. Tests and shutdown only."""
        await self._queue.join()

    # -- request shaping -----------------------------------------------------

    def _headers(self, req: IcapRequest) -> dict[str, str]:
        headers = {
            "X-API-Key": self.cfg.api_key,
            "Content-Type": "application/json",
            # Distinguishes this tap from the browser extension, so telemetry
            # can tell the two apart when a fleet runs both.
            "X-Shield-Source": "icap",
            "X-Shield-Destination": req.host,
        }
        if self.cfg.proxy_token:
            headers["Authorization"] = f"Bearer {self.cfg.proxy_token}"
        device = req.authenticated_user
        if device:
            headers["X-Device-Id"] = device
        return headers

    @staticmethod
    def _message(req: IcapRequest) -> str:
        """The turn being sent, which is what /guardrails/input is shaped for.

        Falls back to the full extracted text when a body carried no identifiable
        user turn, so a screen still happens rather than sending nothing.
        """
        prompt = req.prompt
        return prompt.last_user or prompt.text

    def _body(self, req: IcapRequest) -> dict:
        return {"message": self._message(req), "session_id": req.txn_id}

    # -- screening -----------------------------------------------------------

    def screenable(self, req: IcapRequest) -> bool:
        """Unknown body shapes skip Tier 2 (spec §7); Tier 1 still sees them."""
        if not self.cfg.api_key:
            return False
        return req.prompt.parsed and bool(self._message(req))

    async def _post(self, req: IcapRequest) -> Optional[dict]:
        resp = await self._http().post(
            self.cfg.api_base.rstrip("/") + SCREEN_PATH,
            json=self._body(req),
            headers=self._headers(req),
            timeout=self.cfg.screen_timeout_s,
        )
        if resp.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"screen http={resp.status_code}", request=resp.request, response=resp
            )
        return resp.json()

    async def screen_sync(self, req: IcapRequest) -> Verdict:
        """Inline screen. Only reached when SHIELD_ICAP_SYNC_SCREEN=1."""
        try:
            # Deadline enforced here as well as passed to httpx. On this path
            # the ICAP transaction, and therefore a browser tab, is waiting on
            # the result -- not something to leave to a client library honouring
            # its own timeout config.
            result = await asyncio.wait_for(self._post(req), timeout=self.cfg.screen_timeout_s)
        except Exception as exc:
            # A timeout is not an approval. In sync mode the operator has put
            # Shield on the request path deliberately, so the configured
            # posture decides -- and it defaults to closed.
            log.warning("icap sync screen failed txn=%s err=%s", req.txn_id, exc)
            if self.cfg.fail_open:
                return Verdict()
            return Verdict(
                block=True,
                rule_id="shield_unavailable",
                payload={
                    "error": "Blocked: the screening service is unavailable and "
                             "policy is set to fail closed.",
                    "code": "blocked_by_votal_shield",
                    "reason": "Screening service unavailable and policy is fail-closed.",
                    "rule_id": "shield_unavailable",
                    "severity": "high",
                },
            )
        return self.to_verdict(result or {})

    @staticmethod
    def to_verdict(result: dict) -> Verdict:
        if (result.get("action") or "").lower() != "block":
            return Verdict()
        triggered = [
            g for g in (result.get("guardrail_results") or []) if not g.get("passed", True)
        ]
        names = [g.get("guardrail", "?") for g in triggered] or ["policy"]
        reasons = [g.get("message", "") for g in triggered if g.get("message")]
        return Verdict(
            block=True,
            rule_id=names[0],
            payload={
                "error": "Blocked by your organization's AI policy. "
                         + ("; ".join(reasons) or f"Triggered guardrail: {names[0]}"),
                "code": "blocked_by_votal_shield",
                "reason": "; ".join(reasons) or f"Blocked by guardrail: {names[0]}",
                "rule_id": names[0],
                "guardrails": names,
                "severity": "high",
            },
        )

    # -- background telemetry ------------------------------------------------

    def submit(self, req: IcapRequest) -> None:
        """Queue a screen without awaiting it. Never blocks the transaction.

        A full queue drops rather than applying backpressure: telemetry is worth
        a lot, but not worth holding an employee's browser tab open for.
        """
        if not self.screenable(req):
            return
        try:
            self._queue.put_nowait(req)
            self.submitted += 1
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped % 100 == 1:
                log.warning(
                    "icap telemetry queue full, dropped=%d (screening is falling behind)",
                    self.dropped,
                )

    async def _worker(self) -> None:
        while True:
            req = await self._queue.get()
            try:
                result = await self._post(req)
                action = (result or {}).get("action", "pass")
                if action == "block":
                    # Async mode cannot retract a forwarded request. Recording
                    # it is the difference between an incident someone can find
                    # later and one that never happened as far as the console
                    # is concerned.
                    log.warning(
                        "icap async screen would have blocked txn=%s host=%s",
                        req.txn_id, req.host,
                    )
            except Exception as exc:
                log.warning("icap async screen failed txn=%s err=%s", req.txn_id, exc)
            finally:
                # CancelledError is a BaseException, so it passes through the
                # handler above and still lands here: one get, one task_done.
                self._queue.task_done()


class ScreenPipeline:
    """Tier 1 then Tier 2, in the order their latencies allow."""

    def __init__(self, tier1, shield: ShieldClient, config: IcapConfig):
        self.tier1 = tier1
        self.shield = shield
        self.cfg = config

    async def __call__(self, req: IcapRequest) -> Verdict:
        verdict = await self.tier1(req)

        if verdict.block:
            # Still submitted: a local block that never reaches telemetry is a
            # block the tenant's console cannot show anyone.
            self.shield.submit(req)
            return verdict

        if self.cfg.sync_screen and self.shield.screenable(req):
            return await self.shield.screen_sync(req)

        self.shield.submit(req)
        return Verdict()
