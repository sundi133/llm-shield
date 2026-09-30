"""Tier 1 policy: the tenant's DLP rules, evaluated locally.

Task 3 of docs/spec-swg-icap-adapter.md.

Tier 1 exists because of a latency fact: a cloud text screen is a network
round trip (measured at 1.5-1.9s against the deployed data plane, and
documented elsewhere as far worse), which no ICAP transaction should carry on
every prompt. So the rules that must block inline -- secrets, PII,
keyword blocklists -- are evaluated here from a cached bundle, in under a
millisecond, with no network call on the request path at all.

The bundle comes from `GET /v1/edge/policy-bundle`, which already exists for the
browser extension and ships patterns only, never secrets. Reused verbatim.

The one behaviour to keep in mind while reading this file: **an empty policy
allows everything.** If the bundle has never loaded, this layer has no rules and
cannot block. That is deliberate and load-bearing. Failing closed on an empty
policy would black-hole every AI request in the enterprise the first time Shield
was unreachable at boot, which is a worse outage than the leak it would prevent.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx
# `regex`, not stdlib `re`, for two properties this component cannot do
# without. It supports a real per-match `timeout=`, and it releases the GIL
# while matching. stdlib `re` offers neither: a catastrophic pattern there
# holds the GIL for the whole match, so an asyncio deadline cannot even fire
# until the match it was meant to bound has already finished.
import regex

from icap.config import IcapConfig
# The rule engine lives in icap/rules.py, shared with the device agent
# (docs/specs/device-dlp-agent.md). Re-exported so every importer is unchanged.
from icap.rules import (  # noqa: F401
    EMPTY, Bundle, Hit, Rule, compile_bundle, evaluate,
)
from icap.server import IcapRequest, Verdict

log = logging.getLogger("shield.icap")

BUNDLE_PATH = "/v1/edge/policy-bundle"


class PolicyCache:
    """Holds the last-known-good bundle and refreshes it on a timer."""

    def __init__(
        self,
        config: IcapConfig,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.cfg = config
        self._client = client
        self._bundle: Bundle = EMPTY
        self._etag: str = ""
        self._reachable: Optional[bool] = None
        self._last_error: str = ""
        self._task: Optional[asyncio.Task] = None

    @property
    def bundle(self) -> Bundle:
        return self._bundle

    @property
    def version(self) -> str:
        # Falls back to the build id until a bundle lands, so the SWG always has
        # an ISTag to cache against.
        return self._bundle.version or self.cfg.version

    @property
    def reachable(self) -> Optional[bool]:
        return self._reachable

    @property
    def last_error(self) -> str:
        """Why the most recent refresh did not land, empty when it did.

        Surfaced on /healthz because "reachable but refused" is the failure
        that looks healthiest: an operator sees ok=true and misses rules=0.
        """
        return self._last_error

    def _headers(self) -> dict[str, str]:
        headers = {"X-API-Key": self.cfg.api_key}
        if self.cfg.proxy_token:
            headers["Authorization"] = f"Bearer {self.cfg.proxy_token}"
        if self._etag:
            headers["If-None-Match"] = self._etag
        return headers

    async def refresh(self) -> bool:
        """Fetch the bundle. Returns True when the cached copy changed.

        A failure after a successful load keeps serving the old bundle
        indefinitely. Stale policy beats no policy: the alternative is that a
        Shield outage silently disarms the customer's DLP.
        """
        if not self.cfg.api_key:
            log.warning("icap bundle refresh skipped: SHIELD_API_KEY is not set")
            return False
        client = self._client or httpx.AsyncClient(timeout=self.cfg.bundle_timeout_s)
        owned = self._client is None
        try:
            resp = await client.get(
                self.cfg.api_base.rstrip("/") + BUNDLE_PATH, headers=self._headers()
            )
            self._reachable = True
            if resp.status_code == 304:
                return False
            if resp.status_code in (401, 403):
                # Reachable but refused. Distinct from unreachable, and worth
                # its own state: healthz would otherwise read ok/reachable
                # while rules stayed 0, which looks healthy and enforces
                # nothing.
                self._last_error = f"http {resp.status_code}: tenant key rejected"
                log.error(
                    "icap bundle refresh REJECTED http=%s -- check SHIELD_API_KEY, and "
                    "that the data plane routes /v1/edge through its auth middleware. "
                    "No rules loaded means nothing will be blocked.",
                    resp.status_code,
                )
                return False
            if resp.status_code >= 400:
                self._last_error = f"http {resp.status_code}"
                log.warning("icap bundle refresh http=%s (serving cached)", resp.status_code)
                return False
            bundle = compile_bundle(resp.json(), self.cfg.redact_fallback)

            # Policy differs per tenant, so loading the wrong one governs a
            # fleet by another organisation's rules. When SecOps has declared
            # which tenant this deployment is for, a mismatch is refused
            # rather than applied: no policy is a visible failure, the wrong
            # policy is an invisible one.
            expected = self.cfg.expect_tenant
            if expected and bundle.tenant_id and bundle.tenant_id != expected:
                self._last_error = (
                    f"tenant mismatch: key resolves to '{bundle.tenant_id}', "
                    f"SHIELD_ICAP_EXPECT_TENANT is '{expected}'"
                )
                log.error(
                    "icap REFUSING policy: the API key belongs to tenant '%s' but this "
                    "deployment declares '%s'. Check SHIELD_API_KEY. No policy loaded.",
                    bundle.tenant_id, expected,
                )
                # Drop what is already loaded, unlike a fetch failure. A failed
                # fetch means "cannot refresh, keep what we know is right"; a
                # tenant mismatch means the key itself is not the one this
                # deployment is for, so confidence in the cached policy is gone
                # too. Enforcing nothing is visible; enforcing another
                # organisation's rules is not.
                self._bundle = EMPTY
                self._etag = ""
                return False

            etag = resp.headers.get("etag", "")
            if bundle.version and bundle.version == self._bundle.version:
                self._etag = etag or self._etag
                return False
            self._bundle = bundle
            self._etag = etag or f'"{bundle.version}"'
            self._last_error = ""
            log.info(
                "icap bundle loaded tenant=%s version=%s rules=%d blocklists=%d skipped=%d",
                bundle.tenant_id or "?", bundle.version, len(bundle.rules),
                len(bundle.blocklists), bundle.skipped,
            )
            return True
        except Exception as exc:  # network, TLS, malformed JSON
            self._reachable = False
            self._last_error = str(exc)[:200]
            log.warning(
                "icap bundle refresh failed: %s (serving cached version=%s)",
                exc, self._bundle.version or "none",
            )
            return False
        finally:
            if owned:
                await client.aclose()

    async def run(self) -> None:
        """Background refresh loop. Never raises out."""
        while True:
            await self.refresh()
            await asyncio.sleep(self.cfg.bundle_poll_s)

    def start(self) -> asyncio.Task:
        self._task = asyncio.ensure_future(self.run())
        return self._task


class Tier1Screener:
    """The screener the ICAP server calls. Local rules only, no network."""

    def __init__(self, cache: PolicyCache, config: Optional[IcapConfig] = None):
        self.cache = cache
        self.cfg = config or cache.cfg

    async def __call__(self, req: IcapRequest) -> Verdict:
        bundle = self.cache.bundle
        if bundle.empty:
            # Cold start, or a tenant with no DLP rules configured. Nothing to
            # match against, so nothing to block. See the module docstring.
            return Verdict()

        text = req.prompt.text
        if not text:
            return Verdict()

        budget = self.cfg.scan_timeout_ms / 1000.0
        try:
            # In a thread because `regex` releases the GIL while matching, so
            # the event loop and every other in-flight transaction stay
            # responsive for the duration. The deadline itself is enforced
            # inside the engine, not by an outer wait_for, so the work
            # terminates rather than being merely abandoned.
            hit = await asyncio.to_thread(evaluate, bundle, text, budget)
        except TimeoutError:
            # A regex that cannot finish in 250ms on a body we already capped at
            # 1 MiB is a broken pattern, not a decision. Let the request through
            # and make the pattern visible, rather than holding a browser tab.
            #
            log.warning(
                "icap scan timeout txn=%s version=%s (check tenant regex patterns)",
                req.txn_id, bundle.version,
            )
            return Verdict()

        if hit is None:
            return Verdict()

        reason = (
            f"Prompt contained data matching policy: {hit.rule_id}"
            if hit.kind == "rule"
            else f"Prompt contained a blocked term: {hit.rule_id}"
        )
        return Verdict(
            block=True,
            rule_id=hit.rule_id,
            payload={
                # `error` carries the SENTENCE, not the code. AI web apps render
                # whichever field they happen to parse, and ChatGPT renders this
                # one -- an employee was shown the bare string
                # "blocked_by_votal_shield" and told nothing about why. This is
                # the only message a blocked user ever sees, so it has to say
                # what happened and give them the reference to quote.
                "error": f"Blocked by your organization's AI policy. {reason}.",
                "code": "blocked_by_votal_shield",
                "reason": reason,
                "rule_id": hit.rule_id,
                "severity": hit.severity,
                "policy_version": bundle.version,
            },
        )
