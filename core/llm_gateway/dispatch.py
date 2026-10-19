"""Call a route's targets in order, failing over on the errors the route names.

Spec: docs/specs/gateway-routing-failover.md, sections 4.1, 5 and 7.

- Only targets in the plan are tried, in the plan's order: failover never
  leaves the eligible list.
- A timeout, connection error, 429 or 5xx moves to the next target (when the
  route's `failover.on` lists it); any other 4xx stops, since another target
  would fail the same request the same way.
- A target whose credential cannot be resolved, or whose URL is unsafe, is
  skipped and counted as a failure.
- The guardrails are not here: the endpoint runs them before and after, once.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

import httpx

from core.llm_gateway import config
from core.llm_gateway.select import Plan

logger = logging.getLogger("votal.llm_gateway")

PASSTHROUGH_HEADER = "X-Shield-Upstream-Key"
#: Fields Shield reads from the request body that providers do not accept.
SHIELD_FIELDS = {"prompt", "system", "x_shield", "run_id"}
URL_CHECK_TTL_S = 60

_url_ok: dict[tuple, float] = {}
#: Tests replace this with an httpx.MockTransport.
transport: Optional[httpx.AsyncBaseTransport] = None


class RoutingError(Exception):
    def __init__(self, message: str, attempts: list, status: int = 502):
        super().__init__(message)
        self.attempts = attempts
        self.status = status


class Exhausted(RoutingError):
    """Every eligible target failed."""


class UpstreamRejected(RoutingError):
    """A target refused the request itself (a 4xx other than 408 or 429)."""

    def __init__(self, message: str, attempts: list, status: int, body):
        super().__init__(message, attempts, status)
        self.body = body


def _client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
                             follow_redirects=False, transport=transport)


# ── what is sent ─────────────────────────────────────────────────────


def upstream_body(body: dict, messages: list, target: dict) -> dict:
    """The client's body for this target: its model, without Shield's fields.
    A prompt-style request becomes the messages Shield built from it."""
    out = {k: v for k, v in body.items() if k not in SHIELD_FIELDS}
    if not body.get("messages"):
        out["messages"] = messages
    out["model"] = target["model"]
    return out


async def _check_url(url: str, allow_private: bool) -> None:
    """validate_outbound_url (DNS resolution included) off the event loop,
    remembered for a minute per URL."""
    key = (url, allow_private)
    if _url_ok.get(key, 0) > time.time():
        return
    from core.url_safety import validate_outbound_url

    def check():
        validate_outbound_url(url, purpose="llm-target", allow_private=allow_private)
    await asyncio.get_running_loop().run_in_executor(None, check)
    if len(_url_ok) > 5000:
        _url_ok.clear()
    _url_ok[key] = time.time() + URL_CHECK_TTL_S


def check_url_sync(url: str, allow_private: bool) -> None:
    """For config writes: raises ValueError naming the problem."""
    from core.url_safety import UnsafeURLError, validate_outbound_url
    try:
        validate_outbound_url(url, purpose="llm-target", allow_private=allow_private)
    except UnsafeURLError as e:
        raise ValueError(str(e))


class CredentialUnavailable(Exception):
    pass


def headers_for(tenant_id: str, target: dict, request_headers) -> dict:
    """Request headers for one target. Raises CredentialUnavailable."""
    url = config.target_url(target)
    out = {"Content-Type": "application/json", "Accept": "application/json"}
    auth = target.get("auth") or {}
    mode, header, scheme = auth.get("mode", "none"), auth.get("header", "Authorization"), auth.get("scheme", "")
    if mode == "vault":
        from core.secret_vault.materialize import materialize_headers
        value = f"{scheme} {auth.get('secret_ref', '')}".strip()
        resolved, unresolved = materialize_headers(tenant_id, {header: value}, url)
        if unresolved or resolved.get(header) == value:
            raise CredentialUnavailable("the vault reference is unknown, disabled, or not bound to this host")
        out[header] = resolved[header]
    elif mode == "passthrough":
        key = (request_headers or {}).get(PASSTHROUGH_HEADER) or (request_headers or {}).get(
            PASSTHROUGH_HEADER.lower())
        if not key:
            raise CredentialUnavailable(f"this target needs the caller's key in {PASSTHROUGH_HEADER}")
        out[header] = f"{scheme} {key}".strip()
    return out


def _classify(status: int) -> str:
    if status in (408,):
        return "timeout"
    if status == 429:
        return "429"
    if status >= 500:
        return "5xx"
    return "4xx"


def _failover_allowed(route: dict, outcome: str) -> bool:
    if outcome in ("credential_unavailable", "unsafe_url", "circuit_open"):
        return True                     # the target cannot serve anyone; not the request's fault
    if outcome == "bad_response":
        outcome = "5xx"
    return outcome in ((route.get("failover") or {}).get("on") or config.FAILOVER_ON)


def _error_body(resp: httpx.Response):
    try:
        return resp.json()
    except ValueError:
        return {"error": {"message": resp.text[:500] or f"upstream answered {resp.status_code}"}}


# ── the call ─────────────────────────────────────────────────────────


async def complete(tenant_id: str, plan: Plan, body: dict, messages: list, request_headers) -> tuple:
    """(response JSON, routing info). Raises Exhausted or UpstreamRejected."""
    route = plan.route
    fo = route.get("failover") or {}
    deadline = time.monotonic() + float(fo.get("deadline_s", 120))
    max_attempts = int(fo.get("max_attempts", 3))
    attempts: list = []
    for target in plan.targets:
        if len([a for a in attempts if a["outcome"] not in ("circuit_open",)]) >= max_attempts:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0.5:
            break
        t0 = time.monotonic()
        outcome, data, resp = await _attempt(tenant_id, target, body, messages, request_headers,
                                             min(float(target.get("timeout_s", 60)), remaining))
        ms = round((time.monotonic() - t0) * 1000, 1)
        attempts.append({"target": target["id"], "outcome": outcome, "ms": ms})
        _note(tenant_id, target, outcome, ms)
        if outcome == "ok":
            return data, info(plan, target, attempts)
        if outcome == "4xx":
            raise UpstreamRejected(f"target '{target['id']}' refused the request ({resp.status_code})",
                                   attempts, resp.status_code, _error_body(resp))
        if not _failover_allowed(route, outcome):
            break
    raise Exhausted(f"no target of route '{route['name']}' answered", attempts)


async def _attempt(tenant_id: str, target: dict, body: dict, messages: list, request_headers,
                   timeout: float):
    url = config.target_url(target)
    try:
        await _check_url(url, bool(target.get("allow_private")))
    except Exception as e:
        logger.warning("llm target %s: unsafe URL (%s)", target["id"], e)
        return "unsafe_url", None, None
    try:
        headers = headers_for(tenant_id, target, request_headers)
    except CredentialUnavailable as e:
        logger.warning("llm target %s: %s", target["id"], e)
        return "credential_unavailable", None, None
    payload = upstream_body(body, messages, target)
    try:
        async with _client(timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException:
        return "timeout", None, None
    except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.NetworkError):
        return "connect", None, None
    if resp.status_code >= 400:
        return _classify(resp.status_code), None, resp
    try:
        data = resp.json()
    except ValueError:
        return "bad_response", None, resp
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
        return "bad_response", None, resp
    return "ok", data, resp


def info(plan: Plan, target: dict, attempts: list) -> dict:
    return {"route": plan.route["name"], "target": target["id"], "model": target["model"],
            "attempts": attempts, "failovers": max(0, len(attempts) - 1), "rule": plan.rule,
            "budget": plan.budget}


def headers_out(routing: dict) -> dict:
    return {"X-Shield-Route": routing["route"], "X-Shield-Target": routing.get("target") or "",
            "X-Shield-Failovers": str(routing.get("failovers", 0)),
            "X-Shield-Budget": routing.get("budget", "ok")}


def _note(tenant_id: str, target: dict, outcome: str, ms: float) -> None:
    """Health and latency bookkeeping (task 2)."""
    return None


def describe(err: RoutingError) -> str:
    parts = [f"{a['target']}: {a['outcome']}" for a in err.attempts]
    return f"{err} ({'; '.join(parts) or 'no target tried'})"


def dumps(o) -> str:
    return json.dumps(o, separators=(",", ":"))
