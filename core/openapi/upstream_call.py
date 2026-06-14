"""Build the upstream HTTP request for a generated tool call.

``build_request`` is pure (no network) so it is fully unit-testable: given a
ToolSpec, the call arguments, a base URL, and optional auth, it returns an
UpstreamRequest describing exactly what would be sent. ``execute`` performs the
send with httpx and is the only part that touches the network.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

from core.openapi.tool_mapper import ToolSpec


@dataclasses.dataclass
class UpstreamRequest:
    method: str
    url: str
    params: dict          # query string
    headers: dict
    json_body: Optional[dict]


def build_request(
    tool: ToolSpec,
    arguments: dict,
    *,
    base_url: str,
    auth: Optional[dict] = None,
) -> UpstreamRequest:
    """Assemble the HTTP request for ``tool`` invoked with ``arguments``.

    Path params are substituted into the templated path; query/header/cookie
    params and body fields are routed by the tool's ``param_locations``.

    ``auth`` (optional) supports:
      {"type": "bearer", "token": "..."}                 -> Authorization header
      {"type": "api_key", "name": "X-API-Key", "value": "...", "in": "header"|"query"}
    """
    arguments = arguments or {}
    path = tool.path
    query: dict = {}
    headers: dict = {}
    cookies: list[str] = []
    body: dict = {}

    for key, value in arguments.items():
        loc = tool.param_locations.get(key, "body" if tool.has_body else "query")
        if loc == "path":
            path = path.replace("{%s}" % key, _to_str(value))
        elif loc == "query":
            query[key] = value
        elif loc == "header":
            headers[key] = _to_str(value)
        elif loc == "cookie":
            cookies.append(f"{key}={_to_str(value)}")
        else:  # body
            body[key] = value

    if cookies:
        headers["Cookie"] = "; ".join(cookies)

    _apply_auth(headers, query, auth)

    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    json_body = body if (body and tool.method not in ("GET", "HEAD")) else None

    return UpstreamRequest(
        method=tool.method,
        url=url,
        params=query,
        headers=headers,
        json_body=json_body,
    )


def _apply_auth(headers: dict, query: dict, auth: Optional[dict]) -> None:
    if not auth:
        return
    atype = auth.get("type")
    if atype == "bearer" and auth.get("token"):
        headers["Authorization"] = f"Bearer {auth['token']}"
    elif atype == "api_key" and auth.get("value"):
        where = auth.get("in", "header")
        name = auth.get("name", "X-API-Key")
        if where == "query":
            query[name] = auth["value"]
        else:
            headers[name] = auth["value"]


def _to_str(value) -> str:
    return value if isinstance(value, str) else str(value)


async def execute(req: UpstreamRequest, *, timeout: float = 30.0) -> dict:
    """Send the request and return {status, body}. Network — not unit tested."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.request(
            req.method, req.url,
            params=req.params or None,
            headers=req.headers or None,
            json=req.json_body,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = resp.text
        return {"status": resp.status_code, "body": payload}
