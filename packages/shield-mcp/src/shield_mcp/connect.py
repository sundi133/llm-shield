"""Connect to an MCP server and pull its catalog (tools/resources/prompts).

Target grammar (per docs/spec-mcp-scanner.md):
    stdio:<command line>     e.g.  stdio:python my_server.py
    sse:<url>                e.g.  sse:https://host/sse
    http:<url>               e.g.  http:https://host/mcp   (streamable HTTP)
    https://... | http://... treated as http (streamable) when no prefix

Parsing is pure and unit-tested. The actual network fetch imports the `mcp`
SDK lazily so the pure layers (heuristics/report/parse) need no SDK installed.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from shield_mcp.catalog import Catalog


class ConnectError(Exception):
    """Raised when the target can't be reached or the MCP handshake fails."""


@dataclass
class Target:
    transport: str          # "stdio" | "sse" | "http"
    command: str = ""       # stdio: executable
    args: list = None       # stdio: argv tail
    url: str = ""           # sse/http

    def __post_init__(self):
        if self.args is None:
            self.args = []


def parse_target(spec: str) -> Target:
    """Parse a target string into a Target. Raises ValueError on bad input."""
    if not spec or not spec.strip():
        raise ValueError("empty target")
    spec = spec.strip()

    if spec.startswith("stdio:"):
        rest = spec[len("stdio:"):].strip()
        if not rest:
            raise ValueError("stdio target needs a command")
        parts = shlex.split(rest)
        return Target(transport="stdio", command=parts[0], args=parts[1:])

    if spec.startswith("sse:"):
        url = spec[len("sse:"):].strip()
        if not url:
            raise ValueError("sse target needs a url")
        return Target(transport="sse", url=url)

    if spec.startswith("http:") and "://" in spec[len("http:"):]:
        # http:https://... or http:http://... -> explicit http transport, real URL after prefix
        return Target(transport="http", url=spec[len("http:"):].strip())

    if spec.startswith(("http://", "https://")):
        return Target(transport="http", url=spec)

    raise ValueError(
        f"unrecognized target '{spec}'. Use stdio:<cmd>, sse:<url>, or http:<url>."
    )


def _normalize(items) -> list:
    """Turn mcp SDK pydantic models (or dicts) into plain dicts."""
    out = []
    for it in items or []:
        if hasattr(it, "model_dump"):
            out.append(it.model_dump(exclude_none=True))
        elif isinstance(it, dict):
            out.append(it)
        else:  # last-resort: pull known attrs
            out.append({k: getattr(it, k) for k in
                        ("name", "title", "description", "uri", "inputSchema", "arguments")
                        if getattr(it, k, None) is not None})
    return out


async def fetch_catalog(target: Target, *, timeout: float = 20.0) -> Catalog:
    """Connect and enumerate. Lazily imports the mcp SDK. Raises ConnectError."""
    try:
        from mcp import ClientSession
    except Exception as e:  # pragma: no cover - packaging guard
        raise ConnectError(f"mcp client SDK not installed: {e}") from e

    try:
        if target.transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(command=target.command, args=target.args)
            ctx = stdio_client(params)
        elif target.transport == "sse":
            from mcp.client.sse import sse_client
            ctx = sse_client(target.url)
        elif target.transport == "http":
            from mcp.client.streamable_http import streamablehttp_client
            ctx = streamablehttp_client(target.url)
        else:  # pragma: no cover - parse_target guards this
            raise ConnectError(f"unknown transport {target.transport}")

        async with ctx as streams:
            # stdio/sse yield (read, write); streamable_http yields a third element.
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await _safe_list(session.list_tools, "tools")
                resources = await _safe_list(session.list_resources, "resources")
                prompts = await _safe_list(session.list_prompts, "prompts")
        return Catalog(
            tools=_normalize(tools),
            resources=_normalize(resources),
            prompts=_normalize(prompts),
        )
    except ConnectError:
        raise
    except Exception as e:
        raise ConnectError(f"could not scan {target.transport} target: {e}") from e


async def _safe_list(list_fn, attr: str) -> list:
    """Call a list_* method; return [] if the server doesn't support that capability."""
    try:
        result = await list_fn()
    except Exception:
        return []
    return getattr(result, attr, None) or []
