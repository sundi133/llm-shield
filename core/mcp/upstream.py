"""Live upstream MCP client adapter for the proxy.

``MCPUpstream`` wraps a connected MCP ClientSession and exposes the minimal
surface ``MCPProxy`` needs (``list_tools`` / ``call_tool``). The adapter logic
(result normalization, lifecycle) is injectable and unit-tested with a fake
session; ``connect_upstream`` builds the real transport + session via the
official ``mcp`` SDK and is verified against a live upstream server.

Namespace note: this repository contains a local ``mcp/`` directory which can
shadow the pip-installed ``mcp`` SDK depending on sys.path order. If the SDK
import fails, ``connect_upstream`` raises a clear, actionable error.
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any, Optional


class MCPUpstream:
    """Adapter over a connected MCP ClientSession (or a compatible fake)."""

    def __init__(self, session: Any, *, exit_stack: Optional[AsyncExitStack] = None):
        self._session = session
        self._stack = exit_stack

    async def list_tools(self) -> list[dict]:
        res = await self._session.list_tools()
        tools = getattr(res, "tools", res)  # SDK returns ListToolsResult; fakes may return a list
        out: list[dict] = []
        for t in tools:
            out.append({
                "name": getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else None),
                "description": _attr(t, "description", "") or "",
                "inputSchema": _attr(t, "inputSchema", None)
                or _attr(t, "input_schema", None) or {},
            })
        return out

    async def call_tool(self, name: str, arguments: dict) -> Any:
        res = await self._session.call_tool(name, arguments or {})
        return _normalize_result(res)

    # ── resources ────────────────────────────────────────────────────

    async def list_resources(self) -> list[dict]:
        res = await self._session.list_resources()
        items = _attr(res, "resources", res)
        return [{
            "uri": str(_attr(r, "uri", "")),
            "name": _attr(r, "name", "") or "",
            "description": _attr(r, "description", "") or "",
            "mimeType": _attr(r, "mimeType", None) or _attr(r, "mime_type", None),
        } for r in (items or [])]

    async def read_resource(self, uri: str) -> dict:
        res = await self._session.read_resource(uri)
        contents = _attr(res, "contents", res)
        out: list[dict] = []
        for c in (contents or []):
            block = {
                "uri": str(_attr(c, "uri", uri)),
                "mimeType": _attr(c, "mimeType", None) or _attr(c, "mime_type", None),
            }
            text = _attr(c, "text", None)
            if text is not None:
                block["text"] = text
            else:
                blob = _attr(c, "blob", None)
                if blob is not None:
                    block["blob"] = blob
            out.append(block)
        return {"contents": out}

    async def list_resource_templates(self) -> list[dict]:
        res = await self._session.list_resource_templates()
        items = _attr(res, "resourceTemplates", None) or _attr(res, "resource_templates", res)
        return [{
            "uriTemplate": _attr(t, "uriTemplate", None) or _attr(t, "uri_template", "") or "",
            "name": _attr(t, "name", "") or "",
            "description": _attr(t, "description", "") or "",
        } for t in (items or [])]

    # ── prompts ──────────────────────────────────────────────────────

    async def list_prompts(self) -> list[dict]:
        res = await self._session.list_prompts()
        items = _attr(res, "prompts", res)
        out: list[dict] = []
        for p in (items or []):
            # SDK PromptArgument objects aren't JSON-serializable — normalize to dicts.
            args = [{
                "name": _attr(a, "name", "") or "",
                "description": _attr(a, "description", "") or "",
                "required": bool(_attr(a, "required", False)),
            } for a in (_attr(p, "arguments", None) or [])]
            out.append({
                "name": _attr(p, "name", "") or "",
                "description": _attr(p, "description", "") or "",
                "arguments": args,
            })
        return out

    async def get_prompt(self, name: str, arguments: Optional[dict] = None) -> dict:
        res = await self._session.get_prompt(name, arguments or {})
        out_msgs: list[dict] = []
        for m in (_attr(res, "messages", []) or []):
            content = _attr(m, "content", None)
            text = _attr(content, "text", None) if content is not None else None
            out_msgs.append({
                "role": _attr(m, "role", "") or "",
                "content": text if text is not None else (
                    content if isinstance(content, (str, dict, list)) else str(content)),
            })
        return {"description": _attr(res, "description", "") or "", "messages": out_msgs}

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None


def _attr(obj: Any, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _normalize_result(res: Any) -> Any:
    """Flatten an MCP CallToolResult's content blocks to text.

    Falls back to returning the raw object if it has no ``content`` (so a fake
    that returns a plain value still works).
    """
    content = _attr(res, "content", None)
    if content is None:
        return res
    parts: list[str] = []
    for block in content:
        text = _attr(block, "text", None)
        if text is not None:
            parts.append(text)
            continue
        data = _attr(block, "data", None)
        parts.append(data if isinstance(data, str) else str(block))
    return "\n".join(parts) if parts else ""


_SDK_HINT = (
    "The official `mcp` client SDK is unavailable. Run `pip install mcp`, and "
    "ensure it is not shadowed by this repository's local `mcp/` directory "
    "(import `mcp.client` from a working directory where the installed package "
    "resolves first, or rename the local package)."
)


async def connect_upstream(config: dict) -> MCPUpstream:
    """Connect to an upstream MCP server and return an MCPUpstream.

    config:
      {"transport": "stdio", "command": "python", "args": [...], "env": {...}}
      {"transport": "sse", "url": "https://...", "headers": {...}}
      {"transport": "http", "url": "https://...", "headers": {...}}   # streamable HTTP
    """
    transport = (config.get("transport") or "stdio").lower()
    stack = AsyncExitStack()
    try:
        if transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(
                command=config["command"],
                args=config.get("args", []),
                env=config.get("env"),
            )
            read, write = await stack.enter_async_context(stdio_client(params))
        elif transport == "sse":
            from mcp.client.sse import sse_client
            read, write = await stack.enter_async_context(
                sse_client(config["url"], headers=config.get("headers"))
            )
        elif transport in ("http", "streamable_http", "streamable-http"):
            from mcp.client.streamable_http import streamablehttp_client
            res = await stack.enter_async_context(
                streamablehttp_client(config["url"], headers=config.get("headers"))
            )
            read, write = res[0], res[1]  # (read, write, get_session_id)
        else:
            raise ValueError(f"unknown transport: {transport!r}")

        from mcp import ClientSession
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return MCPUpstream(session, exit_stack=stack)

    except ImportError as e:
        await stack.aclose()
        raise RuntimeError(_SDK_HINT) from e
    except Exception:
        await stack.aclose()
        raise
