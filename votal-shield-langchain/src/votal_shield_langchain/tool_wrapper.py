"""LangChain tool wrapper with Votal Shield enforcement."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any
from uuid import uuid4

from langchain_core.tools import StructuredTool

from votal_shield_langchain.client import ShieldClient
from votal_shield_langchain.context import ShieldContext
from votal_shield_langchain.errors import (
    ShieldAPIError,
    ShieldAuthorizationError,
    ShieldToolExecutionError,
)

_SAFE_BLOCKED_MESSAGE = "Action blocked by Votal Shield policy."
_SAFE_ERROR_MESSAGE = "Tool execution failed safely."


def shield_tool(
    *,
    client: ShieldClient,
    context: ShieldContext,
    name: str | None = None,
    description: str | None = None,
    fail_safe: bool = True,
) -> Callable[[Callable[..., Any]], StructuredTool]:
    """Decorate a Python function as a Shield-protected LangChain tool.

    Args:
        client: Shield API client.
        context: Runtime Shield context for the current agent/session.
        name: Optional public tool name shown to LangChain.
        description: Optional tool description shown to LangChain.
        fail_safe: If true, return safe messages instead of raising errors.

    Returns:
        A LangChain StructuredTool.
    """

    def decorator(func: Callable[..., Any]) -> StructuredTool:
        tool_name = name or func.__name__
        tool_description = description or func.__doc__ or f"Shield tool: {tool_name}"

        @wraps(func)
        def wrapped_tool(**kwargs: Any) -> Any:
            tool_call_id = str(uuid4())

            try:
                client.check_tool(
                    context=context,
                    tool_name=tool_name,
                    tool_params=kwargs,
                )
            except ShieldAuthorizationError:
                if fail_safe:
                    return _SAFE_BLOCKED_MESSAGE
                raise
            except ShieldAPIError:
                if fail_safe:
                    return _SAFE_ERROR_MESSAGE
                raise

            try:
                result = func(**kwargs)
            except Exception as exc:
                if fail_safe:
                    return _SAFE_ERROR_MESSAGE
                raise ShieldToolExecutionError(
                    f"Wrapped tool '{tool_name}' failed."
                ) from exc

            try:
                shield_response = client.report_tool_output(
                    context=context,
                    tool_name=tool_name,
                    tool_output=result,
                    tool_call_id=tool_call_id,
                )
            except ShieldAPIError:
                if fail_safe:
                    return result
                raise

            return shield_response.get("sanitized_output", result)

        return StructuredTool.from_function(
            func=wrapped_tool,
            name=tool_name,
            description=tool_description,
        )

    return decorator