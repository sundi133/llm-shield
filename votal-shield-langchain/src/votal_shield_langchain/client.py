"""HTTP client for Votal Shield APIs."""

from __future__ import annotations

from typing import Any

import requests

from votal_shield_langchain.context import ShieldContext
from votal_shield_langchain.errors import (
    ShieldAPIError,
    ShieldAuthenticationError,
    ShieldAuthorizationError,
)


class ShieldClient:
    """Client for communicating with Votal Shield backend APIs."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def check_tool(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_params: dict[str, Any],
        input_sources: list[str] | None = None,
    ) -> dict[str, Any]:
        """Ask Shield whether a tool call is allowed before execution."""

        payload = {
            "agent_key": context.agent_key,
            "tool_name": tool_name,
            "tool_params": tool_params,
            "session_id": context.session_id,
            "input_sources": input_sources or [],
        }

        response = self._post(
            path="/v1/shield/tool/check",
            context=context,
            json=payload,
        )

        allowed = bool(response.get("allowed", False))

        if not allowed:
            reason = (
                response.get("reason")
                or response.get("message")
                or "Tool call blocked by Shield."
            )
            raise ShieldAuthorizationError(reason)

        return response

    def report_tool_output(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_output: Any,
        tool_call_id: str,
    ) -> dict[str, Any]:
        """Send tool output to Shield for redaction, taint tracking, or auditing."""

        payload = {
            "tool_name": tool_name,
            "tool_output": str(tool_output),
            "session_id": context.session_id,
            "tool_call_id": tool_call_id,
        }

        return self._post(
            path="/v1/shield/tool/output",
            context=context,
            json=payload,
        )

    def _post(
        self,
        *,
        path: str,
        context: ShieldContext,
        json: dict[str, Any],
    ) -> dict[str, Any]:
        """Send a POST request to Shield and return parsed JSON."""

        url = f"{self.base_url}{path}"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            **context.to_headers(),
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json=json,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise ShieldAPIError(f"Could not reach Shield API: {exc}") from exc

        if response.status_code in {401, 403}:
            raise ShieldAuthenticationError("Shield authentication failed.")

        if response.status_code >= 400:
            raise ShieldAPIError(
                f"Shield API error {response.status_code}: {response.text}"
            )

        try:
            parsed = response.json()
        except ValueError as exc:
            raise ShieldAPIError("Shield returned invalid JSON.") from exc

        if not isinstance(parsed, dict):
            raise ShieldAPIError("Shield returned an unexpected response shape.")

        return parsed