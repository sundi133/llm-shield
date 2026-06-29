from typing import Any

from votal_shield_langchain import ShieldClient, ShieldContext, shield_tool


class FakeShieldClient(ShieldClient):
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.checked = False
        self.reported = False

    def check_tool(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_params: dict[str, Any],
        input_sources: list[str] | None = None,
    ) -> dict[str, Any]:
        self.checked = True

        if not self.allowed:
            from votal_shield_langchain.errors import ShieldAuthorizationError

            raise ShieldAuthorizationError("blocked")

        return {"allowed": True}

    def report_tool_output(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_output: Any,
        tool_call_id: str,
    ) -> dict[str, Any]:
        self.reported = True
        return {"sanitized_output": tool_output}


def test_shield_tool_runs_when_allowed() -> None:
    client = FakeShieldClient(allowed=True)
    context = ShieldContext(agent_key="support-bot")

    @shield_tool(client=client, context=context)
    def echo(message: str) -> str:
        """Echo a message."""
        return message

    result = echo.invoke({"message": "hello"})

    assert result == "hello"
    assert client.checked is True
    assert client.reported is True


def test_shield_tool_blocks_safely() -> None:
    client = FakeShieldClient(allowed=False)
    context = ShieldContext(agent_key="support-bot")

    @shield_tool(client=client, context=context)
    def dangerous_action() -> str:
        """Dangerous action."""
        return "should not run"

    result = dangerous_action.invoke({})

    assert result == "Action blocked by Votal Shield policy."
    assert client.checked is True
    assert client.reported is False