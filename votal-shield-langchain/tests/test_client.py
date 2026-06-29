from unittest.mock import Mock, patch

import pytest

from votal_shield_langchain import ShieldClient, ShieldContext
from votal_shield_langchain.errors import ShieldAuthorizationError


def test_check_tool_allows_when_shield_allows() -> None:
    client = ShieldClient(base_url="http://shield.test", api_key="test-key")
    context = ShieldContext(agent_key="support-bot")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"allowed": True}

    with patch("requests.post", return_value=mock_response) as mock_post:
        result = client.check_tool(
            context=context,
            tool_name="email_send",
            tool_params={"to": "ops@bank.ae"},
        )

    assert result == {"allowed": True}
    mock_post.assert_called_once()


def test_check_tool_raises_when_shield_blocks() -> None:
    client = ShieldClient(base_url="http://shield.test", api_key="test-key")
    context = ShieldContext(agent_key="support-bot")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "allowed": False,
        "reason": "Tool not allowed",
    }

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(ShieldAuthorizationError):
            client.check_tool(
                context=context,
                tool_name="database_delete",
                tool_params={},
            )