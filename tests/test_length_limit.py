"""Tests for LengthLimitGuardrail."""

import pytest
from unittest.mock import patch, MagicMock

from config.schema import GuardrailConfig, ShieldConfig


@pytest.fixture
def length_guard(mock_config):
    """Create a LengthLimitGuardrail with mock config (max_chars=100, max_tokens=50)."""
    from guardrails.input.length_limit import LengthLimitGuardrail
    return LengthLimitGuardrail()


@pytest.mark.asyncio
async def test_within_limits(length_guard):
    """Test that short input passes the length check."""
    result = await length_guard.check("Hello world")
    assert result.passed
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_exceeds_char_limit(length_guard):
    """Test that input exceeding max_chars is blocked."""
    long_text = "a" * 150  # Exceeds 100 char limit
    result = await length_guard.check(long_text)
    assert not result.passed
    assert result.action == "block"
    assert "character limit" in result.message


@pytest.mark.asyncio
async def test_exceeds_token_limit():
    """Test that input exceeding max_tokens is blocked (mock tiktoken)."""
    cfg = ShieldConfig(
        guardrails={
            "length_limit": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "max_chars": 10000,
                    "max_tokens": 5,
                    "encoding": "cl100k_base",
                },
            ),
        }
    )

    with patch("config.schema.config", cfg):
        from guardrails.input.length_limit import LengthLimitGuardrail
        guard = LengthLimitGuardrail()

        # If tiktoken is available, it will encode and count tokens
        # The text "one two three four five six seven" should exceed 5 tokens
        result = await guard.check("one two three four five six seven eight nine ten")
        if guard._max_tokens is not None:
            # tiktoken was available
            assert not result.passed
            assert result.action == "block"
            assert "token limit" in result.message
        else:
            # tiktoken not installed; token limit disabled, only char check runs
            assert result.passed
