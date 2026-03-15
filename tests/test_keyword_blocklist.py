"""Tests for KeywordBlocklistGuardrail."""

import pytest
from unittest.mock import patch

from config.schema import GuardrailConfig


@pytest.fixture
def blocklist_guard(mock_config):
    """Create a KeywordBlocklistGuardrail with mock config active."""
    from guardrails.input.keyword_blocklist import KeywordBlocklistGuardrail
    return KeywordBlocklistGuardrail()


@pytest.fixture
def empty_blocklist_guard():
    """Create a KeywordBlocklistGuardrail with no keywords configured."""
    from config.schema import ShieldConfig
    empty_config = ShieldConfig(
        guardrails={
            "keyword_blocklist": GuardrailConfig(
                enabled=True,
                action="block",
                settings={"keywords": []},
            ),
        }
    )
    with patch("config.schema.config", empty_config):
        from guardrails.input.keyword_blocklist import KeywordBlocklistGuardrail
        return KeywordBlocklistGuardrail()


@pytest.mark.asyncio
async def test_blocked_keyword_detected(blocklist_guard):
    """Test that a blocked keyword is detected and blocks the input."""
    result = await blocklist_guard.check("I want to hack into the system")
    assert not result.passed
    assert result.action == "block"
    assert "hack" in result.message


@pytest.mark.asyncio
async def test_no_keywords_matched(blocklist_guard):
    """Test that clean input passes the blocklist check."""
    result = await blocklist_guard.check("Hello, how are you today?")
    assert result.passed
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_case_insensitive_matching(blocklist_guard):
    """Test that keyword matching is case insensitive."""
    result = await blocklist_guard.check("HACK the planet")
    assert not result.passed
    assert result.action == "block"
    assert "hack" in result.details["matched_keywords"]


@pytest.mark.asyncio
async def test_no_keywords_configured(empty_blocklist_guard):
    """Test that with no keywords configured, everything passes."""
    result = await empty_blocklist_guard.check("hack exploit malware")
    assert result.passed
    assert result.action == "pass"
    assert "No keywords configured" in result.message
