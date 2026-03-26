"""Tests for RegexPatternGuardrail."""

import pytest
from unittest.mock import patch

from config.schema import GuardrailConfig, ShieldConfig


@pytest.fixture
def regex_guard(mock_config):
    """Create a RegexPatternGuardrail with mock config."""
    from guardrails.input.regex_pattern import RegexPatternGuardrail

    return RegexPatternGuardrail()


@pytest.mark.asyncio
async def test_pattern_matched_block(regex_guard):
    """Test that an SSN pattern triggers a block."""
    result = await regex_guard.check("My SSN is 123-45-6789")
    assert not result.passed
    assert result.action == "block"
    assert result.details["matched_patterns"][0]["description"] == "SSN pattern"


@pytest.mark.asyncio
async def test_pattern_matched_warn():
    """Test that a warn-level pattern match passes but warns."""
    cfg = ShieldConfig(
        guardrails={
            "regex_pattern": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "patterns": [
                        {
                            "pattern": r"password\s*=\s*\S+",
                            "description": "Password in text",
                            "action": "warn",
                        },
                    ],
                },
            ),
        }
    )
    with patch("config.schema.config", cfg):
        from guardrails.input.regex_pattern import RegexPatternGuardrail

        guard = RegexPatternGuardrail()
        result = await guard.check("My password= secret123")
        assert result.passed  # warn does not block
        assert result.action == "warn"


@pytest.mark.asyncio
async def test_no_match(regex_guard):
    """Test that clean input passes with no matches."""
    result = await regex_guard.check("Hello, how are you?")
    assert result.passed
    assert result.action == "pass"
    assert "No regex patterns matched" in result.message
