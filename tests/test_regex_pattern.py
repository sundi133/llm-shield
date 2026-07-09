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


@pytest.mark.asyncio
async def test_per_request_tenant_patterns_are_enforced(mock_config):
    """Regression: patterns from per-request tenant config (the contextvar
    routes_classify sets) must be enforced, not just whatever was compiled
    from the boot-time config. Previously __init__ froze the boot-time
    patterns forever, so tenant-added custom regexes were stored but
    silently never checked."""
    from guardrails.base import _request_configs
    from guardrails.input.regex_pattern import RegexPatternGuardrail

    guard = RegexPatternGuardrail()  # instantiated under boot-time mock_config

    tenant_cfg = {
        "regex_pattern": {
            "enabled": True,
            "action": "block",
            "settings": {
                "patterns": [
                    {
                        "pattern": "PROJECT-NIGHTHAWK",
                        "description": "internal codename",
                        "action": "block",
                    }
                ]
            },
        }
    }
    token = _request_configs.set(tenant_cfg)
    try:
        result = await guard.check("please review PROJECT-NIGHTHAWK before launch")
    finally:
        _request_configs.reset(token)

    assert not result.passed
    assert result.action == "block"
    assert result.details["matched_patterns"][0]["description"] == "internal codename"

    # And the boot-time SSN pattern (absent from the tenant config) must NOT
    # fire under the tenant's request config.
    token = _request_configs.set(tenant_cfg)
    try:
        result = await guard.check("My SSN is 123-45-6789")
    finally:
        _request_configs.reset(token)
    assert result.passed


@pytest.mark.asyncio
async def test_boot_config_still_enforced_outside_request(regex_guard):
    """Outside a request context the boot-time config still applies."""
    result = await regex_guard.check("My SSN is 123-45-6789")
    assert not result.passed
