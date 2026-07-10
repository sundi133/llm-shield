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


def test_redos_detector_flags_nested_quantifiers():
    """Exponential-backtracking antipatterns are detected (CWE-1333)."""
    from guardrails.input.regex_pattern import _has_nested_quantifier
    for evil in [r"(a+)+$", r"(a*)*", r"(a+)*", r"(.*)+", r"([a-z]+)*", r"(\d+)+"]:
        assert _has_nested_quantifier(evil) is True, evil


def test_redos_detector_allows_safe_patterns():
    """Common safe patterns must NOT be rejected (no false positives on the
    real-world examples the portal ships)."""
    from guardrails.input.regex_pattern import _has_nested_quantifier
    for safe in [
        r"\b\d{3}-\d{2}-\d{4}\b",         # SSN
        r"(abc)+",                          # quantified group, no inner quantifier
        r"password\s*[:=]\s*\S+",           # secret-in-text
        r"api[_-]?key",                     # optional char
        r"\b\d{16}\b",                      # card number
        r"(foo|bar|baz)",                   # alternation, unquantified group
        r"a+b+c+",                          # sequential quantifiers, no nesting
    ]:
        assert _has_nested_quantifier(safe) is False, safe


@pytest.mark.asyncio
async def test_redos_pattern_is_skipped_not_run(mock_config):
    """A catastrophic-backtracking tenant pattern is rejected at compile time
    and never executed, so a crafted payload can't hang the worker. With the
    only pattern skipped, the check returns pass (fail-open for that pattern)
    — and returns effectively instantly rather than backtracking."""
    from guardrails.base import _request_configs
    from guardrails.input.regex_pattern import RegexPatternGuardrail

    guard = RegexPatternGuardrail()
    evil_cfg = {
        "regex_pattern": {
            "enabled": True,
            "action": "block",
            "settings": {
                "patterns": [
                    {"pattern": r"(a+)+$", "description": "catastrophic", "action": "block"}
                ]
            },
        }
    }
    # This payload would take exponential time against (a+)+$ if it ran.
    payload = "a" * 40 + "!"

    token = _request_configs.set(evil_cfg)
    try:
        result = await guard.check(payload)
    finally:
        _request_configs.reset(token)

    # Pattern skipped -> nothing matched -> pass (and no hang).
    assert result.passed is True


@pytest.mark.asyncio
async def test_scan_length_is_capped(mock_config, monkeypatch):
    """Only the first _MAX_SCAN_CHARS of content are scanned (bounds worst-case
    match cost on huge inputs)."""
    import guardrails.input.regex_pattern as rp
    from guardrails.base import _request_configs
    from guardrails.input.regex_pattern import RegexPatternGuardrail

    monkeypatch.setattr(rp, "_MAX_SCAN_CHARS", 10)
    guard = RegexPatternGuardrail()
    cfg = {
        "regex_pattern": {
            "enabled": True,
            "action": "block",
            "settings": {"patterns": [{"pattern": "SECRET", "action": "block"}]},
        }
    }
    # "SECRET" sits past the 10-char cap, so it must NOT be found.
    content = ("x" * 20) + "SECRET"
    token = _request_configs.set(cfg)
    try:
        result = await guard.check(content)
    finally:
        _request_configs.reset(token)
    assert result.passed is True
