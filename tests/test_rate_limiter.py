"""Tests for RateLimiterGuardrail."""

import pytest
from unittest.mock import patch

from config.schema import GuardrailConfig, ShieldConfig
from storage.state_store import StateStore

# conftest's mock config asks for 3 per 60 s; the floor makes it 1,000.
LIMIT = 1000


@pytest.fixture
def rate_guard(mock_config):
    """A RateLimiterGuardrail with mock config (max_requests=3 per 60 s,
    which the 1,000-per-minute floor raises to LIMIT)."""
    # Use a fresh state store to avoid cross-test contamination
    fresh_store = StateStore()
    with patch("guardrails.input.rate_limiter._state_store", fresh_store):
        from guardrails.input.rate_limiter import RateLimiterGuardrail

        guard = RateLimiterGuardrail()
        guard._store = fresh_store
        return guard


@pytest.mark.asyncio
async def test_under_limit_passes(rate_guard):
    """Test that requests under the limit pass."""
    context = {"client_id": "test-client-pass"}
    result = await rate_guard.check("hello", context)
    assert result.passed
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_exceeding_limit_blocks(rate_guard):
    """Test that exceeding the rate limit blocks."""
    context = {"client_id": "test-client-block"}
    # Make LIMIT requests, then the next one should block
    for _ in range(LIMIT):
        result = await rate_guard.check("hello", context)
        assert result.passed

    result = await rate_guard.check("hello", context)
    assert not result.passed
    assert result.action == "block"
    assert "Rate limit exceeded" in result.message


@pytest.mark.asyncio
async def test_different_clients_tracked_separately(rate_guard):
    """Test that different client IDs have independent rate limit counters."""
    ctx_a = {"client_id": "client-a"}
    ctx_b = {"client_id": "client-b"}

    # Exhaust limit for client-a
    for _ in range(LIMIT):
        await rate_guard.check("hello", ctx_a)
    result_a = await rate_guard.check("hello", ctx_a)
    assert not result_a.passed

    # client-b should still be under the limit
    result_b = await rate_guard.check("hello", ctx_b)
    assert result_b.passed
