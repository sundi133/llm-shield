"""Tests for the two-tier guardrail pipeline."""

import pytest
from typing import Optional

from core.models import GuardrailResult
from core.pipeline import run_pipeline
from guardrails.base import BaseGuardrail


class MockFastPass(BaseGuardrail):
    name = "mock_fast_pass"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name)

    @property
    def enabled(self) -> bool:
        return True


class MockFastBlock(BaseGuardrail):
    name = "mock_fast_block"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        return GuardrailResult(
            passed=False,
            action="block",
            guardrail_name=self.name,
            message="Blocked by fast tier",
        )

    @property
    def enabled(self) -> bool:
        return True


class MockFastWarn(BaseGuardrail):
    name = "mock_fast_warn"
    tier = "fast"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        return GuardrailResult(
            passed=True,
            action="warn",
            guardrail_name=self.name,
            message="Warning from fast tier",
        )

    @property
    def enabled(self) -> bool:
        return True


class MockSlowPass(BaseGuardrail):
    name = "mock_slow_pass"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name)

    @property
    def enabled(self) -> bool:
        return True


class MockSlowBlock(BaseGuardrail):
    name = "mock_slow_block"
    tier = "slow"
    stage = "input"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        return GuardrailResult(
            passed=False,
            action="block",
            guardrail_name=self.name,
            message="Blocked by slow tier",
        )

    @property
    def enabled(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_all_pass():
    """Test that when all guardrails pass, pipeline allows."""
    guardrails = [MockFastPass(), MockSlowPass()]
    result = await run_pipeline(guardrails, "hello")
    assert result.allowed
    assert len(result.results) == 2


@pytest.mark.asyncio
async def test_fast_tier_blocks_skips_slow():
    """Test that a fast-tier block prevents slow tier from running."""
    guardrails = [MockFastBlock(), MockSlowPass()]
    result = await run_pipeline(guardrails, "hello")
    assert not result.allowed
    # Only fast tier results should be present (slow tier was skipped)
    assert len(result.results) == 1
    assert result.results[0].guardrail_name == "mock_fast_block"


@pytest.mark.asyncio
async def test_slow_tier_blocks():
    """Test that a slow-tier block causes pipeline to deny."""
    guardrails = [MockFastPass(), MockSlowBlock()]
    result = await run_pipeline(guardrails, "hello")
    assert not result.allowed
    assert len(result.results) == 2


@pytest.mark.asyncio
async def test_warn_does_not_block():
    """Test that a warn action does not block the pipeline."""
    guardrails = [MockFastWarn(), MockSlowPass()]
    result = await run_pipeline(guardrails, "hello")
    assert result.allowed
    assert len(result.results) == 2
    warn_result = [r for r in result.results if r.guardrail_name == "mock_fast_warn"][0]
    assert warn_result.action == "warn"
