import asyncio
from datetime import datetime
from typing import Optional

from core.models import GuardrailResult, PipelineResult
from guardrails.base import BaseGuardrail
from guardrails.registry import get_by_stage, get_by_tier


async def _run_guardrail(
    guardrail: BaseGuardrail, content: str, context: Optional[dict] = None
) -> GuardrailResult:
    """Run a single guardrail, catching exceptions gracefully."""
    start = datetime.now()
    try:
        result = await guardrail.check(content, context)
        return result
    except Exception as e:
        elapsed = (datetime.now() - start).total_seconds() * 1000
        return GuardrailResult(
            passed=False,
            action="log",
            guardrail_name=guardrail.name,
            message=f"Guardrail error: {str(e)}",
            details={"error": str(e)},
            latency_ms=round(elapsed, 2),
        )


async def _run_tier(
    guardrails: list[BaseGuardrail],
    content: str,
    context: Optional[dict] = None,
) -> list[GuardrailResult]:
    """Run all guardrails in a tier in parallel."""
    if not guardrails:
        return []
    tasks = [_run_guardrail(g, content, context) for g in guardrails]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)


def _has_block(results: list[GuardrailResult]) -> bool:
    """Check if any result is a block action."""
    return any(not r.passed and r.action == "block" for r in results)


async def run_pipeline(
    guardrails: list[BaseGuardrail],
    content: str,
    context: Optional[dict] = None,
) -> PipelineResult:
    """Run the three-tier guardrail pipeline with early exit.

    1. Run all fast-tier guardrails in parallel (CPU-only, <1ms).
    2. If any fast-tier guardrail blocks, return immediately.
    3. Run all medium-tier guardrails in parallel (small LLM, ~100-150ms).
    4. If any medium-tier guardrail blocks, return immediately.
    5. Run all slow-tier guardrails in parallel (large LLM, ~500-700ms).
    6. Return the combined PipelineResult.
    """
    start = datetime.now()
    all_results: list[GuardrailResult] = []

    # Filter to only enabled guardrails
    enabled = [g for g in guardrails if g.enabled]

    fast_guardrails = [g for g in enabled if g.tier == "fast"]
    medium_guardrails = [g for g in enabled if g.tier == "medium"]
    slow_guardrails = [g for g in enabled if g.tier == "slow"]

    # Tier 1: Fast (CPU-only)
    fast_results = await _run_tier(fast_guardrails, content, context)
    all_results.extend(fast_results)

    if _has_block(fast_results):
        total_ms = (datetime.now() - start).total_seconds() * 1000
        return PipelineResult(
            allowed=False,
            results=all_results,
            total_latency_ms=round(total_ms, 2),
        )

    # Tier 2: Medium (small LLM — 1.7B)
    medium_results = await _run_tier(medium_guardrails, content, context)
    all_results.extend(medium_results)

    if _has_block(medium_results):
        total_ms = (datetime.now() - start).total_seconds() * 1000
        return PipelineResult(
            allowed=False,
            results=all_results,
            total_latency_ms=round(total_ms, 2),
        )

    # Tier 3: Slow (large LLM — 8B)
    slow_results = await _run_tier(slow_guardrails, content, context)
    all_results.extend(slow_results)

    # Determine final allowed status
    allowed = not _has_block(all_results)
    total_ms = (datetime.now() - start).total_seconds() * 1000

    return PipelineResult(
        allowed=allowed,
        results=all_results,
        total_latency_ms=round(total_ms, 2),
    )


async def run_input_pipeline(
    content: str,
    context: Optional[dict] = None,
) -> PipelineResult:
    """Run the guardrail pipeline for input content."""
    input_guardrails = get_by_stage("input")
    return await run_pipeline(input_guardrails, content, context)


async def run_output_pipeline(
    content: str,
    context: Optional[dict] = None,
) -> PipelineResult:
    """Run the guardrail pipeline for output content."""
    output_guardrails = get_by_stage("output")
    return await run_pipeline(output_guardrails, content, context)
