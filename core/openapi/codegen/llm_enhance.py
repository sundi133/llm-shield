"""LLM-assisted enhancement for codegen.

LLMs are unreliable at emitting whole servers but good at writing clear,
human-readable tool descriptions from terse/empty OpenAPI metadata. This pass
fills in weak descriptions and leaves the deterministic structure untouched. It
always degrades gracefully: any LLM error keeps the original description.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable

from core.openapi.tool_mapper import ToolSpec

logger = logging.getLogger(__name__)

_MIN_GOOD_LEN = 12  # below this, a description is considered weak

_SYSTEM = (
    "You write concise, one-sentence tool descriptions for an AI agent. "
    "Given a tool's name, HTTP method and path, return a clear description of "
    "what it does and when to use it. Reply with the sentence only — no quotes, "
    "no preamble."
)


def _needs_description(t: ToolSpec) -> bool:
    return len((t.description or "").strip()) < _MIN_GOOD_LEN


async def enhance_tool_descriptions(
    tools: Iterable[ToolSpec],
    *,
    model: str | None = None,
) -> list[ToolSpec]:
    """Return the tools with weak descriptions improved by the LLM.

    Tools that already have a good description are left as-is. On any LLM error
    the original description is kept (deterministic fallback), so codegen never
    depends on the LLM succeeding.
    """
    tools = list(tools)
    try:
        from core.llm_backend import async_llm_call
    except Exception as e:  # pragma: no cover - import guard
        logger.debug(f"LLM unavailable, skipping enhancement: {e}")
        return tools

    for t in tools:
        if not _needs_description(t):
            continue
        prompt = (
            f"Tool name: {t.name}\n"
            f"HTTP: {t.method} {t.path}\n"
            f"Parameters: {json.dumps(list((t.input_schema or {}).get('properties', {}).keys()))}\n"
            f"Write the description."
        )
        try:
            resp = await async_llm_call(
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=60,
                temperature=0,
                guardrail_name="codegen_describe",
            )
            text = (resp.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            if text:
                t.description = text.strip().strip('"')
        except Exception as e:
            logger.debug(f"description enhancement failed for {t.name}: {e}")
            # keep original — deterministic fallback
    return tools
