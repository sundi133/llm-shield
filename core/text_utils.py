"""Shared text utilities for guardrails — token estimation and chunking."""

import os
from typing import Optional

CHARS_PER_TOKEN = 3.5

# vLLM max-model-len = 8196; leave headroom for system prompt + output tokens
DEFAULT_SLOT_CONTEXT = int(os.getenv("SHIELD_CHUNK_MAX_TOKENS", "4096"))

# Target max number of chunks per guardrail call (chunks grow to fit)
MAX_CHUNKS_TARGET = int(os.getenv("SHIELD_MAX_CHUNKS", "4"))

# vLLM max-model-len — caps the maximum chunk size so it fits in the model context
MAX_MODEL_LEN = int(os.getenv("SHIELD_MAX_MODEL_LEN", "8196"))


def estimate_tokens(text: str) -> int:
    """Quick token count estimate without a tokenizer (~3.5 chars/token)."""
    return int(len(text) / CHARS_PER_TOKEN)


def adaptive_chunk_budget(content_tokens: int, base_budget: int) -> int:
    """Scale chunk size up so total chunks stays within MAX_CHUNKS_TARGET,
    but never exceed what the guard model can handle (MAX_MODEL_LEN).

    The max usable budget is MAX_MODEL_LEN minus headroom for system prompt
    and output tokens (~800 tokens reserved).

    Examples with MAX_CHUNKS_TARGET=4, MAX_MODEL_LEN=8196:
      4K input   → 1 chunk at 4K   (fits in 1 call)
      16K input  → 4 chunks at 4K  (already within target)
      64K input  → 9 chunks at 7K  (capped by model, not 4 chunks at 16K)
      120K input → 17 chunks at 7K (capped by model, not 4 chunks at 30K)
    """
    max_budget = MAX_MODEL_LEN - 800  # reserve for system prompt + output
    if content_tokens <= base_budget:
        return base_budget
    chunks_needed = (content_tokens + base_budget - 1) // base_budget
    if chunks_needed <= MAX_CHUNKS_TARGET:
        return base_budget
    ideal = (content_tokens + MAX_CHUNKS_TARGET - 1) // MAX_CHUNKS_TARGET
    return min(ideal, max_budget)


def chunk_text(text: str, max_tokens: int) -> list[str]:
    """Split text into overlapping chunks that fit within max_tokens.

    Splits at sentence boundaries when possible, with 10% overlap
    to preserve context across chunk boundaries.
    """
    max_chars = int(max_tokens * CHARS_PER_TOKEN)
    overlap_chars = max(100, max_chars // 10)

    if len(text) <= max_chars:
        return [text]

    chunks = []
    pos = 0
    while pos < len(text):
        end = pos + max_chars
        if end >= len(text):
            chunks.append(text[pos:])
            break

        split_at = end
        for sep in (". ", ".\n", "! ", "? ", "\n\n", "\n"):
            last_sep = text.rfind(sep, pos + max_chars // 2, end)
            if last_sep != -1:
                split_at = last_sep + len(sep)
                break
        else:
            last_space = text.rfind(" ", pos + max_chars // 2, end)
            if last_space != -1:
                split_at = last_space + 1

        chunks.append(text[pos:split_at])
        pos = max(split_at - overlap_chars, pos + 1)

    return chunks


def build_history_messages(
    context: Optional[dict],
    max_turns: int = 6,
) -> list[dict]:
    """Extract the last N conversation turns from context for multi-turn awareness.

    Returns a list of {"role": ..., "content": ...} dicts suitable for
    appending to an LLM messages list before the current user message.
    """
    if not context:
        return []
    conversation_history = context.get("conversation_history", [])
    if not conversation_history:
        return []
    prior_turns = conversation_history[:-1][-max_turns:]
    return [
        {"role": turn.get("role", "user"), "content": turn.get("content", "")}
        for turn in prior_turns
    ]


def trim_history_to_budget(
    history_messages: list[dict],
    available_tokens: int,
    max_history_fraction: float = 0.33,
) -> tuple[list[dict], int]:
    """Trim oldest history messages so they don't exceed a fraction of the budget.

    Returns (trimmed_history, history_token_count).
    """
    max_history_tokens = int(available_tokens * max_history_fraction)
    history_tokens = sum(estimate_tokens(m["content"]) for m in history_messages)
    while history_messages and history_tokens > max_history_tokens:
        removed = history_messages.pop(0)
        history_tokens -= estimate_tokens(removed["content"])
    return history_messages, history_tokens


# Multi-turn awareness for the custom-policy guardrails (input + output).
# Shared so both stages behave identically. Off by default per policy; the env
# var is the operator-level kill switch.
_CUSTOM_POLICY_DEFAULT_TURNS = 6
_CUSTOM_POLICY_SLOT_CONTEXT = 4096   # 8196 max-model-len / 2, matches adversarial
_CUSTOM_POLICY_OUTPUT_TOKENS = 200   # custom_policy max_tokens
_CUSTOM_POLICY_OVERHEAD_TOKENS = 64  # chat template / role framing slack


def custom_policy_history_turns() -> int:
    """Max prior turns to feed opted-in custom policies.

    Reads SHIELD_CUSTOM_POLICY_HISTORY_TURNS (default 6). Returning 0 is the
    operator kill switch: history injection is skipped even for policies that
    set multi_turn=true. Invalid values fall back to the default.
    """
    raw = os.getenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS")
    if raw is None:
        return _CUSTOM_POLICY_DEFAULT_TURNS
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return _CUSTOM_POLICY_DEFAULT_TURNS


def build_policy_messages(
    eval_prompt: str,
    context: Optional[dict],
    max_turns: int,
    slot_context: int = _CUSTOM_POLICY_SLOT_CONTEXT,
) -> list[dict]:
    """Build the LLM messages for a custom-policy evaluation.

    With max_turns <= 0 or no prior turns, returns the single-message prompt
    unchanged (byte-identical to the pre-multi-turn path). Otherwise prepends the
    budget-trimmed prior turns before the evaluation prompt, so the model judges
    the current message in conversational context. Same shaping adversarial uses.
    """
    base = [{"role": "user", "content": eval_prompt}]
    if max_turns <= 0:
        return base
    history = build_history_messages(context, max_turns=max_turns)
    if not history:
        return base
    reserved = (
        estimate_tokens(eval_prompt)
        + _CUSTOM_POLICY_OUTPUT_TOKENS
        + _CUSTOM_POLICY_OVERHEAD_TOKENS
    )
    available = max(0, slot_context - reserved)
    history, _ = trim_history_to_budget(history, available)
    return history + base
