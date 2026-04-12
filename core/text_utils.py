"""Shared text utilities for guardrails — token estimation and chunking."""

from typing import Optional

CHARS_PER_TOKEN = 3.5

# vLLM max-model-len = 8196; leave headroom for system prompt + output tokens
DEFAULT_SLOT_CONTEXT = 4096


def estimate_tokens(text: str) -> int:
    """Quick token count estimate without a tokenizer (~3.5 chars/token)."""
    return int(len(text) / CHARS_PER_TOKEN)


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
