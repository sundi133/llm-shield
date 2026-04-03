"""Guard against context window manipulation and overflow attacks."""

import hashlib
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class ContextWindowGuardrailsGuardrail(BaseGuardrail):
    name = "context_window_guardrails"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        messages = ctx.get("messages", [])
        total_tokens = ctx.get("total_tokens", 0)
        max_context = ctx.get("max_context_tokens", 0)
        system_prompt_hash = ctx.get("system_prompt_hash", "")
        session_id = ctx.get("session_id", "")

        issues = []

        # Context usage check
        if total_tokens and max_context:
            max_pct = self.settings.get("max_context_usage_pct", 90)
            usage_pct = (total_tokens / max_context) * 100
            if usage_pct > max_pct:
                issues.append(f"Context {usage_pct:.0f}% full (limit: {max_pct}%)")

        # Single message size check
        if messages and max_context:
            max_msg_pct = self.settings.get("max_single_message_pct", 50)
            for i, msg in enumerate(messages):
                msg_tokens = len(msg.get("content", "")) // 4  # rough estimate
                if max_context and (msg_tokens / max_context) * 100 > max_msg_pct:
                    issues.append(f"Message {i} is {msg_tokens} tokens ({msg_tokens/max_context*100:.0f}% of context)")

        # Turn count check
        if messages:
            max_turns = self.settings.get("max_turns", 100)
            if len(messages) > max_turns:
                issues.append(f"Turn count {len(messages)} exceeds max {max_turns}")

        # Repetition detection
        if messages and self.settings.get("detect_repetition", True):
            threshold = self.settings.get("repetition_threshold", 0.8)
            contents = [m.get("content", "") for m in messages[-10:]]
            if len(contents) >= 3:
                unique = len(set(contents))
                ratio = unique / len(contents)
                if ratio < (1 - threshold):
                    issues.append(f"High content repetition: {len(contents) - unique}/{len(contents)} duplicate messages")

        # System prompt integrity check
        if system_prompt_hash and messages and self.settings.get("verify_system_prompt", True):
            system_msgs = [m for m in messages if m.get("role") == "system"]
            if system_msgs:
                current_hash = hashlib.sha256(system_msgs[0].get("content", "").encode()).hexdigest()[:16]
                if current_hash != system_prompt_hash:
                    issues.append("System prompt integrity check failed — content has been modified")

        # Token growth rate tracking
        if session_id and total_tokens:
            history_key = f"ctx_window:{session_id}:tokens"
            history = agentic_state.get(history_key) or []
            history.append(total_tokens)
            history = history[-10:]
            agentic_state.set(history_key, history)

            if len(history) >= 3:
                max_growth = self.settings.get("max_tokens_per_turn_growth", 2.0)
                prev = history[-2]
                if prev > 0 and total_tokens / prev > max_growth:
                    issues.append(f"Token growth {total_tokens/prev:.1f}x exceeds {max_growth}x threshold")

        if issues:
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Context window issues: {'; '.join(issues)}",
                details={"issues": issues})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="Context window checks passed")
