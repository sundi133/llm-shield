"""Detect stuck agents — repeated tool calls, cycles, consecutive errors."""

import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from storage.state_store import agentic_state


class LoopDetectionGuardrail(BaseGuardrail):
    name = "loop_detection"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        session_id = ctx.get("session_id")
        tool_name = ctx.get("tool_name", "")
        if not session_id:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="Missing session_id, skipping")

        params_hash = ctx.get("tool_params_hash", "")
        is_error = ctx.get("error", False)
        history_len = self.settings.get("history_length", 20)
        repeat_threshold = self.settings.get("repeat_threshold", 3)
        max_errors = self.settings.get("max_consecutive_errors", 5)
        cooldown = self.settings.get("cooldown_seconds", 30)

        # Check cooldown
        cooldown_key = f"loop:{session_id}:cooldown"
        if agentic_state.get(cooldown_key):
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message="Agent in loop cooldown period")

        # Track consecutive errors
        error_key = f"loop:{session_id}:errors"
        if is_error:
            error_count = (agentic_state.get(error_key) or 0) + 1
            agentic_state.set(error_key, error_count)
            if error_count >= max_errors:
                agentic_state.set(cooldown_key, True, ttl=cooldown)
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Agent stuck: {error_count} consecutive errors",
                    details={"consecutive_errors": error_count})
        else:
            agentic_state.set(error_key, 0)

        # Track action history
        history_key = f"loop:{session_id}:history"
        history = agentic_state.get(history_key) or []
        entry = f"{tool_name}:{params_hash}"
        history.append(entry)
        history = history[-history_len:]
        agentic_state.set(history_key, history)

        # Check exact repetition
        recent = history[-repeat_threshold:]
        if len(recent) == repeat_threshold and len(set(recent)) == 1:
            agentic_state.set(cooldown_key, True, ttl=cooldown)
            return GuardrailResult(
                passed=False, action=self.configured_action, guardrail_name=self.name,
                message=f"Loop detected: '{tool_name}' called {repeat_threshold} times in a row",
                details={"repeated_action": entry, "count": repeat_threshold})

        # Check cycle patterns (A->B->A->B)
        cycle_max = self.settings.get("cycle_max_length", 5)
        for cycle_len in range(2, min(cycle_max + 1, len(history) // 2 + 1)):
            tail = history[-cycle_len:]
            prev = history[-2 * cycle_len:-cycle_len]
            if tail == prev:
                agentic_state.set(cooldown_key, True, ttl=cooldown)
                return GuardrailResult(
                    passed=False, action=self.configured_action, guardrail_name=self.name,
                    message=f"Cycle detected: pattern of length {cycle_len} repeating",
                    details={"cycle": tail, "cycle_length": cycle_len})

        return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                               message="No loop detected")
