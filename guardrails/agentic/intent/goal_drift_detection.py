"""Goal Drift Detection guardrail — detects when agents deviate from assigned goals.

Compares the agent's current action against its registered goal using
a combination of fast regex pre-filtering and LLM-based classification.

Categories of drift:
- goal_deviation: Agent is doing something unrelated to goal
- scope_expansion: Agent is expanding beyond its assigned scope
- mission_creep: Agent is gradually drifting from original intent
- adversarial_redirect: Agent appears to have been hijacked/redirected
"""

import re
import time
from typing import Optional

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult

from guardrails.agentic.intent.intent_store import (
    register_goal,
    get_goal,
    append_action,
    get_action_history,
    update_drift_score,
)

_DEFAULT_FAST_PATTERNS = [
    r"ignore\s+.*(?:original|previous|initial)\s+(?:task|goal|instruction)",
    r"new\s+(?:objective|mission|goal|task)",
    r"forget\s+.*(?:about|previous|original)",
    r"instead\s+(?:of|let's|we\s+should)",
    r"disregard\s+.*(?:instruction|task|goal)",
    r"override\s+.*(?:original|assigned)",
    r"actually\s+(?:I|let|we)\s+(?:want|need|should)",
]

_SYSTEM_PROMPT = (
    "You are a goal-drift classifier for AI agents. Compare the agent's ORIGINAL GOAL "
    "with its CURRENT ACTION and determine if the agent has drifted from its assigned mission.\n\n"
    "ORIGINAL GOAL: {goal}\n\n"
    "RECENT ACTIONS: {history}\n\n"
    "CURRENT ACTION: {action}\n\n"
    "Respond with ONLY one CSV line: is_drifting,category,confidence\n"
    "Categories: goal_deviation, scope_expansion, mission_creep, adversarial_redirect, on_task\n"
    "Example: true,goal_deviation,0.85\n"
    "Example: false,on_task,0.95"
)

_CSV_FIELDS = ["is_drifting", "category", "confidence"]


class GoalDriftDetectionGuardrail(BaseGuardrail):
    """Detects when an agent deviates from its registered goal.

    Context keys used:
        - session_id (required): Links checks in same session
        - agent_key (required): Agent identifier
        - goal (optional): If provided on first call, registers as the session goal
        - current_action_summary (optional): Description of what agent is doing now
        - action_type (optional): Fallback for current action description
        - tool_name (optional): Fallback for current action description
        - chain_of_thought (optional): Agent's reasoning text, used for deeper analysis
    """

    name = "goal_drift_detection"
    tier = "slow"
    stage = "agentic"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        ctx = context or {}
        start = time.perf_counter()

        session_id = ctx.get("session_id")
        agent_key = ctx.get("agent_key", "")

        if not session_id:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="No session_id provided, skipping drift detection",
                latency_ms=round(elapsed, 2),
            )

        tenant_id = ctx.get("tenant_id", "")

        # Check if goal exists; if not, try to register one
        goal_record = get_goal(session_id, tenant_id=tenant_id)

        if not goal_record:
            goal_text = ctx.get("goal")
            if goal_text:
                goal_record = register_goal(
                    session_id=session_id,
                    agent_key=agent_key,
                    goal=goal_text,
                    tenant_id=tenant_id,
                    ttl=self.settings.get("goal_ttl_seconds", 86400),
                )
                elapsed = (time.perf_counter() - start) * 1000
                return GuardrailResult(
                    passed=True, action="pass", guardrail_name=self.name,
                    message="Goal registered for session",
                    details={"goal": goal_text, "session_id": session_id},
                    latency_ms=round(elapsed, 2),
                )
            else:
                # No goal registered and none provided — skip
                elapsed = (time.perf_counter() - start) * 1000
                return GuardrailResult(
                    passed=True, action="pass", guardrail_name=self.name,
                    message="No goal registered for session, skipping drift detection",
                    latency_ms=round(elapsed, 2),
                )

        # Build current action description
        current_action = (
            ctx.get("current_action_summary")
            or ctx.get("chain_of_thought")
            or ctx.get("action_type")
            or ctx.get("tool_name")
            or ""
        )

        if not current_action:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="No current action to compare against goal",
                latency_ms=round(elapsed, 2),
            )

        # Record action in history
        history_window = self.settings.get("history_window", 10)
        append_action(session_id, current_action, max_history=history_window)

        goal_text = goal_record["goal"]

        # Fast regex pre-filter
        if not self.settings.get("always_use_llm", False):
            patterns = self.settings.get("fast_patterns", _DEFAULT_FAST_PATTERNS)
            regex_match = False
            for pattern in patterns:
                if re.search(pattern, current_action, re.IGNORECASE):
                    regex_match = True
                    break

            if not regex_match:
                # No suspicious patterns — pass without LLM call
                elapsed = (time.perf_counter() - start) * 1000
                return GuardrailResult(
                    passed=True, action="pass", guardrail_name=self.name,
                    message="No drift patterns detected",
                    details={"goal": goal_text, "current_action": current_action[:200]},
                    latency_ms=round(elapsed, 2),
                )

        # LLM-based drift classification
        threshold = self.settings.get("sensitivity_threshold", 0.7)
        history = get_action_history(session_id)
        history_text = "; ".join(history[-5:]) if history else "(no prior actions)"

        try:
            from core.llm_backend import async_llm_call, parse_csv_response

            prompt = _SYSTEM_PROMPT.format(
                goal=goal_text,
                history=history_text,
                action=current_action,
            )
            response = await async_llm_call(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": current_action},
                ],
                max_tokens=30,
                temperature=0,
                guardrail_name=self.name,
            )
            raw = response["choices"][0]["message"]["content"]
            result = parse_csv_response(raw, _CSV_FIELDS)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"LLM drift check failed, allowing: {e}",
                latency_ms=round(elapsed, 2),
            )

        elapsed = (time.perf_counter() - start) * 1000

        is_drifting = result.get("is_drifting", False)
        confidence = result.get("confidence", 0.0)
        category = result.get("category", "on_task")

        # Update rolling drift score
        update_drift_score(session_id, confidence if is_drifting else 0.0)

        if is_drifting and confidence >= threshold:
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Goal drift detected: {category} "
                    f"(confidence: {confidence:.2f}). "
                    f"Goal: '{goal_text[:100]}'"
                ),
                details={
                    "is_drifting": True,
                    "category": category,
                    "confidence": confidence,
                    "goal": goal_text,
                    "current_action": current_action[:500],
                    "session_id": session_id,
                },
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message="Agent is on task",
            details={
                "is_drifting": False,
                "category": category,
                "confidence": confidence,
                "goal": goal_text[:200],
            },
            latency_ms=round(elapsed, 2),
        )
