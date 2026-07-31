"""Custom Policy Input Guardrail - Tenant-specific LLM-based policy evaluation for input."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional

from guardrails.base import BaseGuardrail, safe_float
from core.llm_backend import async_llm_call
from guardrails.output.custom_policy import _parse_policy_csv
from core.models import GuardrailResult
from core.text_utils import build_policy_messages, custom_policy_history_turns

logger = logging.getLogger(__name__)


class CustomPolicyInputGuardrail(BaseGuardrail):
    """Executes tenant-specific custom policies using LLM evaluation for input content."""

    def __init__(self):
        super().__init__()
        self.name = "custom_policy_input"
        self.tier = "slow"  # Custom policies use LLM evaluation
        self.stage = "input"

    async def check(self, text: str, context: Optional[dict] = None) -> GuardrailResult:
        """Check input text against tenant's custom policies."""
        context = context or {}

        try:
            # Get enabled custom policies from guardrail settings
            policies = self.settings.get("policies", [])
            enabled_policies = [p for p in policies if p.get("enabled", True) and p.get("stage", "input") == "input"]

            if not enabled_policies:
                return GuardrailResult(
                    passed=True,
                    action="pass",
                    guardrail_name=self.name,
                    message="No custom input policies configured",
                    details={"policy_count": 0},
                    latency_ms=0.0
                )

            # Evaluate all policies concurrently: each is an independent LLM call,
            # so wall-clock is the slowest single policy rather than their sum.
            # (Was sequential with a first-block short-circuit; parallel trades a
            # possible early exit for far lower guard-path latency, which matters
            # once multi_turn inflates each policy's prompt.)
            start_time = datetime.now()

            async def _eval(policy):
                try:
                    return await self._evaluate_policy_with_llm(text, policy, context)
                except Exception as e:
                    logger.error(f"Error evaluating input policy {policy['policy_id']}: {e}")
                    return None

            results = await asyncio.gather(*[_eval(p) for p in enabled_policies])
            # enabled_policies is priority-sorted; gather preserves order, so
            # violations stay in priority order for aggregation.
            violations = [r for r in results if r is not None and not r["passed"]]

            end_time = datetime.now()
            latency_ms = (end_time - start_time).total_seconds() * 1000

            # Return worst violation or pass
            final_result = self._aggregate_policy_results(violations, enabled_policies)
            final_result["action"] = self._apply_guardrail_action(final_result["action"])
            final_result["latency_ms"] = round(latency_ms, 2)

            return GuardrailResult(
                passed=final_result["passed"],
                action=final_result["action"],
                guardrail_name=self.name,
                message=final_result["message"],
                details=final_result["details"],
                latency_ms=final_result["latency_ms"]
            )

        except Exception as e:
            logger.error(f"Error in custom policy input guardrail: {e}")
            return GuardrailResult(
                passed=True,  # Fail open for safety
                action="pass",
                guardrail_name=self.name,
                message=f"Custom input policy evaluation error: {str(e)}",
                details={"error": str(e)},
                latency_ms=0.0
            )

    async def _evaluate_policy_with_llm(self, text: str, policy: Dict, context: Dict) -> Dict:
        """Use LLM to evaluate if input text violates custom policy."""

        evaluation_prompt = f"""You are a content policy evaluator. Analyze the given input text against the specified policy.

POLICY INFORMATION:
- Name: {policy['name']}
- Description: {policy['description']}

EVALUATION CRITERIA:
{policy['prompt']}

INPUT TEXT TO ANALYZE:
"{text}"

CONTEXT:
- User Role: {context.get('user_role', 'unknown')}
- Session ID: {context.get('session_id', 'unknown')}
- Stage: Input validation

Analyze if the input text violates the policy. Consider context and intent.

Respond with ONLY one CSV line: violates_policy,confidence,violation_type,reasoning
Use "none" for violation_type when there is no violation. Do not quote fields;
reasoning is last so a comma inside it is harmless.
Example: true,0.95,pii_disclosure,message shares a full name and card number
Example: false,0.90,none,no policy violation found"""

        try:
            # Opt-in multi-turn: prepend prior conversation turns so the policy
            # LLM judges the current message in context. Off by default -> the
            # single-message prompt is byte-identical to the pre-multi-turn path.
            max_turns = custom_policy_history_turns() if policy.get("multi_turn") else 0
            messages = build_policy_messages(evaluation_prompt, context, max_turns)

            # Use guardrail LLM to evaluate
            llm_response = await async_llm_call(
                messages=messages,
                max_tokens=200,
                temperature=0,
                guardrail_name="custom_policy_input"
            )

            result = _parse_policy_csv(
                llm_response["choices"][0]["message"]["content"])

            # Validate LLM response
            if not isinstance(result.get("violates_policy"), bool):
                raise ValueError("Invalid LLM response format")

            confidence = safe_float(result.get("confidence"), 0.5)
            violates_policy = result["violates_policy"]

            # Apply confidence threshold
            if confidence < policy.get("confidence_threshold", 0.8):
                violates_policy = False  # Not confident enough

            return {
                "passed": not violates_policy,
                "action": policy["action"] if violates_policy else "pass",
                "confidence": confidence,
                "message": f"Custom input policy '{policy['name']}': {result.get('reasoning', 'No reasoning provided')}",
                "details": {
                    "policy_id": policy["policy_id"],
                    "policy_name": policy["name"],
                    "violation_type": result.get("violation_type"),
                    "reasoning": result.get("reasoning", ""),
                    "confidence": confidence,
                    "threshold": policy.get("confidence_threshold", 0.8)
                }
            }

        except Exception as e:
            logger.error(f"LLM evaluation error for input policy {policy['policy_id']}: {e}")
            # Fail open - don't block due to evaluation errors
            return {
                "passed": True,
                "action": "pass",
                "confidence": 0.0,
                "message": f"Input policy evaluation error: {str(e)}",
                "details": {
                    "policy_id": policy["policy_id"],
                    "error": str(e)
                }
            }

    def _apply_guardrail_action(self, policy_action: str) -> str:
        """Let the parent custom_policy_input action escalate policy violations.

        The per-policy action is the default. If the tenant sets the wrapper
        guardrail action to warn/redact/block, use the stricter of the two.
        action=pass keeps per-policy actions unchanged.
        """
        action_severity = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "block": 4}
        wrapper_action = self.configured_action
        if wrapper_action == "pass":
            return policy_action
        return max(
            [policy_action, wrapper_action],
            key=lambda action: action_severity.get(action, 0),
        )

    def _aggregate_policy_results(self, violations: list[Dict], all_policies: list[Dict]) -> Dict:
        """Aggregate results from multiple policy violations."""

        if not violations:
            return {
                "passed": True,
                "action": "pass",
                "message": f"All {len(all_policies)} custom input policies passed",
                "details": {
                    "policies_checked": len(all_policies),
                    "violations": 0
                }
            }

        # Find the most severe action
        action_severity = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "block": 4}
        worst_violation = max(violations, key=lambda v: action_severity.get(v["action"], 0))

        # Collect all violation details
        violation_details = []
        for violation in violations:
            violation_details.append({
                "policy_id": violation["details"]["policy_id"],
                "policy_name": violation["details"]["policy_name"],
                "violation_type": violation["details"].get("violation_type"),
                "confidence": violation["confidence"]
            })

        return {
            "passed": False,
            "action": worst_violation["action"],
            "message": f"{len(violations)} custom input policy violation(s). Worst: {worst_violation['message']}",
            "details": {
                "policies_checked": len(all_policies),
                "violations": len(violations),
                "violation_details": violation_details,
                "primary_violation": worst_violation["details"]
            }
        }