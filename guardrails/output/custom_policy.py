"""Custom Policy Output Guardrail - Tenant-specific LLM-based policy evaluation for output."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional

from guardrails.base import BaseGuardrail, safe_float
from core.llm_backend import async_llm_call, parse_csv_response
from core.text_utils import build_policy_messages, custom_policy_history_turns
from core.models import GuardrailResult

logger = logging.getLogger(__name__)


# Same four values the JSON schema carried. CSV is not about decode cost —
# json.loads on 200 bytes is microseconds — it is about GENERATION cost: the
# braces, quotes and field names of a JSON object are tokens the model must
# emit before this guard can return, on a path that already dominates request
# latency. Free text goes LAST so an unescaped comma inside it cannot shift the
# fields that carry the decision.
_CSV_FIELDS = ["violates_policy", "confidence", "violation_type", "reasoning"]


def _parse_policy_csv(raw: str) -> dict:
    """parse_csv_response, with the trailing free-text field kept whole.

    The shared parser splits on every comma, so a reasoning string containing
    one would be truncated at it. Truncated prose is cosmetic; a shifted field
    is not, which is why reasoning is last.
    """
    result = parse_csv_response(raw, _CSV_FIELDS)
    line = raw.strip().splitlines()[-1].strip().strip('"')
    parts = line.split(",")
    if len(parts) > len(_CSV_FIELDS):
        result["reasoning"] = ",".join(parts[len(_CSV_FIELDS) - 1:]).strip().strip('"')
    return result


class CustomPolicyOutputGuardrail(BaseGuardrail):
    """Executes tenant-specific custom policies using LLM evaluation for output content."""

    def __init__(self):
        super().__init__()
        self.name = "custom_policy_output"
        self.tier = "slow"  # Custom policies use LLM evaluation
        self.stage = "output"

    async def check(self, text: str, context: Optional[dict] = None) -> GuardrailResult:
        """Check output text against tenant's custom policies."""
        context = context or {}

        try:
            # Get enabled custom policies from guardrail settings
            policies = self.settings.get("policies", [])
            enabled_policies = [p for p in policies if p.get("enabled", True) and p.get("stage", "output") == "output"]

            if not enabled_policies:
                return GuardrailResult(
                    passed=True,
                    action="pass",
                    guardrail_name=self.name,
                    message="No custom output policies configured",
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
                    logger.error(f"Error evaluating output policy {policy['policy_id']}: {e}")
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
            logger.error(f"Error in custom policy output guardrail: {e}")
            return GuardrailResult(
                passed=True,  # Fail open for safety
                action="pass",
                guardrail_name=self.name,
                message=f"Custom output policy evaluation error: {str(e)}",
                details={"error": str(e)},
                latency_ms=0.0
            )

    async def _evaluate_policy_with_llm(self, text: str, policy: Dict, context: Dict) -> Dict:
        """Use LLM to evaluate if output text violates custom policy."""

        evaluation_prompt = f"""You are a content policy evaluator. Analyze the given output text against the specified policy.

POLICY INFORMATION:
- Name: {policy['name']}
- Description: {policy['description']}

EVALUATION CRITERIA:
{policy['prompt']}

OUTPUT TEXT TO ANALYZE:
"{text}"

CONTEXT:
- User Role: {context.get('user_role', 'unknown')}
- Session ID: {context.get('session_id', 'unknown')}
- Stage: Output validation

Analyze if the output text violates the policy. Consider context and intent.

Respond with ONLY a JSON object in this exact format:
{{
    "violates_policy": true/false,
    "confidence": 0.85,
    "reasoning": "Brief explanation of the decision",
    "violation_type": "specific violation category or null"
}}"""

        try:
            # Opt-in multi-turn: prepend prior conversation turns so the policy
            # LLM judges the current output in context. Off by default -> the
            # single-message prompt is byte-identical to the pre-multi-turn path.
            max_turns = custom_policy_history_turns() if policy.get("multi_turn") else 0
            messages = build_policy_messages(evaluation_prompt, context, max_turns)

            # Use guardrail LLM to evaluate
            llm_response = await async_llm_call(
                messages=messages,
                max_tokens=200,
                temperature=0,
                guardrail_name="custom_policy_output"
            )

            result = _parse_policy_csv(
                llm_response["choices"][0]["message"]["content"])

            # reasoning is last so a comma inside it cannot shift the other
            # fields; rejoin whatever the split scattered.
            if not isinstance(result.get("violates_policy"), bool):
                raise ValueError("Invalid LLM response format")
            if result.get("violation_type", "").lower() in ("none", "null", ""):
                result["violation_type"] = None

            confidence = safe_float(result.get("confidence"), 0.5)
            violates_policy = result["violates_policy"]

            # Apply confidence threshold
            if confidence < policy.get("confidence_threshold", 0.8):
                violates_policy = False  # Not confident enough

            return {
                "passed": not violates_policy,
                "action": policy["action"] if violates_policy else "pass",
                "confidence": confidence,
                "message": f"Custom output policy '{policy['name']}': {result.get('reasoning', 'No reasoning provided')}",
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
            logger.error(f"LLM evaluation error for output policy {policy['policy_id']}: {e}")
            # Fail open - don't block due to evaluation errors
            return {
                "passed": True,
                "action": "pass",
                "confidence": 0.0,
                "message": f"Output policy evaluation error: {str(e)}",
                "details": {
                    "policy_id": policy["policy_id"],
                    "error": str(e)
                }
            }

    def _apply_guardrail_action(self, policy_action: str) -> str:
        """Let the parent custom_policy_output action escalate policy violations.

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
                "message": f"All {len(all_policies)} custom output policies passed",
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
            "message": f"{len(violations)} custom output policy violation(s). Worst: {worst_violation['message']}",
            "details": {
                "policies_checked": len(all_policies),
                "violations": len(violations),
                "violation_details": violation_details,
                "primary_violation": worst_violation["details"]
            }
        }