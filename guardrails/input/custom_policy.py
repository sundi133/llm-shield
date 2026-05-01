"""Custom Policy Input Guardrail - Tenant-specific LLM-based policy evaluation for input."""

import json
import logging
from datetime import datetime
from typing import Dict

from guardrails.base import BaseGuardrail
from core.llm_backend import async_llm_call, parse_llm_json
from core.models import GuardrailResult
from storage.custom_policies import get_tenant_custom_policies

logger = logging.getLogger(__name__)


class CustomPolicyInputGuardrail(BaseGuardrail):
    """Executes tenant-specific custom policies using LLM evaluation for input content."""

    def __init__(self):
        super().__init__()
        self.name = "custom_policy_input"
        self.tier = "slow"  # Custom policies use LLM evaluation
        self.stage = "input"

    async def check(self, text: str, **kwargs) -> GuardrailResult:
        """Check input text against tenant's custom policies."""
        context = kwargs.get("context", {})
        tenant_id = context.get("tenant_id", "default")

        try:
            # Get enabled custom policies for tenant (max 10)
            policies = get_tenant_custom_policies(tenant_id, enabled_only=True)

            if not policies:
                return GuardrailResult(
                    passed=True,
                    action="pass",
                    guardrail_name=self.name,
                    message="No custom input policies configured",
                    details={"policy_count": 0},
                    latency_ms=0.0
                )

            # Run LLM evaluation for each policy
            start_time = datetime.now()
            violations = []

            for policy in policies:
                try:
                    result = await self._evaluate_policy_with_llm(text, policy, context)
                    if not result["passed"]:
                        violations.append(result)
                        # Stop on first blocking violation for performance
                        if result["action"] == "block":
                            break
                except Exception as e:
                    logger.error(f"Error evaluating input policy {policy['policy_id']}: {e}")
                    # Continue with other policies if one fails
                    continue

            end_time = datetime.now()
            latency_ms = (end_time - start_time).total_seconds() * 1000

            # Return worst violation or pass
            final_result = self._aggregate_policy_results(violations, policies)
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

Respond with ONLY a JSON object in this exact format:
{{
    "violates_policy": true/false,
    "confidence": 0.85,
    "reasoning": "Brief explanation of the decision",
    "violation_type": "specific violation category or null"
}}"""

        try:
            # Use guardrail LLM to evaluate
            llm_response = await async_llm_call(
                messages=[{"role": "user", "content": evaluation_prompt}],
                max_tokens=200,
                temperature=0,
                response_format={
                    "type": "object",
                    "properties": {
                        "violates_policy": {"type": "boolean"},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "string"},
                        "violation_type": {"type": ["string", "null"]}
                    }
                },
                guardrail_name="custom_policy_input"
            )

            result = parse_llm_json(llm_response["choices"][0]["message"]["content"])

            # Validate LLM response
            if not isinstance(result.get("violates_policy"), bool):
                raise ValueError("Invalid LLM response format")

            confidence = float(result.get("confidence", 0.5))
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
        action_severity = {"pass": 0, "warn": 1, "redact": 2, "block": 3}
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