"""Role-Based Output Policy Guardrail - Apply data policies to final LLM responses.

This guardrail closes the security gap where LLM responses incorporating tool outputs
are not subject to role-based data policy checks. It ensures that final LLM responses
respect the same data access controls as individual tool calls.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

from guardrails.base import BaseGuardrail
from core.llm_backend import async_llm_call, parse_llm_json
from core.models import GuardrailResult

logger = logging.getLogger(__name__)


class RoleBasedOutputPolicyGuardrail(BaseGuardrail):
    """Apply role-based data policies to final LLM responses."""

    def __init__(self):
        super().__init__()
        self.name = "role_based_policy"
        self.tier = "slow"  # Uses LLM evaluation for semantic analysis
        self.stage = "output"

    async def check(self, text: str, context: Optional[dict] = None) -> GuardrailResult:
        """Check LLM response against role-based data policies."""
        context = context or {}
        tenant_id = context.get("tenant_id")
        user_role = context.get("user_role") or context.get("role")  # Support both formats

        # Skip if we don't have the required context
        if not tenant_id or not user_role:
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No tenant/role context - skipping role-based policy check",
                details={},
                latency_ms=0.0
            )

        try:
            start_time = datetime.now()

            # Load role-based data policies
            role_policies = await self._load_role_policies(tenant_id, user_role)

            if not role_policies:
                return GuardrailResult(
                    passed=True,
                    action="pass",
                    guardrail_name=self.name,
                    message=f"No role-based policies configured for role '{user_role}'",
                    details={"role": user_role, "policies_found": 0},
                    latency_ms=0.0
                )

            # Analyze LLM response against role policies
            policy_violations = await self._analyze_response_with_llm(
                text, user_role, role_policies, context
            )

            end_time = datetime.now()
            latency_ms = (end_time - start_time).total_seconds() * 1000

            # Determine final action based on violations
            result = self._process_policy_violations(policy_violations, user_role)
            result["latency_ms"] = round(latency_ms, 2)

            return GuardrailResult(
                passed=result["passed"],
                action=result["action"],
                guardrail_name=self.name,
                message=result["message"],
                details=result["details"],
                latency_ms=result["latency_ms"]
            )

        except Exception as e:
            logger.error(f"Error in role-based output policy guardrail: {e}")
            return GuardrailResult(
                passed=True,  # Fail open for safety
                action="pass",
                guardrail_name=self.name,
                message=f"Role-based policy check error: {str(e)}",
                details={"error": str(e), "role": user_role},
                latency_ms=0.0
            )

    async def _load_role_policies(self, tenant_id: str, user_role: str) -> List[Dict]:
        """Load data policies that apply to this user role."""
        try:
            # Get all tool data policies for this tenant
            from storage.tenant_store import _get_redis
            r = _get_redis()
            if not r:
                return []

            data_policies_key = f"data_policies:{tenant_id}"
            policies_data = r.get(data_policies_key)
            if not policies_data:
                return []

            all_policies = json.loads(policies_data)
            role_applicable_policies = []

            # Extract policies that apply to this role
            for tool_name, policy in all_policies.items():
                role_policies = policy.get("role_policies", [])
                for role_policy in role_policies:
                    if role_policy.get("role") == user_role:
                        role_applicable_policies.append({
                            "tool_name": tool_name,
                            "role": user_role,
                            "action": role_policy.get("action", "allow"),
                            "data_scope": role_policy.get("data_scope", []),
                            "redaction_level": role_policy.get("redaction_level", "partial"),
                            "input_rules": role_policy.get("input_rules", []),
                            "output_rules": role_policy.get("output_rules", []),
                            "compliance_framework": policy.get("compliance_framework"),
                            "sanitization_intent": policy.get("sanitization_intent")
                        })

            return role_applicable_policies

        except Exception as e:
            logger.error(f"Error loading role policies for {tenant_id}/{user_role}: {e}")
            return []

    async def _analyze_response_with_llm(
        self,
        response_text: str,
        user_role: str,
        role_policies: List[Dict],
        context: Dict
    ) -> List[Dict]:
        """Use LLM to analyze if the response violates role-based policies."""

        # Build policy description for LLM
        policy_descriptions = []
        restricted_data_types = set()
        blocked_tools = []
        redaction_rules = []

        for policy in role_policies:
            tool_name = policy["tool_name"]
            action = policy["action"]
            data_scope = policy.get("data_scope", [])

            if action == "block":
                blocked_tools.append(tool_name)
                restricted_data_types.update(data_scope)
            elif action == "redact":
                redaction_rules.append({
                    "tool": tool_name,
                    "data_types": data_scope,
                    "level": policy.get("redaction_level", "partial")
                })

            # Add output rules if they exist
            output_rules = policy.get("output_rules", [])
            if output_rules:
                policy_descriptions.extend(output_rules)

        # Create LLM evaluation prompt
        evaluation_prompt = f"""You are a healthcare data policy compliance analyzer. Analyze the AI assistant response below to determine if it violates role-based access controls.

USER ROLE: {user_role}

POLICY VIOLATIONS TO CHECK:
1. BLOCKED DATA ACCESS: Role '{user_role}' should NOT have access to data from: {blocked_tools}
2. RESTRICTED DATA TYPES: The following data types are restricted: {list(restricted_data_types)}
3. REDACTION VIOLATIONS: Information requiring redaction may be exposed
4. POLICY RULES: {policy_descriptions if policy_descriptions else 'No specific rules configured'}

ASSISTANT RESPONSE TO ANALYZE:
"{response_text}"

ANALYSIS CONTEXT:
- User Role: {user_role}
- Session Context: {context.get('session_id', 'unknown')}
- Previous Tool Calls: {context.get('tool_calls_made', 'unknown')}

Determine if this response violates role-based access controls by:
1. Revealing data the role shouldn't access
2. Exposing information that should be redacted
3. Making inferences from restricted data
4. Paraphrasing or summarizing blocked information
5. Violating specific output rules for this role

Consider that AI responses can leak information through:
- Direct disclosure of restricted data
- Inferences and patterns from multiple data points
- Paraphrasing that circumvents redaction
- Medical knowledge filling in sanitized gaps

Respond with ONLY a JSON object:
{{
    "violates_policy": true/false,
    "confidence": 0.85,
    "violation_type": "data_access_violation|redaction_bypass|inference_leak|rule_violation",
    "specific_violations": [
        {{
            "data_type": "medical_diagnosis|personal_info|financial|etc",
            "violation_reason": "specific explanation of what was disclosed inappropriately",
            "severity": "low|medium|high|critical",
            "recommended_action": "warn|redact|block"
        }}
    ],
    "reasoning": "Brief explanation of the analysis and decision"
}}"""

        try:
            # Use guardrail LLM to evaluate
            llm_response = await async_llm_call(
                messages=[{"role": "user", "content": evaluation_prompt}],
                max_tokens=300,
                temperature=0,
                response_format={
                    "type": "object",
                    "properties": {
                        "violates_policy": {"type": "boolean"},
                        "confidence": {"type": "number"},
                        "violation_type": {"type": ["string", "null"]},
                        "specific_violations": {"type": "array"},
                        "reasoning": {"type": "string"}
                    }
                },
                guardrail_name="role_based_policy"
            )

            result = parse_llm_json(llm_response["choices"][0]["message"]["content"])

            # Validate LLM response structure
            if not isinstance(result.get("violates_policy"), bool):
                raise ValueError("Invalid LLM response format")

            return result.get("specific_violations", []) if result.get("violates_policy") else []

        except Exception as e:
            logger.error(f"LLM analysis error for role-based policy: {e}")
            return []  # Fail open

    def _process_policy_violations(self, violations: List[Dict], user_role: str) -> Dict:
        """Process policy violations and determine final action."""

        if not violations:
            return {
                "passed": True,
                "action": "pass",
                "message": f"Response complies with role '{user_role}' data access policies",
                "details": {
                    "role": user_role,
                    "violations": 0,
                    "policy_check": "passed"
                }
            }

        # Determine worst violation
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        action_priority = {"warn": 1, "redact": 2, "block": 3}

        worst_violation = max(
            violations,
            key=lambda v: (
                severity_order.get(v.get("severity", "medium"), 2),
                action_priority.get(v.get("recommended_action", "warn"), 1)
            )
        )

        final_action = worst_violation.get("recommended_action", "warn")

        # Build detailed response
        violation_details = []
        for v in violations:
            violation_details.append({
                "data_type": v.get("data_type"),
                "reason": v.get("violation_reason"),
                "severity": v.get("severity", "medium"),
                "action": v.get("recommended_action", "warn")
            })

        return {
            "passed": final_action == "warn",  # Warn still "passes" but flags issue
            "action": final_action,
            "message": f"Role '{user_role}' policy violation: {worst_violation.get('violation_reason', 'Unauthorized data access detected')}",
            "details": {
                "role": user_role,
                "violations": len(violations),
                "worst_severity": worst_violation.get("severity"),
                "violation_details": violation_details,
                "primary_violation_type": worst_violation.get("data_type")
            }
        }