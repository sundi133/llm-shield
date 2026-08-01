"""Custom Policy Output Guardrail - Tenant-specific LLM-based policy evaluation for output."""

import asyncio
import logging
import os
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


# How the evaluator is told to read the text. The previous wording — "Consider
# context and intent" — reads as an invitation to weigh the message as a whole,
# and on a long multi-topic message the model anchors on the leading topic:
# a pricing disclosure that blocked at confidence 0.95 on its own passed
# outright once an unrelated paragraph was prepended to it, with the identical
# sentence still present twice further down.
#
# Presence-type policies (PII, pricing, secrets) are not about what a message is
# FOR. A violating clause buried in an otherwise mundane request is still a
# violation, so the evaluator is told to scan spans rather than summarise.
POLICY_SCAN_INSTRUCTION = (
    "Read the ENTIRE text from beginning to end and judge each sentence "
    "against the criteria on its own.\n"
    "A violation ANYWHERE makes the whole text a violation, even when it is a "
    "single clause inside a long message that is mostly about something else.\n"
    "Do NOT weigh how routine or benign the overall request seems, and do NOT "
    "let the opening sentences settle the verdict. Unrelated surrounding "
    "content never excuses a violating span.\n"
    "Where the policy describes intent rather than presence, judge the intent "
    "of the specific span, not of the message as a whole."
)


def custom_policy_fail_open() -> bool:
    """Whether a policy that FAILED TO EVALUATE should be treated as passing.

    Default True — unchanged from the behaviour this flag replaces, so no
    tenant's traffic changes on upgrade. Set SHIELD_CUSTOM_POLICY_FAIL_OPEN=0
    to make an unevaluated policy block instead: for a tenant whose custom
    policies are the control (rather than defence in depth), silently passing
    traffic a policy never actually judged is the worse failure.
    """
    return os.environ.get("SHIELD_CUSTOM_POLICY_FAIL_OPEN", "1").strip() != "0"


def _parse_policy_csv(raw: str) -> dict:
    """parse_csv_response, with the trailing free-text field kept whole.

    The shared parser splits on every comma, so a reasoning string containing
    one would be truncated at it. Truncated prose is cosmetic; a shifted field
    is not, which is why reasoning is last.

    The shared parser also assumes the verdict is the LAST line. On longer,
    multi-topic inputs the model is measurably more likely to append a closing
    remark after the CSV — and a trailing prose line makes `violates_policy`
    a string, which the caller rejects as an invalid response and then FAILS
    OPEN. So: search the lines from the bottom up for the first one that
    actually yields a boolean verdict, and only fall back to last-line
    behaviour when none does.
    """
    lines = [ln.strip() for ln in raw.strip().splitlines() if ln.strip()]
    for line in reversed(lines or [""]):
        result = parse_csv_response(line, _CSV_FIELDS)
        if isinstance(result.get("violates_policy"), bool):
            parts = line.strip('"').split(",")
            if len(parts) > len(_CSV_FIELDS):
                result["reasoning"] = ",".join(
                    parts[len(_CSV_FIELDS) - 1:]).strip().strip('"')
            return result

    # No parseable verdict anywhere. Preserve the previous shape so the caller
    # raises its own "Invalid LLM response format" rather than a KeyError.
    result = parse_csv_response(raw, _CSV_FIELDS)
    line = (lines or [""])[-1].strip('"')
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
                    # Return a shaped error rather than None: an unevaluated
                    # policy must stay countable downstream, or it disappears
                    # into the "all policies passed" summary.
                    return {
                        "passed": True, "action": "pass", "confidence": 0.0,
                        "suppressed": False, "error": str(e),
                        "message": f"Output policy evaluation error: {e}",
                        "details": {
                            "policy_id": policy.get("policy_id"),
                            "policy_name": policy.get("name", ""),
                            "error": str(e),
                        },
                    }

            results = [r for r in await asyncio.gather(
                *[_eval(p) for p in enabled_policies]) if r is not None]
            # enabled_policies is priority-sorted; gather preserves order, so
            # violations stay in priority order for aggregation.
            violations = [r for r in results if not r["passed"]]
            suppressed = [r for r in results if r.get("suppressed")]
            errored = [r for r in results if r.get("error")]

            end_time = datetime.now()
            latency_ms = (end_time - start_time).total_seconds() * 1000

            # Return worst violation or pass
            final_result = self._aggregate_policy_results(
                violations, enabled_policies, suppressed, errored)
            if errored and final_result["passed"] and not custom_policy_fail_open():
                final_result["passed"] = False
                final_result["action"] = "block"
                final_result["message"] = (
                    f"{len(errored)} of {len(enabled_policies)} custom output "
                    "policies could not be evaluated and "
                    "SHIELD_CUSTOM_POLICY_FAIL_OPEN=0")
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
            fail_open = custom_policy_fail_open()
            return GuardrailResult(
                passed=fail_open,
                action="pass" if fail_open else "block",
                guardrail_name=self.name,
                message=f"Custom output policy evaluation error: {str(e)}",
                details={"error": str(e), "fail_open": fail_open},
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

OUTPUT TEXT TO ANALYZE (everything between the markers):
<<<BEGIN TEXT
{text}
END TEXT>>>

CONTEXT:
- User Role: {context.get('user_role', 'unknown')}
- Session ID: {context.get('session_id', 'unknown')}
- Stage: Output validation

{POLICY_SCAN_INSTRUCTION}

Respond with ONLY one CSV line: violates_policy,confidence,violation_type,reasoning
Use "none" for violation_type when there is no violation. Do not quote fields;
reasoning is last so a comma inside it is harmless.
Example: true,0.95,pii_disclosure,output contains a customer name and card number
Example: false,0.90,none,no policy violation found"""

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

            # Apply confidence threshold. A flagged-but-under-threshold verdict
            # is recorded: without it, "the model found nothing" and "the model
            # flagged this at 0.79 and we dropped it" are the same response, and
            # the second is the one an operator needs to see to tune the
            # threshold or the policy prompt.
            suppressed = False
            if confidence < policy.get("confidence_threshold", 0.8):
                suppressed = bool(violates_policy)
                violates_policy = False  # Not confident enough

            return {
                "passed": not violates_policy,
                "action": policy["action"] if violates_policy else "pass",
                "confidence": confidence,
                "suppressed": suppressed,
                "error": None,
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
            # Fail open per policy - the aggregate decides what to do with it
            # (see custom_policy_fail_open), but the error is always counted.
            return {
                "passed": True,
                "action": "pass",
                "confidence": 0.0,
                "suppressed": False,
                "error": str(e),
                "message": f"Output policy evaluation error: {str(e)}",
                "details": {
                    "policy_id": policy["policy_id"],
                    "policy_name": policy.get("name", ""),
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

    def _aggregate_policy_results(self, violations: list[Dict], all_policies: list[Dict],
                                  suppressed: Optional[list[Dict]] = None,
                                  errored: Optional[list[Dict]] = None) -> Dict:
        """Aggregate results from multiple policy violations."""

        # Near-misses and failed evaluations ride along on every response.
        # Both used to be invisible: a policy that flagged at 0.79 and a policy
        # whose LLM call raised both landed in the same "passed" summary as a
        # policy that genuinely found nothing.
        extra: Dict = {}
        if suppressed:
            extra["suppressed_by_threshold"] = [{
                "policy_id": s["details"].get("policy_id"),
                "policy_name": s["details"].get("policy_name"),
                "violation_type": s["details"].get("violation_type"),
                "confidence": s["confidence"],
                "threshold": s["details"].get("threshold"),
            } for s in suppressed]
        if errored:
            extra["errors"] = [{
                "policy_id": e["details"].get("policy_id"),
                "policy_name": e["details"].get("policy_name"),
                "error": e["details"].get("error"),
            } for e in errored]

        if not violations:
            evaluated = len(all_policies) - len(errored or [])
            message = f"All {len(all_policies)} custom output policies passed"
            if errored:
                message = (f"{evaluated} of {len(all_policies)} custom output policies "
                           f"passed; {len(errored)} could not be evaluated")
            if suppressed:
                message += (f" ({len(suppressed)} detection(s) below the "
                            "confidence threshold)")
            return {
                "passed": True,
                "action": "pass",
                "message": message,
                "details": {
                    "policies_checked": len(all_policies),
                    "policies_evaluated": evaluated,
                    "violations": 0,
                    **extra,
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
                "policies_evaluated": len(all_policies) - len(errored or []),
                "violations": len(violations),
                "violation_details": violation_details,
                "primary_violation": worst_violation["details"],
                **extra,
            }
        }