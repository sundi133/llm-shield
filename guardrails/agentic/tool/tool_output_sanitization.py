"""Sanitize tool outputs via LLM-based data policy checks.

All output sanitization is handled by the LLM against tenant-configured
data policies. No hardcoded regex patterns. Uses CSV output for minimal
token cost.
"""

import json
import logging
from typing import Optional, Any

from guardrails.base import BaseGuardrail, safe_float
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response

logger = logging.getLogger("votal.tool_output_sanitization")

# `sanitized` is LAST on purpose: it carries free text that will contain
# commas, so everything after the fourth comma is content.
_CSV_FIELDS = ["has_sensitive", "action", "confidence", "findings", "sanitized"]

# The ladder already canonical in this repo (api/routes_classify.py:629).
# `mask` sits level with `redact`: both return modified content without refusing
# the call, so neither may be capped into the other.
_SEVERITY = {"pass": 0, "allow": 0, "log": 1, "warn": 2,
             "redact": 3, "mask": 3, "block": 4}


def _cap_enabled() -> bool:
    """SHIELD_TOOL_OUTPUT_ACTION_CAP=off restores model-authoritative behavior."""
    import os
    return os.environ.get("SHIELD_TOOL_OUTPUT_ACTION_CAP", "").strip().lower() \
        not in ("0", "off", "false", "no")


def _cap_action(action: str, configured: str) -> str:
    """Clamp the model's verdict to the configured action.

    The verdict used to be authoritative: `action` came straight from the LLM,
    and `configured_action` was consulted in exactly one branch. A deployment
    configured for `warn` was blocked anyway, and had no way to dial the
    guardrail down -- configuration could not restrain it.

    Only ever REDUCES severity. A verdict at or below the configured action
    passes through untouched; nothing here can escalate.

    Fails closed on anything unrecognised: an unknown verdict scores 0 (never
    exceeds the cap) and an unknown configured action scores 4 (caps nothing),
    so a typo loosens neither.
    """
    if not _cap_enabled() or not configured:
        return action
    if _SEVERITY.get(action, 0) > _SEVERITY.get(configured, 4):
        return configured
    return action

def _redaction_enabled() -> bool:
    """SHIELD_LLM_REDACTION=off restores the old behaviour.

    UNSAFE. The behaviour it restores is the bug: `redact` returned the original
    text unchanged. Present for rollback only, not as a supported mode.
    """
    import os
    return os.environ.get("SHIELD_LLM_REDACTION", "").strip().lower() \
        not in ("0", "off", "false", "no")


def _extract_sanitized(raw: str) -> str:
    """The 5th CSV field, verbatim, commas included.

    parse_csv_response splits on EVERY comma and indexes, so a redacted payload
    containing a comma would be truncated at the first one. Redacted content is
    free text and will contain commas, so take the remainder after the fourth
    separator instead. Mirrors the shared parser's preprocessing so both see the
    same line.
    """
    line = (raw or "").strip()
    if "\n" in line:
        line = line.split("\n")[-1].strip()
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]
    parts = line.split(",", 4)
    return parts[4].strip() if len(parts) == 5 else ""


#: A redaction wildly longer than its input is a rewrite, not a redaction.
_REDACTION_GROWTH_LIMIT = 1.5


def _usable_redaction(sanitized: str, original: str) -> tuple[bool, str]:
    """Whether the model actually produced a redaction. (ok, why_not).

    Every rejection here escalates to block. That is the whole point: the defect
    being fixed is "we said redact and returned the original", so a lenient
    fallback would reintroduce it under a new name. If redaction was required
    and could not be produced, withholding is the only safe answer.
    """
    if not sanitized or not sanitized.strip():
        return False, "empty"
    if sanitized.strip() == original.strip():
        # Claimed a redaction, changed nothing. Exactly the old bug.
        return False, "unchanged"
    if len(sanitized) > len(original) * _REDACTION_GROWTH_LIMIT:
        # Returning invented content as tool output is worse than withholding.
        return False, "rewritten"
    return True, ""


_SYSTEM = (
    "You are a data protection engine. Analyze tool output for sensitive data "
    "that should be blocked or redacted before showing to the user.\n"
    "Check for: PII, secrets, role-restricted data, regulated data, internal system data.\n"
    "Respond with ONLY one CSV line: has_sensitive,action,confidence,findings,sanitized\n"
    "action is one of: allow, redact, block\n"
    # Without this the model returns a verdict and nothing else, which is how
    # `redact` came to return the original text unchanged.
    "When action is redact you MUST fill `sanitized`: reproduce the tool output "
    "EXACTLY, changing ONLY the values the policy forbids. Replace each with the "
    "replacement the policy gives, or [REDACTED] when it gives none. Keep every "
    "other character identical. Never summarise, reformat, or invent content.\n"
    "When action is allow or block, leave `sanitized` empty.\n"
    "`sanitized` is the last field, so it may contain commas.\n"
    "Example: true,block,0.95,SSN and credit card numbers found,\n"
    "Example: false,allow,0.90,no sensitive data detected,\n"
    "Example: true,redact,0.95,passport number found,"
    "name=Jane Doe passport=[REDACTED] tier=gold"
)


class ToolOutputSanitizationGuardrail(BaseGuardrail):
    name = "tool_output_sanitization"
    tier = "slow"  # Uses LLM for policy evaluation
    stage = "agentic"

    @staticmethod
    def _normalize_output(value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        ctx = context or {}
        tool_output = self._normalize_output(ctx.get("tool_output", content))
        tool_name = ctx.get("tool_name", "")
        tenant_id = ctx.get("tenant_id") or ctx.get("X-Tenant-ID", "")
        user_role = ctx.get("user_role") or ctx.get("X-User-Role", "user")

        if not tool_output or not tool_output.strip():
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="Empty tool output", details={},
            )

        # Length truncation
        max_len = self.settings.get("max_output_length", 0)
        truncated = False
        if max_len and len(tool_output) > max_len:
            tool_output = tool_output[:max_len] + "... [TRUNCATED]"
            truncated = True

        policies_text = self._load_policies_text(tenant_id, tool_name, user_role)

        # No policy for THIS tool means nothing to enforce. The judge used to be
        # handed "No specific data policies configured. Apply reasonable
        # security defaults", which invited it to invent a rule -- so a tool
        # whose policy was empty still got blocked, by a policy that did not
        # exist. Enforcement is driven by configured policy, not improvisation.
        #
        # The structural floor above (max_output_length) still applies, and so
        # do deterministic sanitization_rules. Only the model's discretion is
        # withdrawn. Spec: docs/spec-tool-output-action-authority.md
        if not policies_text:
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message="No data policy configured for this tool",
                details={"sanitized_output": tool_output, "truncated": truncated,
                         "tenant_id": tenant_id, "user_role": user_role,
                         "skipped": "no_policy_for_tool"},
            )

        try:
            # Prefill optimization: the static instruction + the tenant policy
            # text are stable across requests, so they go in the SYSTEM message
            # (vLLM prefix-caches it); only the variable tool output goes in the
            # user message. Same information, reordered so the policy block isn't
            # re-prefilled on every call. (Stable-prefix-first; see APC.)
            system_content = f"{_SYSTEM}\n\nData policies:\n{policies_text}"
            user_content = (
                f"Tool: {tool_name}\n"
                f"User role: {user_role}\n\n"
                f"Tool output:\n{tool_output[:4000]}"
            )

            llm_response = await async_llm_call(
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content},
                ],
                # Was 60: enough for a verdict, not for returned content. The
                # input is already capped by max_output_length, so this bounds
                # the redacted rendering of it.
                max_tokens=1200,
                temperature=0,
                guardrail_name="tool_output_sanitization",
            )

            raw = (llm_response.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            result = parse_csv_response(raw, _CSV_FIELDS)

        except Exception as e:
            logger.error(f"LLM output sanitization error: {e}")
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Output sanitization error: {e}",
                details={"error": str(e), "sanitized_output": tool_output, "truncated": truncated},
            )

        action = result.get("action", "allow")
        if isinstance(action, str):
            action = action.lower().strip()
        findings = result.get("findings", "")
        confidence = safe_float(result.get("confidence"), 0.5)

        if confidence < 0.75:
            action = "allow"

        action = _cap_action(action, self.configured_action)

        # Only a block withholds the output. Everything else surfaces the
        # finding and returns the content, so a capped verdict is still visible
        # rather than silently becoming a pass -- the first version of the cap
        # let a capped `warn` fall through every branch and report "clean",
        # which loses the signal entirely.
        if action == "block":
            return GuardrailResult(
                passed=False, action="block", guardrail_name=self.name,
                message=f"Tool output blocked: {findings}",
                details={
                    "findings": findings,
                    "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]",
                    "truncated": truncated,
                    "tenant_id": tenant_id,
                    "user_role": user_role,
                    "confidence": confidence,
                },
            )

        # `redact`/`mask` promise modified content. Produce it or withhold.
        if action in ("mask", "redact") and _redaction_enabled():
            sanitized = _extract_sanitized(raw)
            ok, why = _usable_redaction(sanitized, tool_output)
            if not ok:
                escalated = _cap_action("block", self.configured_action)
                logger.warning(
                    "tool_output_sanitization: %s redaction unusable (%s) for %s; "
                    "escalating to %s", action, why, tool_name, escalated)
                return GuardrailResult(
                    passed=False, action=escalated, guardrail_name=self.name,
                    message=f"Redaction required but not produced ({why}): {findings}",
                    details={
                        "findings": findings,
                        # ALWAYS withhold, whatever the capped action label says.
                        # The cap governs how severe the result is reported to
                        # be; it must never decide whether we leak. Returning
                        # the original here under a capped `redact` label would
                        # be precisely the bug this change exists to fix.
                        "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]",
                        "truncated": truncated,
                        "tenant_id": tenant_id,
                        "user_role": user_role,
                        "confidence": confidence,
                        "redaction_failed": why,
                    },
                )
            details = {
                "findings": findings,
                "sanitized_output": sanitized,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role,
                "confidence": confidence,
                "redacted": True,
            }
            if action == "mask":
                details["mask_level"] = "partial"
            # mask and redact are different promises; keep the wording
            # distinct so an operator reading a log can tell which was applied.
            verb = ("partially masked" if action == "mask" else "redacted")
            return GuardrailResult(
                passed=False, action=action, guardrail_name=self.name,
                message=f"Sensitive data {verb} in tool output: {findings}",
                details=details,
            )

        if action in ("mask", "redact", "warn", "log"):
            noun = {"mask": "Sensitive data partially masked in tool output",
                    "redact": "Sensitive data found in tool output",
                    "warn": "Sensitive data found in tool output (warn only)",
                    "log": "Sensitive data found in tool output (logged)"}[action]
            details = {
                "findings": findings,
                "sanitized_output": tool_output,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role,
                "confidence": confidence,
            }
            if action == "mask":
                details["mask_level"] = "partial"
            return GuardrailResult(
                passed=False, action=action, guardrail_name=self.name,
                message=f"{noun}: {findings}", details=details,
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message="Tool output clean",
            details={
                "sanitized_output": tool_output,
                "truncated": truncated,
                "tenant_id": tenant_id,
                "user_role": user_role,
            },
        )

    @staticmethod
    def _load_policies_text(tenant_id: str, tool_name: str = "",
                            user_role: str = "") -> str:
        """Policy text for THIS tool, or "" when none applies.

        Two changes from the original, both deliberate.

        Scoped by tool: this called _load_data_policies WITHOUT a tool name, so
        every policy on the tenant was in scope for every tool. The input-side
        judge (payload_risk) was already fixed for exactly this -- its docstring
        records that a rule about `customer_profile.get` judging `patient_lookup`
        made the model report restrictions that did not exist. The output side
        kept loading the lot; one tenant had 15 tool policies, including
        prescribe_medication and rotate_credential, all in scope when judging a
        bank statement.

        Empty means empty: it now returns "" rather than prose telling the model
        to "apply reasonable security defaults", which is an instruction to
        invent a policy. The caller skips the judge entirely.
        """
        if not tenant_id:
            return ""
        try:
            from guardrails.agentic.tool.payload_risk import _load_data_policies, _format_data_policies
            policies = _load_data_policies(tenant_id, tool_name)
            if not policies:
                return ""
            return _format_data_policies(policies, tenant_id, tool_name, user_role)
        except Exception:
            # A load failure is not "no policy" -- it is unknown. Returning ""
            # here would skip the judge on a storage blip, so fail closed by
            # letting the caller run with no policy text.
            return " "
