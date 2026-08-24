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

# The verdict line only. `findings` is last so its commas fall in the final
# field. The redacted content is NOT here -- it is a separate marker line, see
# _split_verdict_and_sanitized, because two comma-bearing free-text fields on
# one CSV line cannot be separated positionally.
_CSV_FIELDS = ["has_sensitive", "action", "confidence", "findings"]

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


def _split_verdict_and_sanitized(raw: str) -> tuple[str, str]:
    """(verdict_line, sanitized_content).

    The model returns a CSV verdict line and, when redacting, a second line
    beginning with SANITIZED: carrying the redacted content verbatim. The two
    are on separate lines ON PURPOSE: `findings` and the redacted record BOTH
    contain commas, and an earlier single-line CSV design let the tail of
    `findings` bleed into the content, returning garbled output (the customer's
    name replaced by a fragment of the finding).

    Everything after the marker is content, commas and newlines included.
    """
    text = (raw or "").strip()
    idx = text.find(_SANITIZED_MARKER)
    if idx == -1:
        return text, ""
    verdict = text[:idx].strip()
    sanitized = text[idx + len(_SANITIZED_MARKER):].strip()
    # The verdict is the last non-empty line before the marker (handles a header
    # echo, same as parse_csv_response does).
    lines = [l for l in verdict.splitlines() if l.strip()]
    return (lines[-1] if lines else verdict), sanitized


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


_SANITIZED_MARKER = "SANITIZED:"

_SYSTEM = (
    "You are a data protection engine. Analyze tool output for sensitive data "
    "that should be blocked or redacted before showing to the user.\n"
    "Check for: PII, secrets, role-restricted data, regulated data, internal system data.\n"
    "Respond with a CSV verdict line: has_sensitive,action,confidence,findings\n"
    "action is one of: allow, redact, block\n"
    # The redacted content goes on its OWN line after a marker, never in the CSV.
    # findings is free text and contains commas; a redacted record contains
    # commas; two comma-bearing fields on one CSV line cannot be separated
    # positionally, which produced garbled output. Keep them on different lines.
    "When action is redact, add a SECOND line beginning with 'SANITIZED:' "
    "followed by the tool output reproduced EXACTLY, changing ONLY the values "
    "the policy forbids. Replace each with the replacement the policy gives, or "
    "[REDACTED] when it gives none. Keep every other character identical. Never "
    "summarise, reformat, or invent content.\n"
    "When action is allow or block, output only the CSV line.\n"
    "Example:\ntrue,block,0.95,SSN and credit card numbers found\n"
    "Example:\nfalse,allow,0.90,no sensitive data detected\n"
    "Example:\ntrue,redact,0.95,passport, national ID found\n"
    "SANITIZED:name=Jane Doe passport=[REDACTED] tier=gold"
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
            verdict_line, sanitized_content = _split_verdict_and_sanitized(raw)
            result = parse_csv_response(verdict_line, _CSV_FIELDS)

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
            sanitized = sanitized_content
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
