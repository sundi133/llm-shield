"""Sanitize tool outputs via LLM-based data policy checks.

All output sanitization is handled by the LLM against tenant-configured
data policies. No hardcoded regex patterns. Uses CSV output for minimal
token cost.
"""

import asyncio
import json
import logging
from typing import Optional, Any

from guardrails.base import BaseGuardrail, safe_float
from core.models import GuardrailResult
from core.llm_backend import async_llm_call, parse_csv_response
from core.text_utils import (
    REDACTION_GROWTH_LIMIT, SANITIZED_MARKER, split_marker, usable_redaction,
)

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


def _full_scan_enabled() -> bool:
    """SHIELD_DLP_FULL_SCAN=on judges the WHOLE payload in chunks.

    Off by default because it changes cost: one model call per
    `judge_chunk_chars` of payload instead of one call that sees only the first
    chunk. With it off the behaviour is exactly the historic single slice, and
    the result reports `unjudged_chars` so the blind spot is at least visible.
    Spec: docs/spec-runtime-dlp-gaps.md, G4.
    """
    import os
    return os.environ.get("SHIELD_DLP_FULL_SCAN", "").strip().lower() \
        in ("1", "on", "true", "yes")


#: The slice the judge used to see, hard-coded as `tool_output[:4000]`.
_DEFAULT_CHUNK_CHARS = 4000
#: Chunks judged per payload under full scan. Beyond this the tail is withheld,
#: not leaked: 8 x 4000 = 32 KB judged, which covers a large SQL result.
_DEFAULT_MAX_CHUNKS = 8
_TAIL_WITHHELD = "[TAIL WITHHELD: exceeds scan budget]"


def _split_chunks(text: str, chunk_chars: int) -> list[str]:
    """Non-overlapping chunks of at most `chunk_chars`, cut at whitespace.

    Chunks are reassembled by plain concatenation after redaction, so they
    must not overlap. Cutting at the last whitespace in the final fifth of
    the window means a token such as `784-1990-1234567-1` is never split
    across two chunks, which is what would let it evade both. Concatenating
    the chunks yields the original text exactly.
    """
    chunk_chars = max(1, int(chunk_chars))
    if len(text) <= chunk_chars:
        return [text]
    chunks: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        end = pos + chunk_chars
        if end >= n:
            chunks.append(text[pos:])
            break
        cut = -1
        floor = pos + (chunk_chars * 4) // 5
        for i in range(end, floor, -1):
            if text[i - 1].isspace():
                cut = i
                break
        if cut == -1:
            cut = end
        chunks.append(text[pos:cut])
        pos = cut
    return chunks


def _plan_chunks(text: str, chunk_chars: int, max_chunks: int,
                 full_scan: bool) -> tuple[list[str], int, bool]:
    """(chunks_to_judge, unjudged_chars, tail_withheld)."""
    if not full_scan:
        head = text[:chunk_chars]
        return [head], len(text) - len(head), False
    chunks = _split_chunks(text, chunk_chars)
    tail_withheld = False
    if len(chunks) > max(1, int(max_chunks)):
        chunks = chunks[:max(1, int(max_chunks))]
        tail_withheld = True
    judged = sum(len(c) for c in chunks)
    return chunks, len(text) - judged, tail_withheld


def _edge_whitespace(chunk: str) -> tuple[str, str]:
    """The chunk's leading and trailing whitespace, which the model strips."""
    lead = chunk[:len(chunk) - len(chunk.lstrip())]
    trail = chunk[len(chunk.rstrip()):]
    return lead, trail


def _split_verdict_and_sanitized(raw: str) -> tuple[str, str]:
    """(verdict_line, sanitized_content). Shared with the chat-output path;
    the implementation lives in core.text_utils.split_marker."""
    return split_marker(raw, _SANITIZED_MARKER)


#: A redaction wildly longer than its input is a rewrite, not a redaction.
_REDACTION_GROWTH_LIMIT = REDACTION_GROWTH_LIMIT


def _usable_redaction(sanitized: str, original: str) -> tuple[bool, str]:
    """Whether a model-produced redaction may replace the original.

    Every rejection here escalates to block. That is the whole point: the defect
    being fixed is "we said redact and returned the original", so a lenient
    fallback would reintroduce it under a new name. If redaction was required
    and could not be produced, withholding is the only safe answer.
    Implementation shared with the chat-output path: core.text_utils.usable_redaction.
    """
    return usable_redaction(sanitized, original)


_SANITIZED_MARKER = SANITIZED_MARKER

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

        settings = self.settings
        chunk_chars = int(settings.get("judge_chunk_chars") or _DEFAULT_CHUNK_CHARS)
        max_chunks = int(settings.get("max_chunks") or _DEFAULT_MAX_CHUNKS)
        chunks, unjudged_chars, tail_withheld = _plan_chunks(
            tool_output, chunk_chars, max_chunks, _full_scan_enabled())

        # Prefill optimization: the static instruction + the tenant policy
        # text are stable across requests, so they go in the SYSTEM message
        # (vLLM prefix-caches it); only the variable tool output goes in the
        # user message. Same information, reordered so the policy block isn't
        # re-prefilled on every call. (Stable-prefix-first; see APC.)
        system_content = f"{_SYSTEM}\n\nData policies:\n{policies_text}"

        base_details = {
            "truncated": truncated,
            "tenant_id": tenant_id,
            "user_role": user_role,
            "unjudged_chars": unjudged_chars,
            "chunks": len(chunks),
            "tail_withheld": tail_withheld,
        }

        try:
            verdicts = await asyncio.gather(*[
                self._judge_chunk(system_content, tool_name, user_role,
                                  chunk, i, len(chunks))
                for i, chunk in enumerate(chunks)
            ])
        except Exception as e:
            logger.error(f"LLM output sanitization error: {e}")
            return GuardrailResult(
                passed=True, action="pass", guardrail_name=self.name,
                message=f"Output sanitization error: {e}",
                details={"error": str(e), "sanitized_output": tool_output, **base_details},
            )

        # Per-chunk confidence floor, then worst chunk wins, then the cap.
        # Same order the single-slice version applied to its one verdict.
        for v in verdicts:
            if v["confidence"] < 0.75:
                v["action"] = "allow"
        worst = max(verdicts, key=lambda v: _SEVERITY.get(v["action"], 0))
        action = worst["action"]
        confidence = worst["confidence"]
        flagged = [v["findings"] for v in verdicts
                   if v["findings"] and v["action"] != "allow"]
        findings = "; ".join(dict.fromkeys(flagged)) if flagged else worst["findings"]

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
                    "confidence": confidence,
                    **base_details,
                },
            )

        # `redact`/`mask` promise modified content. Produce it or withhold.
        if action in ("mask", "redact") and _redaction_enabled():
            parts: list[str] = []
            why = ""
            for v, chunk in zip(verdicts, chunks):
                if v["action"] in ("mask", "redact"):
                    ok, why = usable_redaction(v["sanitized"], chunk, v["finish_reason"])
                    if not ok:
                        break
                    lead, trail = _edge_whitespace(chunk)
                    parts.append(lead + v["sanitized"] + trail)
                else:
                    parts.append(chunk)
            if why:
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
                        "confidence": confidence,
                        "redaction_failed": why,
                        **base_details,
                    },
                )
            if tail_withheld:
                parts.append("\n" + _TAIL_WITHHELD)
            details = {
                "findings": findings,
                "sanitized_output": "".join(parts),
                "confidence": confidence,
                "redacted": True,
                **base_details,
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

        # An unjudged tail past the scan budget is withheld even when every
        # judged chunk was clean: returning it would deliver text no policy
        # ever saw.
        delivered = tool_output
        if tail_withheld:
            delivered = "".join(chunks) + "\n" + _TAIL_WITHHELD

        if action in ("mask", "redact", "warn", "log"):
            noun = {"mask": "Sensitive data partially masked in tool output",
                    "redact": "Sensitive data found in tool output",
                    "warn": "Sensitive data found in tool output (warn only)",
                    "log": "Sensitive data found in tool output (logged)"}[action]
            details = {
                "findings": findings,
                "sanitized_output": delivered,
                "confidence": confidence,
                **base_details,
            }
            if action == "mask":
                details["mask_level"] = "partial"
            return GuardrailResult(
                passed=False, action=action, guardrail_name=self.name,
                message=f"{noun}: {findings}", details=details,
            )

        if tail_withheld:
            return GuardrailResult(
                passed=False, action="warn", guardrail_name=self.name,
                message=(f"Tool output clean in the {len(chunks)} judged chunk(s); "
                         f"{unjudged_chars} unjudged character(s) withheld"),
                details={"sanitized_output": delivered, **base_details},
            )

        return GuardrailResult(
            passed=True, action="pass", guardrail_name=self.name,
            message="Tool output clean",
            details={"sanitized_output": tool_output, **base_details},
        )

    async def _judge_chunk(self, system_content: str, tool_name: str,
                           user_role: str, chunk: str, index: int, total: int) -> dict:
        """One model call over one chunk. Raises on transport or parse error;
        the caller decides what an error means for the whole payload."""
        part = f" (part {index + 1} of {total})" if total > 1 else ""
        user_content = (
            f"Tool: {tool_name}\n"
            f"User role: {user_role}\n\n"
            f"Tool output{part}:\n{chunk}"
        )
        llm_response = await async_llm_call(
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
            # Was 60: enough for a verdict, not for returned content. The
            # chunk is bounded by judge_chunk_chars, so this bounds the
            # redacted rendering of it.
            max_tokens=1200,
            temperature=0,
            guardrail_name="tool_output_sanitization",
        )
        choice = (llm_response.get("choices") or [{}])[0]
        raw = ((choice.get("message") or {}).get("content") or "").strip()
        verdict_line, sanitized_content = _split_verdict_and_sanitized(raw)
        result = parse_csv_response(verdict_line, _CSV_FIELDS)
        action = result.get("action", "allow")
        action = action.lower().strip() if isinstance(action, str) else "allow"
        return {
            "action": action,
            "confidence": safe_float(result.get("confidence"), 0.5),
            "findings": result.get("findings", "") or "",
            "sanitized": sanitized_content,
            # finish_reason=length means the SANITIZED line was cut, not
            # redacted; usable_redaction refuses it.
            "finish_reason": choice.get("finish_reason"),
        }

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
