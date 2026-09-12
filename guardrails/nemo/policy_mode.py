"""Nemotron custom-policy adjudication, shaped as each guardrail's verdict.

Task 4 of docs/spec-nemotron-guardrail-family.md.

One adapter class serves every policy-mode guardrail. What differs between them
is data, not behaviour: the policy text, and which key names their existing
`_CSV_FIELDS` use for "did it fire", "how sure", "what kind" and "how bad". So
`PolicyModeAdapter` takes a `VerdictShape` and the 19 registrations in
`prompts.py` are a table rather than 19 classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from guardrails.nemo import format as fmt
from guardrails.nemo.base import (
    parse_labelled_block,
    read_categories,
    read_safety_verdict,
    reasoning_enabled,
    severity_to_score,
    stamp_derived,
    strip_reasoning,
)


@dataclass(frozen=True)
class VerdictShape:
    """How one guardrail names the four things a verdict carries.

    `flag` is required; the rest are optional because not every guardrail has
    all four. Anything with no key configured is simply absent from the dict,
    which matches what `parse_csv_response` produces for a field the model
    omitted.
    """

    flag: str                                   # e.g. "is_toxic", "biased"
    score: Optional[str] = None                 # e.g. "bias_score", "confidence"
    kind: Optional[str] = None                  # e.g. "bias_type", "attack_type"
    severity: Optional[str] = None
    reason: Optional[str] = None
    # Some guardrails read the flag inverted: factual_grounding's "grounded"
    # and tone_enforcement's "compliant" are TRUE when nothing is wrong.
    invert: bool = False
    # Values for `kind` when the model reports nothing.
    kind_when_clean: str = "none"
    extras: dict = field(default_factory=dict)  # constant keys merged in


class PolicyModeAdapter:
    """Adjudicate against a policy, return one guardrail's verdict dict."""

    def __init__(
        self,
        policy: str,
        shape: VerdictShape,
        *,
        max_tokens: int = 96,
        reasoning: bool = False,
        content_key: Optional[str] = None,
        policy_from_settings: Optional[Callable[[dict], str]] = None,
    ):
        self.policy = policy
        self.shape = shape
        self.reasoning = reasoning
        # Reasoning traces need room. A trace truncated by max_tokens carries
        # no verdict at all (see strip_reasoning), so this is not a place to
        # economise.
        self._base_max_tokens = max_tokens
        self.content_key = content_key
        self.policy_from_settings = policy_from_settings

    @property
    def max_tokens(self) -> int:
        if self.reasoning and reasoning_enabled():
            return max(self._base_max_tokens, 512)
        return self._base_max_tokens

    # ── request ─────────────────────────────────────────────────────────

    def _system(self, settings: Optional[dict]) -> str:
        policy = self.policy
        if self.policy_from_settings and settings:
            policy = self.policy_from_settings(settings) or policy
        system = f"{fmt.POLICY_SYSTEM}\n\nPOLICY:\n{policy}"
        if self.reasoning and reasoning_enabled():
            system += fmt.POLICY_REASONING_SUFFIX
        return system

    def build_messages(
        self, content: str, context: Optional[dict] = None, settings: Optional[dict] = None
    ) -> list[dict]:
        context = context or {}
        history = context.get("history_messages") or []
        # A guardrail whose subject is not the bare `content` string (tool
        # output, a memory record, a reasoning trace) names the context key
        # holding it, so the adjudicator judges the right text.
        subject = content
        if self.content_key:
            supplied = context.get(self.content_key)
            if supplied:
                subject = supplied if isinstance(supplied, str) else str(supplied)

        messages: list[dict] = [{"role": "system", "content": self._system(settings)}]
        messages.extend(history)
        messages.append({"role": "user", "content": subject})
        return messages

    # ── response ────────────────────────────────────────────────────────

    def parse(self, raw: str) -> dict:
        verdict_text, trace = strip_reasoning(raw)
        block = parse_labelled_block(verdict_text)

        # Raises on an unusable verdict rather than defaulting to "nothing
        # found" — the whole reason this adapter layer is riskier than it
        # looks. See guardrails/nemo/base.read_safety_verdict.
        unsafe = read_safety_verdict(block, fmt.KEY_USER_SAFETY)
        categories = read_categories(block, fmt.KEY_CATEGORIES)
        severity = block.get(fmt.KEY_SEVERITY)
        shape = self.shape

        out: dict = dict(shape.extras)
        out[shape.flag] = (not unsafe) if shape.invert else unsafe

        if shape.score:
            out[shape.score] = severity_to_score(severity, unsafe=unsafe)
        if shape.kind:
            out[shape.kind] = (
                ", ".join(categories) if categories
                else (fmt.CATEGORY_UNSPECIFIED if unsafe else shape.kind_when_clean)
            )
        if shape.severity:
            out[shape.severity] = (severity or ("high" if unsafe else "none")).lower()
        if shape.reason:
            # The reasoning trace is the best available explanation; without
            # one, say what fired rather than leaving the field empty, since
            # several guardrails surface this string straight to the operator.
            out[shape.reason] = trace or (
                f"policy violation: {', '.join(categories)}" if categories
                else ("policy violation" if unsafe else "no policy violation found")
            )

        if shape.score:
            stamp_derived(out)
        return out


__all__ = ["PolicyModeAdapter", "VerdictShape"]
