"""Translate a natural-language custom policy into a Sigma rule (export only).

Sigma is deterministic and a natural-language policy is judged by an LLM, so
this is a best-effort approximation. The model is asked for structured terms
only (keywords and regex patterns, via a JSON schema); the rule itself is built
and validated deterministically by core.sigma_policy.nl_policy_to_rule, so a
model can never emit malformed Sigma. Invalid regexes are dropped.

Runs on the data plane (where the guardrail LLM is), from an admin-initiated
export request. It is never called on /guardrails/*, cap/mint or tools/call.
"""
from __future__ import annotations

import logging

import regex

from core.llm_backend import async_llm_call, parse_llm_json
from core.sigma_policy import nl_policy_to_rule

logger = logging.getLogger(__name__)

_SCHEMA = {
    "type": "object",
    "properties": {
        "keywords": {"type": "array", "items": {"type": "string"}},
        "patterns": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["keywords", "patterns"],
}

_MAX_TERMS = 25


def _prompt(policy: dict) -> str:
    return f"""Convert this content policy into detection terms for a Sigma rule.

POLICY NAME: {policy.get('name', '')}
POLICY DESCRIPTION: {policy.get('description', '')}
POLICY CRITERIA:
{policy.get('prompt', '')}

Return JSON with:
- "keywords": short literal phrases whose presence in a message indicates a violation
- "patterns": regular expressions for structured data the policy forbids
  (for example card numbers, account ids, API keys)
Only include terms that directly indicate a violation. Use [] when none apply."""


async def translate_nl_policy(policy: dict) -> dict:
    """Return a Sigma rule for a natural-language policy. Raises ValueError."""
    response = await async_llm_call(
        messages=[{"role": "user", "content": _prompt(policy)}],
        max_tokens=400,
        temperature=0,
        response_format=_SCHEMA,
        guardrail_name="custom_policy_sigma_export",
    )
    content = response["choices"][0]["message"]["content"]
    data = parse_llm_json(content) or {}

    keywords = [k for k in data.get("keywords") or [] if isinstance(k, str)][:_MAX_TERMS]
    patterns = []
    for p in (data.get("patterns") or [])[:_MAX_TERMS]:
        if not isinstance(p, str):
            continue
        try:
            regex.compile(p)
            patterns.append(p)
        except regex.error:
            logger.info("sigma export: dropping invalid pattern from translation: %r", p)

    return nl_policy_to_rule(policy, keywords, patterns)
