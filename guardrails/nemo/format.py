"""Every assumption about Nemotron's wire format, in one file.

These constants are taken from the model card, NOT from observed output.
`scripts/probe_nemo.py` (task 1 of docs/spec-nemotron-guardrail-family.md)
captures the real strings; when it runs, correcting the format means editing
this file and nothing else.

Keys are compared after `parse_labelled_block` lowercases them and replaces
spaces with underscores, so ``User Safety:`` arrives as ``user_safety``.
"""

from __future__ import annotations

# ── labelled-block keys ─────────────────────────────────────────────────

KEY_USER_SAFETY = "user_safety"
KEY_RESPONSE_SAFETY = "response_safety"
KEY_CATEGORIES = "safety_categories"

# Not documented as always present. severity_to_score() falls back to the
# unsafe default when it is missing, so an absent severity never reads as safe.
KEY_SEVERITY = "severity"

CATEGORY_UNSPECIFIED = "unspecified"

# ── system prompts ──────────────────────────────────────────────────────

# The native moderation task. Kept minimal on purpose: the model is fine-tuned
# for this, and elaborate instructions mostly pull it off its trained
# behaviour.
SAFETY_SYSTEM = (
    "You are a content safety moderator. Classify the user message.\n"
    "Respond with:\n"
    "User Safety: safe or unsafe\n"
    "Safety Categories: comma-separated categories, or none\n"
    "Severity: none, low, medium, high, or critical"
)

# Custom-policy adjudication. The scan instruction is the same lesson as #378:
# a violation buried in a long multi-topic message is still a violation, and
# telling the model to weigh the message as a whole is what let a pricing
# disclosure through when an unrelated paragraph was prepended to it.
POLICY_SYSTEM = (
    "You are a policy adjudicator. Judge the text against the POLICY below.\n"
    "Read the ENTIRE text and judge each sentence against the policy on its "
    "own. A violation ANYWHERE makes the whole text a violation, even when it "
    "is a single clause inside a long message about something else. Do not "
    "weigh how routine the overall request seems, and do not let the opening "
    "sentences settle the verdict.\n"
    "Respond with:\n"
    "User Safety: safe or unsafe\n"
    "Safety Categories: the policy category you detected, or none\n"
    "Severity: none, low, medium, high, or critical"
)

POLICY_REASONING_SUFFIX = (
    "\nThink step by step inside <think></think> tags before answering."
)

__all__ = [
    "CATEGORY_UNSPECIFIED",
    "KEY_CATEGORIES",
    "KEY_RESPONSE_SAFETY",
    "KEY_SEVERITY",
    "KEY_USER_SAFETY",
    "POLICY_REASONING_SUFFIX",
    "POLICY_SYSTEM",
    "SAFETY_SYSTEM",
]
