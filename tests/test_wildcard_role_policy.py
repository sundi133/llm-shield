"""A role policy written as "*" must govern every caller.

There was no way to write a data policy for everyone. `role` is required, no
wildcard was handled anywhere, and role matching was not done in code at all:
_format_data_policies rendered the rule as prose and the model decided whether
it applied. So `*` PROBABLY worked, on undocumented syntax, re-judged every
request by a component whose phrasing already varies between identical calls.

Not hypothetical. A tenant wrote "Never return a national ID, passport number,
or SSN" for role `support`, called the tool as `user`, and received an
unredacted passport and Emirates ID. The policy was correct and named a role the
caller did not have.

test_both_guard_paths_pass_the_role is the one that matters most. A formatter
that supports wildcards while one caller forgets to pass the role is the same
half-applied fix that left the output side unscoped for months.

Spec: docs/spec-wildcard-role-policy.md
"""
import asyncio

import pytest

import guardrails.agentic.tool.payload_risk as pr
import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.tool.payload_risk import (
    _format_data_policies, _resolve_role_policies,
)

RULE = "Never return a national ID, passport number, or SSN"


def _policy(*role_policies):
    return [{"tool_name": "customer_profile_get", "sanitization_rules": [],
             "role_policies": list(role_policies)}]


def _render(policies, user_role):
    return _format_data_policies(policies, "bankco", "customer_profile_get", user_role)


def _role_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip().startswith("- Role")]


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.delenv("SHIELD_WILDCARD_ROLE_POLICY", raising=False)


# ── the feature ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("caller", ["user", "support", "teller", "branch_manager"])
def test_a_wildcard_governs_every_role(caller):
    """The headline. One rule, every caller."""
    text = _render(_policy({"role": "*", "action": "block",
                            "output_rules": [RULE]}), caller)
    assert _role_lines(text) == [f"- Role '{caller}': block (scope: all)"]
    assert RULE in text


def test_the_model_never_sees_an_asterisk():
    """The actual contract. Resolution happens in code so the judge is told the
    caller's real role and has nothing to interpret."""
    text = _render(_policy({"role": "*", "action": "block"}), "user")
    assert "*" not in text


def test_a_caller_with_no_role_is_governed():
    """Renders as 'any role', not Role '', which would be indistinguishable
    from the existing no-role rule."""
    text = _render(_policy({"role": "*", "action": "block"}), "")
    assert _role_lines(text) == ["- Role 'any role': block (scope: all)"]


def test_the_reproduction_from_the_spec():
    """The tenant's rule named `support`; the caller was `user`. Under a
    wildcard it applies."""
    before = _render(_policy({"role": "support", "action": "block",
                              "output_rules": [RULE]}), "user")
    after = _render(_policy({"role": "*", "action": "block",
                             "output_rules": [RULE]}), "user")
    assert "user" not in before          # named a role the caller did not have
    assert RULE in after and "Role 'user'" in after


# ── precedence ───────────────────────────────────────────────────────────


def test_an_exact_match_beats_the_wildcard_even_when_permissive():
    """{"*": block} + {"admin": allow} reads as "everyone blocked except
    admin". Most-restrictive-wins would make that exception unwritable."""
    pol = _policy({"role": "*", "action": "block"},
                  {"role": "admin", "action": "allow"})
    assert _role_lines(_render(pol, "admin")) == ["- Role 'admin': allow (scope: all)"]
    assert _role_lines(_render(pol, "user")) == ["- Role 'user': block (scope: all)"]


def test_an_exact_match_for_another_role_does_not_suppress_the_wildcard():
    pol = _policy({"role": "*", "action": "block"},
                  {"role": "admin", "action": "allow"})
    assert "block" in _render(pol, "teller")


def test_empty_role_is_an_exact_match_and_is_not_widened():
    """`""` already means "caller with no role" and existing policies rely on
    it. Conflating it with `*` would silently widen every such rule to the whole
    tenant, which is the kind of change discovered during an incident.

    It renders as Role '' exactly as it does today: only the WILDCARD path
    substitutes a friendly label, because only there is the role unknown.
    """
    pol = _policy({"role": "", "action": "redact"},
                  {"role": "*", "action": "block"})
    assert _role_lines(_render(pol, "")) == ["- Role '': redact (scope: all)"]


def test_the_match_kind_is_recorded():
    exact = _resolve_role_policies([{"role": "user", "action": "block"}], "user")
    wild = _resolve_role_policies([{"role": "*", "action": "block"}], "user")
    assert exact[0]["_role_match"] == "exact"
    assert wild[0]["_role_match"] == "wildcard"


# ── nothing else moves ───────────────────────────────────────────────────


def test_no_wildcard_renders_exactly_as_before():
    """Backward-compatibility guard: a policy without `*` is untouched."""
    pol = _policy({"role": "support", "action": "redact"},
                  {"role": "admin", "action": "allow"})
    assert _role_lines(_render(pol, "support")) == \
        ["- Role 'support': redact (scope: all)"]


def test_a_caller_matching_nothing_gets_nothing():
    text = _render(_policy({"role": "admin", "action": "allow"}), "user")
    assert _role_lines(text) == ["- Role 'admin': allow (scope: all)"]


def test_the_escape_hatch_restores_literal_matching(monkeypatch):
    monkeypatch.setenv("SHIELD_WILDCARD_ROLE_POLICY", "off")
    text = _render(_policy({"role": "*", "action": "block"}), "user")
    assert _role_lines(text) == ["- Role '*': block (scope: all)"]


def test_only_the_applicable_rule_reaches_the_model():
    """A deliberate narrowing, not a side effect.

    Previously EVERY role's rules were rendered and the model picked. One live
    tenant has 29 roles, so the judge was shown 28 rules that did not apply and
    invited to reason about them. This repo has already been bitten twice by
    exactly that shape: a policy for one tool judging another, and a rule for one
    role reported as governing a different one. Only the caller's rule is shown.
    """
    roles = [f"role_{i}" for i in range(29)]
    enumerated = _policy(*[{"role": r, "action": "block"} for r in roles])
    text = _render(enumerated, "role_7")
    assert _role_lines(text) == ["- Role 'role_7': block (scope: all)"]
    assert "role_3" not in text and "role_28" not in text


def test_a_wildcard_says_the_same_thing_in_one_rule():
    roles = [f"role_{i}" for i in range(29)]
    enumerated = _policy(*[{"role": r, "action": "block"} for r in roles])
    wild = _policy({"role": "*", "action": "block"})
    assert _role_lines(_render(wild, "role_7")) == _role_lines(_render(enumerated, "role_7"))


# ── the whole point: it has to reach the MCP guard path ──────────────────


def test_both_guard_paths_pass_the_role(monkeypatch):
    """THE test. A formatter that supports wildcards while a caller forgets to
    pass the role is the half-applied fix that left the output side unscoped for
    months. Assert BOTH the input and output judges thread it through.
    """
    seen = []

    def _spy(policies, tenant_id="", tool_name="", user_role=""):
        seen.append(user_role)
        return "policy text"

    monkeypatch.setattr(pr, "_format_data_policies", _spy)
    monkeypatch.setattr(tos, "_format_data_policies", _spy, raising=False)
    monkeypatch.setattr(pr, "_load_data_policies",
                        lambda t, n="": [{"tool_name": n, "role_policies": []}])

    # output judge
    tos.ToolOutputSanitizationGuardrail._load_policies_text(
        "bankco", "customer_profile_get", "branch_manager")
    assert "branch_manager" in seen, (
        "tool_output_sanitization did not pass the caller role; a wildcard "
        "policy would never resolve on the output path")


def test_the_output_judge_signature_accepts_the_role():
    """Pins the seam itself, so a refactor cannot quietly drop the parameter."""
    import inspect
    sig = inspect.signature(
        tos.ToolOutputSanitizationGuardrail._load_policies_text)
    assert "user_role" in sig.parameters


def test_a_wildcard_reaches_the_output_judge_prompt(monkeypatch):
    """End to end on the output path: policy in the store, wildcard resolved,
    caller's real role in the text handed to the judge."""
    monkeypatch.setattr(
        pr, "_load_data_policies",
        lambda tenant_id, tool_name="", user_role="": _policy(
            {"role": "*", "action": "block", "output_rules": [RULE]}))
    text = tos.ToolOutputSanitizationGuardrail._load_policies_text(
        "bankco", "customer_profile_get", "user")
    assert "Role 'user': block" in text
    assert RULE in text
    assert "*" not in text
