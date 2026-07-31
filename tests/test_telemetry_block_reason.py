"""The audit trail must name the guardrail that denied, not the first one that ran.

Observed in the console: a tool call BLOCKED by tool_call_validation recorded
"RBAC check passed" as its Block Reason, because the code took results[0] and
rbac_guard happens to run first.
"""

from api.routes_tool import _first_denial


class _R:
    def __init__(self, passed, message):
        self.passed, self.message = passed, message


def test_reports_the_denying_guardrail_not_the_first():
    results = [
        {"guardrail": "rbac_guard", "passed": True, "message": "RBAC check passed"},
        {"guardrail": "tool_allowlist", "passed": True, "message": "allowed"},
        {"guardrail": "tool_call_validation", "passed": False,
         "message": "Payload policy blocked 'view_records'"},
    ]
    assert _first_denial(results) == "Payload policy blocked 'view_records'"


def test_a_passing_message_is_never_the_block_reason():
    results = [{"guardrail": "rbac_guard", "passed": True, "message": "RBAC check passed"}]
    assert "passed" not in _first_denial(results).lower().replace("no failing", "")


def test_no_failing_guardrail_says_so_rather_than_guessing():
    assert "no failing guardrail" in _first_denial([])
    assert "no failing guardrail" in _first_denial(
        [{"guardrail": "x", "passed": True, "message": "fine"}])


def test_accepts_objects_as_well_as_dicts():
    assert _first_denial([_R(True, "ok"), _R(False, "denied by policy")]) == "denied by policy"


def test_first_of_several_denials_wins():
    results = [{"passed": False, "message": "first denial"},
               {"passed": False, "message": "second denial"}]
    assert _first_denial(results) == "first denial"
