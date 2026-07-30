"""A data policy must judge only the tool it was written for.

Observed against a live tenant: `patient_lookup` (no policy of its own) was
denied with "role 'nurse' is explicitly blocked for patient lookup operations".
No such rule existed. The guard had loaded EVERY policy the tenant owned —
including `customer_profile.get` from an unrelated banking agent — and the LLM
generalised from rules written for a different tool.
"""

import json
from unittest.mock import patch

from guardrails.agentic.tool.payload_risk import (
    _format_data_policies, _load_data_policies)

_STORED = {
    "customer_profile.get": {
        "sanitization_rules": [],
        "role_policies": [{"role": "customer_support", "action": "block",
                           "input_rules": ["Block name-only lookup"]}],
    },
    "view_records": {"sanitization_rules": [], "role_policies": []},
}


class _Redis:
    def get(self, key):
        return json.dumps(_STORED) if key.endswith(":acme") else None


def _with_redis():
    return patch("storage.tenant_store._get_redis", return_value=_Redis())


def test_only_the_called_tools_policy_is_loaded():
    with _with_redis():
        got = _load_data_policies("acme", "view_records")
    assert [p["tool_name"] for p in got] == ["view_records"]


def test_a_tool_with_no_policy_gets_none_of_the_others():
    """The reported bug: patient_lookup has no policy and must inherit nothing."""
    with _with_redis():
        got = _load_data_policies("acme", "patient_lookup")
    assert got == []
    with _with_redis():
        text = _format_data_policies(None, "acme", "patient_lookup")
    assert "customer_profile" not in text
    assert "customer_support" not in text


def test_unscoped_load_still_returns_everything():
    """Callers that genuinely want the whole set are unchanged."""
    with _with_redis():
        got = _load_data_policies("acme")
    assert {p["tool_name"] for p in got} == set(_STORED)


def test_no_policy_text_does_not_invent_a_domain():
    """The old fallback told the LLM to apply "financial/banking" defaults,
    which is how a clinical tool was judged against banking norms."""
    with _with_redis():
        text = _format_data_policies(None, "acme", "patient_lookup")
    assert "financial" not in text.lower() and "banking" not in text.lower()
    assert "do not infer" in text.lower()


def test_no_policy_text_forbids_role_decisions():
    """rbac_guard already decided role->tool. This guard re-deciding it is how
    the portal could show a grant while the call was refused."""
    with _with_redis():
        text = _format_data_policies(None, "acme", "patient_lookup")
    assert "role decisions" in text.lower() or "authorization" in text.lower()


def test_the_matching_policy_is_still_applied():
    """Scoping must not turn the guard off for tools that DO have a policy."""
    with _with_redis():
        text = _format_data_policies(None, "acme", "customer_profile.get")
    assert "customer_profile.get" in text
    assert "customer_support" in text


def test_exact_match_only():
    with _with_redis():
        assert _load_data_policies("acme", "customer_profile") == []
        assert _load_data_policies("acme", "view_records_v2") == []
