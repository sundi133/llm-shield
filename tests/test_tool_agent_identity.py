"""Anti-spoof for the direct tool-check path (HR QA deep-rbac-009).

The direct /v1/shield/tool/check route trusted body.agent_key, so a caller
authenticated as agent A could put agent B in the body and borrow B's tool
permissions (the MCP path uses the X-Agent-Key header and blocked it). These
tests pin the reconciliation helper that closes that gap.
"""
from api.routes_tool import _reconcile_agent_identity


def test_mismatch_is_blocked():
    # deep-rbac-009: header agent != body agent -> impersonation
    err = _reconcile_agent_identity("people-ops-agent", "people-directory-agent")
    assert err is not None
    assert "mismatch" in err.lower()


def test_matching_identity_ok():
    assert _reconcile_agent_identity("people-ops-agent", "people-ops-agent") is None


def test_header_absent_preserves_body_only_flow():
    # legacy/legit callers that only send body.agent_key must still work
    assert _reconcile_agent_identity("", "people-ops-agent") is None


def test_body_absent_ok():
    assert _reconcile_agent_identity("people-ops-agent", "") is None


def test_whitespace_normalized_then_compared():
    # trailing space on the header alone should not create a false mismatch
    assert _reconcile_agent_identity("people-ops-agent ", "people-ops-agent") is None
    # but a genuinely different agent still mismatches even with padding
    assert _reconcile_agent_identity(" people-ops-agent ", "people-directory-agent") is not None
