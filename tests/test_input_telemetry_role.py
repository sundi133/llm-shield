"""Input-guardrail telemetry must record the caller's role and its provenance.

Reported from the console: every /guardrails/input row read "role unavailable",
even with a verified OIDC claim on the request.

Cause: the telemetry took `request.state.role_name`, which middleware sets from
`enforcer.resolve_role(agent_key)` — the STATIC rbac config's agent->role map. An
agent registered in the tenant registry (not that config) resolves to None, so the
role was dropped from every input decision. The tool path never had this problem
because it uses core.identity_resolution.

The activity log is the audit trail, so a missing role is not cosmetic: it makes
"what did nurses submit?" unanswerable.
"""

from unittest.mock import patch

import api.routes_classify as rc


class _Req:
    def __init__(self, headers=None, state=None):
        self.headers = headers or {}
        self.state = state or type("S", (), {})()


def test_resolution_uses_the_shared_seam_not_state_role_name():
    """The regression guard. If someone reverts to request.state.role_name, an
    agent outside the static rbac config silently loses its role again."""
    called = {}

    def _fake(request, **kw):
        called["hit"] = True
        return type("R", (), {"user_role": "nurse", "role_source": "oidc",
                              "identity_method": "oidc_sa"})()

    with patch("core.identity_resolution.resolve_identity", _fake):
        ident = rc._resolve_request_identity(_Req(), {})
    assert called.get("hit") is True
    assert ident.user_role == "nurse"
    assert ident.role_source == "oidc"


def test_body_fields_are_forwarded():
    """A caller may assert its role in the body rather than a header; the seam
    handles precedence, but only if the values reach it."""
    seen = {}

    def _fake(request, **kw):
        seen.update(kw)
        return type("R", (), {"user_role": "", "role_source": "none",
                              "identity_method": ""})()

    with patch("core.identity_resolution.resolve_identity", _fake):
        rc._resolve_request_identity(_Req(), {"agent_key": "a1", "user_role": "nurse"})
    assert seen["body_agent_key"] == "a1"
    assert seen["body_user_role"] == "nurse"


def test_telemetry_failure_cannot_break_a_guardrail_check():
    """Logging is a side effect. A request that already passed must not 500
    because provenance could not be resolved."""
    with patch("core.identity_resolution.resolve_identity",
               side_effect=RuntimeError("identity backend down")):
        ident = rc._resolve_request_identity(_Req(), {})
    assert ident.user_role == ""
    assert ident.role_source == "none"      # honest absence, not a guess


def test_missing_body_is_tolerated():
    """The file endpoint has no JSON body at all."""
    with patch("core.identity_resolution.resolve_identity",
               lambda request, **kw: type("R", (), {
                   "user_role": "doctor", "role_source": "agent_token",
                   "identity_method": "agent_token"})()):
        assert rc._resolve_request_identity(_Req()).user_role == "doctor"


def test_both_endpoints_record_role_and_provenance():
    """Pinning the two call sites: the file path previously hardcoded ''.

    Originally this grepped for two literal "role_source" keys. Both were
    later replaced by `**identity.audit_fields()`, which emits role_source
    along with acting_for, delegation_verified and the rest — a superset. The
    assertion moved with it: what matters is that both paths spread the full
    provenance set, not that a particular key is typed out.
    """
    src = open(rc.__file__).read()
    assert src.count("audit_fields()") >= 2, (
        "both the JSON and file paths must record the full provenance set")
    assert '"user_role": _file_identity.user_role or ""' in src
    assert '"user_role": ""' not in src, "a path is still hardcoding an empty role"


def test_provenance_set_still_carries_what_the_literals_did():
    """The superset claim, checked rather than asserted in a comment.

    If audit_fields ever stops emitting role_source or identity_method, the
    telemetry regression this file exists to prevent comes back silently —
    the grep above would still pass.
    """
    from core.identity_resolution import ResolvedIdentity
    fields = ResolvedIdentity().audit_fields()
    for key in ("role_source", "identity_method", "acting_for",
                "delegation_verified"):
        assert key in fields, f"audit_fields no longer emits {key}"
