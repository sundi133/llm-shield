"""Identity provenance for authorization decisions.

`resolve_identity()` must return exactly what the header-reading code returned —
it is a seam, not a behaviour change — while reporting where each value came
from. These tests pin both halves: the values (so nothing breaks) and the
sources (so the audit is truthful).
"""
from types import SimpleNamespace

import pytest

from core.identity import IdentityTuple
from core.identity_resolution import (
    SOURCE_AGENT_TOKEN, SOURCE_BODY, SOURCE_HEADER, SOURCE_NONE, SOURCE_OIDC,
    resolve_identity,
)


def _req(headers=None, identity=None):
    return SimpleNamespace(headers=headers or {}, state=SimpleNamespace(identity=identity))


def _tuple(agent_id="signed-bot", method="agent_token", trust="high"):
    return IdentityTuple(
        user_sub="u1", agent_id=agent_id, agent_instance_id="i1", tenant_id="t1",
        build_hash="b" * 64, model_version="m1", session_id="s1",
        trust_level=trust, identity_method=method,
    )


class TestValuesAreUnchanged:
    """The seam must not move any value the old code would have used."""

    def test_header_agent_and_role(self):
        r = resolve_identity(_req({"X-Agent-Key": "bot", "X-User-Role": "support"}))
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_body_wins_over_header_for_role(self):
        r = resolve_identity(_req({"X-User-Role": "from-header"}), body_user_role="from-body")
        assert r.user_role == "from-body"

    def test_lowercase_headers_resolve(self):
        r = resolve_identity(_req({"x-agent-key": "bot", "x-user-role": "support"}))
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_absent_is_empty_not_none(self):
        r = resolve_identity(_req())
        assert (r.agent_key, r.user_role) == ("", "")

    def test_whitespace_is_stripped(self):
        r = resolve_identity(_req(), body_agent_key="  bot  ", body_user_role="  support  ")
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_blank_body_falls_through_to_header(self):
        r = resolve_identity(_req({"X-User-Role": "support"}), body_user_role="   ")
        assert (r.user_role, r.role_source) == ("support", SOURCE_HEADER)


class TestProvenance:
    def test_header_role_is_marked_unverified(self):
        """The finding, pinned: nothing today carries a verified role claim."""
        r = resolve_identity(_req({"X-User-Role": "payments_officer"}))
        assert r.role_source == SOURCE_HEADER
        assert r.role_verified is False

    def test_body_role_is_also_unverified(self):
        r = resolve_identity(_req(), body_user_role="payments_officer")
        assert (r.role_source, r.role_verified) == (SOURCE_BODY, False)

    def test_verified_token_agent_outranks_headers(self):
        r = resolve_identity(
            _req({"X-Agent-Key": "spoofed"}, identity=_tuple(agent_id="signed-bot")),
            body_agent_key="also-spoofed",
        )
        assert r.agent_key == "signed-bot"
        assert (r.agent_source, r.agent_verified) == (SOURCE_AGENT_TOKEN, True)

    def test_oidc_identity_method_maps_to_oidc_source(self):
        r = resolve_identity(_req(identity=_tuple(method="oidc_sa")))
        assert (r.agent_source, r.agent_verified) == (SOURCE_OIDC, True)

    def test_identity_method_and_trust_are_carried(self):
        r = resolve_identity(_req(identity=_tuple(method="mtls", trust="high")))
        assert (r.identity_method, r.trust_level) == ("mtls", "high")

    def test_missing_values_report_none_source(self):
        r = resolve_identity(_req())
        assert (r.agent_source, r.role_source) == (SOURCE_NONE, SOURCE_NONE)


class TestAuditFields:
    def test_audit_carries_both_sources(self):
        r = resolve_identity(_req({"X-User-Role": "admin"}, identity=_tuple()))
        f = r.audit_fields()
        assert f["role_source"] == SOURCE_HEADER
        assert f["agent_source"] == SOURCE_AGENT_TOKEN
        assert f["role_verified"] is False and f["agent_verified"] is True

    def test_audit_fields_are_flat_and_serialisable(self):
        import json
        json.dumps(resolve_identity(_req()).audit_fields())


class TestRobustness:
    @pytest.mark.parametrize("req", [
        SimpleNamespace(),                                    # no headers, no state
        SimpleNamespace(headers={}),                          # no state
        SimpleNamespace(headers={}, state=SimpleNamespace()),  # state without identity
    ])
    def test_degenerate_requests_do_not_raise(self, req):
        """This sits on the guard path. It must never be the thing that 500s."""
        assert resolve_identity(req).agent_key == ""
