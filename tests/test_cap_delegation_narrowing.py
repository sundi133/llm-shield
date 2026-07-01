"""Delegation narrowing: parent → child capability enforcement.

Spec: docs/specs/cap-delegation-narrowing.md

CRITICAL direction note: cap `scope` entries are CONSTRAINTS, so a narrower
child carries MORE constraints — the invariant is
    set(parent.scope) ⊆ set(child.scope)
The first two tests lock that direction in; if someone "fixes" the check to
the OAuth-permissions direction (child ⊆ parent), they fail loudly.
"""

import time

import pytest
from fastapi import HTTPException

from core.capabilities import (
    MAX_DELEGATED_SCOPE_ENTRIES,
    CapabilityError,
    CapClaims,
    clear_nonce_store_for_tests,
    delegation_narrowing_mode,
    get_cap_signer,
    mint_cap,
    reset_cap_signer_cache_for_tests,
    verify_cap,
    _expected_cap_audience,
    _expected_cap_issuer,
)
from core.identity import IdentityTuple
from core.jwt_utils import encode_jwt
from storage.revocation import clear_all_for_tests, revoke_jti


@pytest.fixture
def identity():
    return IdentityTuple(
        user_sub="user-1",
        agent_id="billing-bot",
        agent_instance_id="inst-1",
        tenant_id="t1",
        build_hash="b",
        model_version="m",
        session_id="s",
    )


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_CAP_DELEGATION_NARROWING", raising=False)
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    yield
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()


def _mint_parent(identity, scope=("limit:10", "region:eu"),
                 clearance="confidential", ttl=30):
    token = mint_cap(
        identity=identity, tool="orchestrate", resource="task/1",
        scope=list(scope), clearance_max=clearance, ttl_seconds=ttl,
    )
    return token, verify_cap(token, expected_tool="orchestrate", burn_nonce=False)


def _forge_delegated_cap(identity, *, scope, parent_scope):
    """Hand-sign a delegated cap that BYPASSES mint_cap's narrowing — the
    verify-time backstop must catch it (guards future mint sites)."""
    signer = get_cap_signer()
    now = int(time.time())
    claims = {
        "iss": _expected_cap_issuer(),
        "aud": _expected_cap_audience(),
        "user_sub": identity.user_sub,
        "agent_id": identity.agent_id,
        "agent_instance_id": identity.agent_instance_id,
        "tenant_id": identity.tenant_id,
        "tool": "send_email",
        "resource": "user/1/inbox",
        "scope": list(scope),
        "clearance_max": "public",
        "nonce": "n-forged",
        "iat": now,
        "exp": now + 30,
        "cap_id": "cap-forged",
        "parent_cap_id": "cap-parent",
        "parent_scope": list(parent_scope),
        "kid": signer.kid,
    }
    return encode_jwt(claims, signer)


# ── Direction lock-in ─────────────────────────────────────────────────────


class TestNarrowingDirection:
    def test_child_with_all_parent_constraints_passes(self, identity):
        _, parent = _mint_parent(identity)
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            scope=["to:ops@corp"], parent_claims=parent,
        )
        claims = verify_cap(child, expected_tool="send_email")
        # union: own constraint + ALL parent constraints
        assert set(parent.scope).issubset(set(claims.scope))
        assert "to:ops@corp" in claims.scope
        assert claims.parent_scope == parent.scope

    def test_dropped_parent_constraint_rejected_by_backstop(self, identity):
        forged = _forge_delegated_cap(
            identity, scope=["limit:10"], parent_scope=["limit:10", "region:eu"],
        )
        with pytest.raises(CapabilityError, match="narrowing violated"):
            verify_cap(forged, expected_tool="send_email")

    def test_superset_child_passes_backstop(self, identity):
        ok = _forge_delegated_cap(
            identity,
            scope=["limit:10", "region:eu", "extra:x"],
            parent_scope=["limit:10", "region:eu"],
        )
        claims = verify_cap(ok, expected_tool="send_email")
        assert claims.parent_scope == ["limit:10", "region:eu"]


# ── Mint-time narrowing math ──────────────────────────────────────────────


class TestMintNarrowing:
    def test_clearance_clamped_to_parent(self, identity):
        _, parent = _mint_parent(identity, clearance="internal")
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            clearance_max="restricted", parent_claims=parent,
        )
        claims = verify_cap(child, expected_tool="send_email")
        assert claims.clearance_max == "internal"

    def test_clearance_below_parent_kept(self, identity):
        _, parent = _mint_parent(identity, clearance="confidential")
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            clearance_max="public", parent_claims=parent,
        )
        assert verify_cap(child, expected_tool="send_email").clearance_max == "public"

    def test_exp_clamped_to_parent(self, identity):
        _, parent = _mint_parent(identity, ttl=5)
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            ttl_seconds=60, parent_claims=parent,
        )
        claims = verify_cap(child, expected_tool="send_email")
        assert claims.exp <= parent.exp

    def test_expired_parent_rejected(self, identity):
        _, parent = _mint_parent(identity)
        dead = CapClaims(**{**parent.__dict__, "exp": int(time.time()) - 5})
        with pytest.raises(CapabilityError, match="already expired"):
            mint_cap(
                identity=identity, tool="send_email", resource="user/1/inbox",
                parent_claims=dead,
            )

    def test_scope_union_dedups_stably(self, identity):
        _, parent = _mint_parent(identity, scope=("a", "b"))
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            scope=["b", "c"], parent_claims=parent,
        )
        claims = verify_cap(child, expected_tool="send_email")
        assert claims.scope == ["b", "c", "a"]  # requested order, then parent

    def test_scope_union_overflow_rejected(self, identity):
        big = tuple(f"c:{i}" for i in range(MAX_DELEGATED_SCOPE_ENTRIES))
        _, parent = _mint_parent(identity, scope=big)
        with pytest.raises(CapabilityError, match="exceeds"):
            mint_cap(
                identity=identity, tool="send_email", resource="user/1/inbox",
                scope=["one-more"], parent_claims=parent,
            )

    def test_parent_cap_id_stamped(self, identity):
        _, parent = _mint_parent(identity)
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            parent_claims=parent,
        )
        assert verify_cap(child, expected_tool="send_email").parent_cap_id == parent.cap_id

    def test_empty_parent_scope_is_valid(self, identity):
        _, parent = _mint_parent(identity, scope=())
        child = mint_cap(
            identity=identity, tool="send_email", resource="user/1/inbox",
            scope=["x"], parent_claims=parent,
        )
        claims = verify_cap(child, expected_tool="send_email")
        assert claims.scope == ["x"] and claims.parent_scope == []


# ── Legacy / regression ───────────────────────────────────────────────────


class TestLegacyUnaffected:
    def test_non_delegated_token_has_no_parent_scope(self, identity):
        cap = mint_cap(identity=identity, tool="send_email", resource="r")
        claims = verify_cap(cap, expected_tool="send_email")
        assert claims.parent_scope is None
        assert claims.parent_cap_id is None

    def test_bare_parent_cap_id_passthrough_still_works(self, identity):
        cap = mint_cap(
            identity=identity, tool="send_email", resource="r",
            parent_cap_id="legacy-id",
        )
        claims = verify_cap(cap, expected_tool="send_email")
        assert claims.parent_cap_id == "legacy-id"
        assert claims.parent_scope is None  # backstop stays disarmed

    def test_delegation_does_not_burn_parent_nonce(self, identity):
        token, parent = _mint_parent(identity)
        # _mint_parent already verified once with burn_nonce=False; the
        # parent must still be executable exactly once...
        assert verify_cap(token, expected_tool="orchestrate").cap_id == parent.cap_id
        # ...and replay-protected afterwards.
        with pytest.raises(CapabilityError, match="replay"):
            verify_cap(token, expected_tool="orchestrate")


# ── Route helper: _resolve_parent_delegation ──────────────────────────────


def _mk_body(parent_token, **kw):
    from api.routes_agent_auth import CapMintRequest
    return CapMintRequest(
        tool="send_email", resource="user/1/inbox",
        parent_cap_token=parent_token, **kw,
    )


class TestRouteDelegation:
    def test_enforce_valid_parent(self, identity):
        from api.routes_agent_auth import _resolve_parent_delegation
        token, parent = _mint_parent(identity)
        pc, pid, extras = _resolve_parent_delegation(identity, _mk_body(token))
        assert pc is not None and pc.cap_id == parent.cap_id
        assert pid is None
        assert extras.get("delegated") is True

    def test_revoked_parent_403(self, identity):
        from api.routes_agent_auth import _resolve_parent_delegation
        token, parent = _mint_parent(identity)
        revoke_jti(parent.cap_id)
        with pytest.raises(HTTPException) as ei:
            _resolve_parent_delegation(identity, _mk_body(token))
        assert ei.value.status_code == 403

    def test_identity_mismatch_403(self, identity):
        from api.routes_agent_auth import _resolve_parent_delegation
        token, _ = _mint_parent(identity)
        other = IdentityTuple(
            user_sub="mallory", agent_id="billing-bot", agent_instance_id="i2",
            tenant_id="t1", build_hash="b", model_version="m", session_id="s",
        )
        with pytest.raises(HTTPException) as ei:
            _resolve_parent_delegation(other, _mk_body(token))
        assert ei.value.status_code == 403

    def test_cross_tenant_403(self, identity):
        from api.routes_agent_auth import _resolve_parent_delegation
        token, _ = _mint_parent(identity)
        other_tenant = IdentityTuple(
            user_sub="user-1", agent_id="billing-bot", agent_instance_id="i2",
            tenant_id="t2", build_hash="b", model_version="m", session_id="s",
        )
        with pytest.raises(HTTPException) as ei:
            _resolve_parent_delegation(other_tenant, _mk_body(token))
        assert ei.value.status_code == 403

    def test_malformed_parent_400(self, identity):
        from api.routes_agent_auth import _resolve_parent_delegation
        with pytest.raises(HTTPException) as ei:
            _resolve_parent_delegation(identity, _mk_body("not-a-jwt"))
        assert ei.value.status_code == 400

    def test_warn_mode_verifies_but_does_not_narrow(self, identity, monkeypatch):
        from api.routes_agent_auth import _resolve_parent_delegation
        monkeypatch.setenv("SHIELD_CAP_DELEGATION_NARROWING", "warn")
        token, parent = _mint_parent(identity)
        pc, pid, extras = _resolve_parent_delegation(identity, _mk_body(token))
        assert pc is None                       # no narrowing applied
        assert pid == parent.cap_id             # linkage still stamped
        assert extras["narrowing_applied"] is False
        assert set(extras["would_add_constraints"]) == set(parent.scope)
        # invalid parent still rejects in warn mode
        revoke_jti(parent.cap_id)
        with pytest.raises(HTTPException):
            _resolve_parent_delegation(identity, _mk_body(token))

    def test_off_mode_passthrough(self, identity, monkeypatch):
        from api.routes_agent_auth import _resolve_parent_delegation
        monkeypatch.setenv("SHIELD_CAP_DELEGATION_NARROWING", "off")
        token, parent = _mint_parent(identity)
        revoke_jti(parent.cap_id)  # off mode verifies NOTHING (escape hatch)
        pc, pid, extras = _resolve_parent_delegation(identity, _mk_body(token))
        assert pc is None and pid == parent.cap_id and extras == {}


class TestFlag:
    def test_default_is_enforce(self, monkeypatch):
        monkeypatch.delenv("SHIELD_CAP_DELEGATION_NARROWING", raising=False)
        assert delegation_narrowing_mode() == "enforce"

    def test_invalid_value_falls_back_to_enforce(self, monkeypatch):
        monkeypatch.setenv("SHIELD_CAP_DELEGATION_NARROWING", "banana")
        assert delegation_narrowing_mode() == "enforce"

    def test_modes_parse(self, monkeypatch):
        for m in ("enforce", "warn", "off"):
            monkeypatch.setenv("SHIELD_CAP_DELEGATION_NARROWING", m.upper())
            assert delegation_narrowing_mode() == m
