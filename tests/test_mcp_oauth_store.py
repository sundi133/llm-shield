"""OAuth brokering state store (task 1 of docs/spec-mcp-oauth-brokering.md).

Brokering holds a long-lived delegation of a real upstream account, so the
security-relevant properties of this store get tests rather than comments:

  * no secret material is stored here — only vault references;
  * a pending authorization is single-use and TTL-bounded, which is the CSRF
    control for the callback;
  * tenancy is bound to the unguessable `state`, never to a query parameter.
"""

import json
import time
from unittest.mock import patch

import pytest

from storage import mcp_oauth_store as store

_PREFIX = "mcp_oauth:"


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIX)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


def _record(**over):
    rec = {
        "issuer": "https://mcp.higgsfield.ai",
        "token_endpoint": "https://mcp.higgsfield.ai/oauth2/token",
        "client_id": "abc",
        "scopes": ["openid", "email", "offline_access"],
        "access_token_ref": f"shield://{store.access_ref('higgsfield')}",
        "refresh_token_ref": f"shield://{store.refresh_ref('higgsfield')}",
        "status": store.STATUS_CONNECTED,
        "expires_at": int(time.time()) + 3600,
    }
    rec.update(over)
    return rec


# ── broker record ────────────────────────────────────────────────────


def test_set_get_delete():
    store.set_broker("acme", "higgsfield", _record())
    rec = store.get_broker("acme", "higgsfield")
    assert rec["client_id"] == "abc"
    assert rec["tenant_id"] == "acme" and rec["route"] == "higgsfield"

    assert store.delete_broker("acme", "higgsfield") is True
    assert store.delete_broker("acme", "higgsfield") is False
    assert store.get_broker("acme", "higgsfield") is None


def test_tenant_isolation():
    store.set_broker("a", "r", _record(client_id="for-a"))
    store.set_broker("b", "r", _record(client_id="for-b"))
    assert store.get_broker("a", "r")["client_id"] == "for-a"
    assert store.get_broker("b", "r")["client_id"] == "for-b"

    store.delete_broker("a", "r")
    assert store.get_broker("b", "r") is not None


def test_record_holds_references_not_secrets():
    """The whole point of splitting this from the vault: a Redis dump must not
    contain a usable credential."""
    store.set_broker("acme", "higgsfield", _record())
    raw = json.dumps(store.get_broker("acme", "higgsfield"))
    assert "shield://" in raw                    # references, yes
    for forbidden in ("access_token", "refresh_token", "client_secret"):
        # only *_ref keys may appear, never a bare token field
        assert f'"{forbidden}"' not in raw


def test_vault_refs_are_derived_from_the_route():
    """Derived, not free text, so a tampered record cannot point the refresh path
    at another route's secret."""
    assert store.access_ref("higgsfield") == "oauth-higgsfield-access"
    assert store.refresh_ref("higgsfield") == "oauth-higgsfield-refresh"
    assert store.client_secret_ref("higgsfield") == "oauth-higgsfield-client"
    assert store.access_ref("a") != store.access_ref("b")


def test_update_status_does_not_clobber_config():
    """The refresh loop records outcomes; it must not be able to lose the
    endpoints or vault refs while doing so."""
    store.set_broker("acme", "higgsfield", _record())
    out = store.update_status("acme", "higgsfield", store.STATUS_NEEDS_CONSENT,
                              error="invalid_grant")
    assert out["status"] == store.STATUS_NEEDS_CONSENT
    assert out["last_error"] == "invalid_grant"
    assert out["client_id"] == "abc"                  # config survived
    assert out["token_endpoint"].endswith("/oauth2/token")


def test_update_status_on_missing_record_returns_none():
    assert store.update_status("acme", "nope", store.STATUS_ERROR) is None


def test_mark_refreshed_sets_expiry_and_timestamp():
    store.set_broker("acme", "higgsfield", _record())
    future = int(time.time()) + 7200
    out = store.update_status("acme", "higgsfield", store.STATUS_CONNECTED,
                              expires_at=future, mark_refreshed=True)
    assert out["expires_at"] == future
    assert out["last_refresh_at"] > 0


# ── refresh scheduling ───────────────────────────────────────────────


def test_due_only_within_the_margin():
    now = 1_000_000
    assert store.due_for_refresh(_record(expires_at=now + 3600),
                                 margin_seconds=300, now=now) is False
    assert store.due_for_refresh(_record(expires_at=now + 120),
                                 margin_seconds=300, now=now) is True
    assert store.due_for_refresh(_record(expires_at=now - 10),
                                 margin_seconds=300, now=now) is True


def test_needs_consent_is_never_refreshed():
    """Retrying a revoked grant cannot recover it. A loop would hammer the
    provider and bury the one state a human has to act on."""
    now = 1_000_000
    rec = _record(status=store.STATUS_NEEDS_CONSENT, expires_at=now - 10)
    assert store.due_for_refresh(rec, margin_seconds=300, now=now) is False


@pytest.mark.parametrize("status", [store.STATUS_PENDING, store.STATUS_ERROR])
def test_only_connected_routes_are_refreshed(status):
    now = 1_000_000
    assert store.due_for_refresh(_record(status=status, expires_at=now - 10),
                                 margin_seconds=300, now=now) is False


def test_unknown_expiry_is_treated_as_due():
    """Refreshing on an unknown expiry is safer than assuming it is still valid."""
    rec = _record()
    rec.pop("expires_at")
    assert store.due_for_refresh(rec, margin_seconds=300, now=1_000_000) is True


def test_listing_is_derived_from_live_routes():
    """Derived from the gateway's route index, not a second index that could
    drift — a deleted route must stop being refreshed."""
    from storage import mcp_gateway_store as gstore

    with patch("storage.tenant_store._get_redis", return_value=None):
        for k in [k for k in gstore._fallback_store if k.startswith("mcp_gateway:")]:
            del gstore._fallback_store[k]
        gstore.set_upstream("acme", "higgsfield", {"route": "higgsfield"})
        gstore.set_upstream("acme", "plain", {"route": "plain"})
        store.set_broker("acme", "higgsfield", _record())

        assert store.list_brokered_routes("acme") == ["higgsfield"]

        gstore.delete_upstream("acme", "higgsfield")
        assert store.list_brokered_routes("acme") == []


# ── pending authorization: the CSRF control ──────────────────────────


def test_state_is_unguessable_and_unique():
    a, b = store.new_state(), store.new_state()
    assert a != b
    assert len(a) >= 40          # 32 bytes urlsafe-b64
    assert len(set(store.new_state() for _ in range(50))) == 50


def test_pending_round_trip_carries_tenant_and_verifier():
    s = store.new_state()
    store.put_pending(s, "acme", "higgsfield", "verifier123", "https://shield/cb")
    rec = store.take_pending(s)
    assert rec["tenant_id"] == "acme"
    assert rec["route"] == "higgsfield"
    assert rec["code_verifier"] == "verifier123"


def test_pending_is_single_use():
    """A leaked authorization code must not be replayable against a still-valid
    state."""
    s = store.new_state()
    store.put_pending(s, "acme", "higgsfield", "v", "https://shield/cb")
    assert store.take_pending(s) is not None
    assert store.take_pending(s) is None


def test_unknown_state_resolves_to_nothing():
    assert store.take_pending("fabricated") is None
    assert store.take_pending("") is None
    assert store.take_pending(None) is None


def test_expired_pending_is_rejected_even_without_redis_ttl():
    """Redis expires the key; the in-memory fallback cannot, so the timestamp is
    enforced in code. Otherwise dev mode would keep a replay window open forever."""
    s = store.new_state()
    store.put_pending(s, "acme", "higgsfield", "v", "https://shield/cb")

    from storage.tenant_store import _fallback_store
    key = f"mcp_oauth:pending:{s}"
    rec = json.loads(_fallback_store[key])
    rec["expires_at"] = int(time.time()) - 1
    _fallback_store[key] = json.dumps(rec)

    assert store.take_pending(s) is None


def test_taking_an_expired_state_still_deletes_it():
    """No accumulation of dead states, and no second chance at one."""
    s = store.new_state()
    store.put_pending(s, "acme", "higgsfield", "v", "https://shield/cb")
    from storage.tenant_store import _fallback_store
    key = f"mcp_oauth:pending:{s}"
    rec = json.loads(_fallback_store[key])
    rec["expires_at"] = int(time.time()) - 1
    _fallback_store[key] = json.dumps(rec)

    store.take_pending(s)
    assert key not in _fallback_store


def test_pending_ttl_is_bounded():
    assert 0 < store.PENDING_TTL_SECONDS <= 900
