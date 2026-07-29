"""Effective policy: profile <- route overrides, denormalized onto the route.

The guard path reads policy from the route document it already loads once per
call, so policy is computed on WRITE. That buys a free hot path and costs the
possibility of drift, which is why is_drifted() and the fan-out report exist.

Every per-control suite builds on what this produces.
"""

from unittest.mock import patch

import pytest

from storage import mcp_gateway_store as gstore
from storage import mcp_policy_store as store

_PREFIXES = ("mcp_profile:", "mcp_profiles:", "mcp_gateway:")


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIXES)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


def _route(route="higgsfield", **extra):
    cfg = {"route": route, "transport": "http", "url": "https://u/mcp"}
    cfg.update(extra)
    gstore.set_upstream("acme", route, cfg)
    return cfg


# ── merge semantics ──────────────────────────────────────────────────


def test_profile_only():
    prof = {"tools": {"allow": ["a"]}, "dlp": {"sanitize_as": "public"}}
    eff = store.compute_effective_policy(prof, None)
    assert eff["tools"]["allow"] == ["a"]
    assert eff["dlp"]["sanitize_as"] == "public"


def test_overrides_win_and_merge_deeply():
    """A route override must be able to change one nested key without having to
    restate the rest of the profile."""
    prof = {"dlp": {"sanitize_as": "public", "max_output_length": 100}}
    eff = store.compute_effective_policy(prof, {"dlp": {"sanitize_as": "admin"}})
    assert eff["dlp"]["sanitize_as"] == "admin"
    assert eff["dlp"]["max_output_length"] == 100  # untouched key survives


def test_profile_metadata_is_not_policy():
    """effective_policy carries policy only; profile bookkeeping would otherwise
    look like configuration to whatever reads it later."""
    prof = {"profile_id": "p", "tenant_id": "acme", "created_at": 1,
            "updated_at": 2, "rev": 3, "description": "x", "tools": {"allow": []}}
    eff = store.compute_effective_policy(prof, None)
    assert set(eff) == {"tools"}


def test_empty_inputs():
    assert store.compute_effective_policy(None, None) == {}
    assert store.compute_effective_policy(None, {"tools": {"allow": []}}) == {
        "tools": {"allow": []}}


def test_merge_matches_control_plane_semantics():
    """Coupling guard: this reuses agentic_control_plane._deep_merge so nested
    guardrail config composes identically in both places. If that private helper
    changes shape, this fails here rather than silently diverging."""
    from storage.agentic_control_plane import _deep_merge

    base = {"a": {"b": 1, "c": 2}, "d": 3}
    upd = {"a": {"b": 9}, "e": 4}
    assert store.compute_effective_policy(base, upd) == _deep_merge(base, upd)


# ── stamping onto a route ────────────────────────────────────────────


def test_stamp_sets_policy_and_rev():
    cfg = {"route": "r"}
    prof = {"rev": 7, "tools": {"allow": ["a"]}}
    out = store.stamp_effective_policy(cfg, prof, None)
    assert out["effective_policy"]["tools"]["allow"] == ["a"]
    assert out["effective_rev"] == 7
    assert "effective_policy" not in cfg  # pure; caller persists


def test_revision_is_a_counter_not_a_timestamp():
    """Two edits inside the same second must be distinguishable. A wall-clock
    revision has second granularity, so a stale route would look current — and
    it moves backwards under NTP correction."""
    first = store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    second = store.set_profile("acme", "p", {"tools": {"allow": ["b"]}})
    assert second["rev"] == first["rev"] + 1
    assert second["updated_at"] == first["updated_at"]  # same second, as expected

    cfg = store.stamp_effective_policy({"route": "r", "profile_id": "p"}, first, None)
    assert store.is_drifted(cfg, second) is True


def test_stamp_with_no_profile_yields_rev_zero():
    out = store.stamp_effective_policy({"route": "r"}, None, {"tools": {"allow": []}})
    assert out["effective_rev"] == 0
    assert out["effective_policy"] == {"tools": {"allow": []}}


# ── drift ────────────────────────────────────────────────────────────


def test_unbound_route_never_drifts():
    assert store.is_drifted({"route": "r"}, None) is False


def test_drift_when_rev_trails_profile():
    prof = store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    cfg = store.stamp_effective_policy({"route": "r", "profile_id": "p"}, prof, None)
    assert store.is_drifted(cfg, prof) is False

    newer = store.set_profile("acme", "p", {"tools": {"allow": ["a", "b"]}})
    assert store.is_drifted(cfg, newer) is True


def test_bound_route_with_vanished_profile_is_drifted():
    """Its stored policy has no source any more — that is exactly the state a
    reconciler needs to see, not a silent pass."""
    assert store.is_drifted({"route": "r", "profile_id": "gone"}, None) is True


# ── recompute + fan-out ──────────────────────────────────────────────


def test_recompute_route_refreshes_from_current_profile():
    prof = store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    _route("higgsfield", profile_id="p")
    store.bind_route("acme", "p", "higgsfield")

    out = store.recompute_route("acme", "higgsfield")
    assert out["effective_policy"]["tools"]["allow"] == ["a"]
    assert out["effective_rev"] == prof["rev"]
    assert gstore.get_upstream("acme", "higgsfield")["effective_rev"] == prof["rev"]


def test_recompute_applies_route_overrides():
    store.set_profile("acme", "p", {"dlp": {"sanitize_as": "public"}})
    _route("vendor-x", profile_id="p", overrides={"dlp": {"sanitize_as": "admin"}})
    out = store.recompute_route("acme", "vendor-x")
    assert out["effective_policy"]["dlp"]["sanitize_as"] == "admin"


def test_recompute_missing_route_returns_none():
    assert store.recompute_route("acme", "nope") is None


def test_recompute_keeps_last_policy_when_profile_vanished():
    """Dropping a bound route to no policy because its profile disappeared would
    silently loosen it; keep the last known-good and let drift report it."""
    prof = store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    _route("r", profile_id="p")
    store.recompute_route("acme", "r")
    store.delete_profile("acme", "p")

    out = store.recompute_route("acme", "r")
    assert out["effective_policy"]["tools"]["allow"] == ["a"]
    assert store.is_drifted(out, None) is True


def test_fanout_updates_every_bound_route():
    store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    for r in ("higgsfield", "vendor-x"):
        _route(r, profile_id="p")
        store.bind_route("acme", "p", r)

    newer = store.set_profile("acme", "p", {"tools": {"allow": ["a", "b"]}})
    report = store.fanout_profile("acme", "p")

    assert sorted(report["updated"]) == ["higgsfield", "vendor-x"]
    for r in ("higgsfield", "vendor-x"):
        cfg = gstore.get_upstream("acme", r)
        assert cfg["effective_policy"]["tools"]["allow"] == ["a", "b"]
        assert store.is_drifted(cfg, newer) is False


def test_fanout_reports_deleted_route_instead_of_raising():
    """One bad route must not abort the rest of the fleet."""
    store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    _route("live", profile_id="p")
    store.bind_route("acme", "p", "live")
    store.bind_route("acme", "p", "ghost")  # indexed but never created

    report = store.fanout_profile("acme", "p")
    assert report["updated"] == ["live"]
    assert report["missing"] == ["ghost"]
    assert report["failed"] == []


def test_fanout_ignores_other_tenants():
    store.set_profile("acme", "p", {"tools": {"allow": ["a"]}})
    store.set_profile("other", "p", {"tools": {"allow": ["z"]}})
    gstore.set_upstream("other", "r", {"route": "r", "transport": "http",
                                       "url": "u", "profile_id": "p"})
    store.bind_route("other", "p", "r")

    assert store.fanout_profile("acme", "p")["updated"] == []
    assert "effective_policy" not in gstore.get_upstream("other", "r")
