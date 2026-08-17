"""Portal sessions: identify a human, and be able to sign them out.

Storage only — no routes, no OIDC. The two tests that justify the design over
a signed-JWT cookie are `test_revoke_all_for_subject_signs_them_out_everywhere`
and `test_an_expired_session_is_refused_without_redis_ttl`: the first is the
capability a stateless session cannot have, the second is why expiry lives in
the record rather than being delegated to the store.

`test_a_session_id_is_never_taken_from_the_caller` is the security invariant.

Spec: docs/spec-portal-sso.md PR 1
"""
import pytest

from storage import portal_sessions as ps, tenant_store as ts

TENANT = "acme"
OTHER = "globex"
CLAIMS = {"sub": "3f9c-dana", "email": "dana@acme.com", "name": "Dana Okoro",
          "issuer": "https://auth.acme.com/realms/acme"}


@pytest.fixture
def store(monkeypatch):
    """In-memory, no Redis — the worst case for anything expiry-related,
    because the fallback has no TTL of its own."""
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.delenv("SHIELD_PORTAL_SESSION_TTL", raising=False)
    monkeypatch.delenv("SHIELD_PORTAL_SESSION_IDLE", raising=False)
    return data


@pytest.fixture
def clock(monkeypatch):
    """Movable time. Sessions are all about deadlines."""
    now = {"t": 1_800_000_000}
    monkeypatch.setattr(ps, "_now", lambda: now["t"])
    return now


# ── round trip ───────────────────────────────────────────────────────────


def test_create_and_read(store):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    s = ps.get_session(sid)
    assert s["tenant_id"] == TENANT
    assert s["sub"] == "3f9c-dana"
    assert s["email"] == "dana@acme.com"
    assert s["is_admin"] is True


def test_a_non_admin_session_says_so(store):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=False)
    assert ps.get_session(sid)["is_admin"] is False


def test_missing_email_and_name_are_not_fatal(store):
    """sub is the identifier. Email is a display convenience, and an IdP that
    does not release it must not break login."""
    sid = ps.create_session(TENANT, {"sub": "x"}, is_admin=False)
    s = ps.get_session(sid)
    assert s["sub"] == "x" and s["email"] == "" and s["name"] == ""


def test_unknown_session_is_none(store):
    assert ps.get_session("nope") is None


@pytest.mark.parametrize("bad", ["", None, 123, [], {}])
def test_garbage_session_ids_are_none_not_errors(store, bad):
    assert ps.get_session(bad) is None


# ── the security invariant ───────────────────────────────────────────────


def test_a_session_id_is_never_taken_from_the_caller():
    """Session fixation is impossible by construction: create_session accepts
    no id, so there is no parameter to smuggle one through."""
    import inspect
    sig = inspect.signature(ps.create_session)
    assert "session_id" not in sig.parameters
    assert set(sig.parameters) == {"tenant_id", "claims", "is_admin"}


def test_ids_are_unguessable_and_unique(store):
    ids = {ps.create_session(TENANT, CLAIMS, is_admin=True) for _ in range(20)}
    assert len(ids) == 20
    assert all(len(i) >= 40 for i in ids)


def test_a_session_without_a_subject_is_refused(store):
    """A session that identifies nobody is worse than no session, because it
    looks like attribution."""
    with pytest.raises(ValueError):
        ps.create_session(TENANT, {"sub": ""}, is_admin=True)
    with pytest.raises(ValueError):
        ps.create_session(TENANT, {}, is_admin=True)


def test_a_session_without_a_tenant_is_refused(store):
    with pytest.raises(ValueError):
        ps.create_session("", CLAIMS, is_admin=True)


# ── expiry ───────────────────────────────────────────────────────────────


def test_an_expired_session_is_refused_without_redis_ttl(store, clock):
    """The in-memory fallback has no expiry, so if correctness were delegated
    to the store a Redis-less deployment would honour a session forever."""
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += ps.session_ttl() + 1
    assert ps.get_session(sid) is None


def test_an_expired_session_is_deleted_on_read(store, clock):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += ps.session_ttl() + 1
    ps.get_session(sid)
    assert ts.kv_get("portalsession:" + sid) is None


def test_a_session_is_valid_right_up_to_its_deadline(store, clock):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += ps.session_ttl() - 1
    assert ps.get_session(sid) is not None


def test_ttl_is_configurable(store, monkeypatch):
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_TTL", "60")
    assert ps.session_ttl() == 60


@pytest.mark.parametrize("bad", ["", "abc", "-5", "0"])
def test_a_nonsense_ttl_falls_back_to_the_default(store, monkeypatch, bad):
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_TTL", bad)
    assert ps.session_ttl() == ps.DEFAULT_TTL_SECONDS


def test_an_absurd_ttl_is_capped(store, monkeypatch):
    """A tenant that sets a year has disabled session expiry while believing
    they configured it."""
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_TTL", str(365 * 24 * 3600))
    assert ps.session_ttl() == ps._MAX_TTL_SECONDS


# ── idle timeout ─────────────────────────────────────────────────────────


def test_no_idle_timeout_by_default(store, clock):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += 7 * 3600
    assert ps.get_session(sid) is not None


def test_an_idle_session_dies_when_configured(store, clock, monkeypatch):
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_IDLE", "1800")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += 1801
    assert ps.get_session(sid) is None


def test_activity_keeps_an_idle_session_alive(store, clock, monkeypatch):
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_IDLE", "1800")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += 1000
    ps.touch_session(sid)
    clock["t"] += 1000          # 2000s since login, 1000s since activity
    assert ps.get_session(sid) is not None


def test_activity_cannot_outlive_the_absolute_deadline(store, clock, monkeypatch):
    """Touching forever must not turn an 8h cap into an unbounded session."""
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_IDLE", "1800")
    monkeypatch.setenv("SHIELD_PORTAL_SESSION_TTL", "3600")
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    for _ in range(10):
        clock["t"] += 600
        ps.touch_session(sid)
    assert ps.get_session(sid) is None


def test_touch_writes_nothing_when_idle_is_off(store, monkeypatch):
    """The common case must stay one read per request. A write bought for
    nothing is still a write."""
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    writes: list = []
    monkeypatch.setattr(ps, "kv_set",
                        lambda *a, **k: writes.append(a[0]))
    ps.touch_session(sid)
    assert writes == []


# ── revocation, the reason this is server-side ───────────────────────────


def test_revoke_session(store):
    sid = ps.create_session(TENANT, CLAIMS, is_admin=True)
    assert ps.revoke_session(sid) is True
    assert ps.get_session(sid) is None


def test_revoking_an_unknown_session_is_false_not_an_error(store):
    assert ps.revoke_session("nope") is False


def test_revoke_all_for_subject_signs_them_out_everywhere(store):
    """The capability a stateless signed cookie cannot have, and the question
    asked immediately after "who did this"."""
    ids = [ps.create_session(TENANT, CLAIMS, is_admin=True) for _ in range(3)]
    assert ps.revoke_all_for_subject(TENANT, CLAIMS["sub"]) == 3
    assert all(ps.get_session(i) is None for i in ids)


def test_revoke_all_does_not_touch_another_tenant(store):
    """Same subject string in two tenants is not the same person."""
    mine = ps.create_session(TENANT, CLAIMS, is_admin=True)
    theirs = ps.create_session(OTHER, CLAIMS, is_admin=True)
    ps.revoke_all_for_subject(TENANT, CLAIMS["sub"])
    assert ps.get_session(mine) is None
    assert ps.get_session(theirs) is not None


def test_revoke_all_does_not_touch_another_person(store):
    mine = ps.create_session(TENANT, CLAIMS, is_admin=True)
    other = ps.create_session(TENANT, {**CLAIMS, "sub": "someone-else"},
                              is_admin=True)
    ps.revoke_all_for_subject(TENANT, "someone-else")
    assert ps.get_session(mine) is not None
    assert ps.get_session(other) is None


def test_revoking_one_session_drops_it_from_the_index(store):
    """A stale id in the index would make revoke_all report a count that
    includes sessions already gone."""
    a = ps.create_session(TENANT, CLAIMS, is_admin=True)
    ps.create_session(TENANT, CLAIMS, is_admin=True)
    ps.revoke_session(a)
    assert ps.revoke_all_for_subject(TENANT, CLAIMS["sub"]) == 1


def test_the_index_is_bounded(store):
    """One human logging in from many devices must not grow a list forever."""
    for _ in range(60):
        ps.create_session(TENANT, CLAIMS, is_admin=True)
    assert len(ts.kv_get(f"portalsessions:{TENANT}:{CLAIMS['sub']}")) == 50


def test_listing_skips_expired_sessions(store, clock):
    old = ps.create_session(TENANT, CLAIMS, is_admin=True)
    clock["t"] += ps.session_ttl() + 1
    fresh = ps.create_session(TENANT, CLAIMS, is_admin=True)
    ids = [s["session_id"] for s in ps.list_sessions_for_subject(TENANT, CLAIMS["sub"])]
    assert ids == [fresh] and old not in ids


# ── the guard path must not learn about any of this ──────────────────────


def test_the_guard_path_reads_no_session(store, monkeypatch):
    """resolve_tenant_by_api_key runs on every guarded request. Portal
    sessions are an admin-plane concern and must stay one."""
    ts.add_api_key(TENANT, "sk-guard-key-aaaaaaaaaaaa")
    ps.create_session(TENANT, CLAIMS, is_admin=True)
    monkeypatch.setattr(ts, "_cache", {})

    reads: list = []
    real_get = dict.get

    class _Spy(dict):
        def get(self, k, *a):
            reads.append(k)
            return real_get(self, k, *a)

    monkeypatch.setattr(ts, "_fallback_store", _Spy(store))
    for _ in range(50):
        ts.resolve_tenant_by_api_key("sk-guard-key-aaaaaaaaaaaa")

    assert not [k for k in reads if "portalsession" in k]


def test_resolve_tenant_does_not_reference_sessions():
    """Source-level companion: a spy only catches the read that exists today."""
    import inspect
    assert "portalsession" not in inspect.getsource(ts.resolve_tenant_by_api_key)


# ── the kv_set ttl this needed ───────────────────────────────────────────


def test_kv_set_ttl_is_optional_and_backward_compatible(store):
    ts.kv_set("plain", {"a": 1})
    assert ts.kv_get("plain") == {"a": 1}


def test_kv_set_passes_ttl_to_redis_when_available(monkeypatch):
    calls: list = []

    class _Redis:
        def setex(self, k, ttl, payload):
            calls.append((k, ttl))

        def set(self, k, payload):
            calls.append((k, None))

    monkeypatch.setattr(ts, "_get_redis", lambda: _Redis())
    ts.kv_set("k", {"a": 1}, ttl=60)
    assert calls == [("k", 60)]


def test_kv_set_falls_back_when_setex_is_missing(monkeypatch):
    """Upstash REST and older clients may not expose setex. The value's own
    deadline still governs, so a plain set is correct rather than fatal."""
    calls: list = []

    class _Redis:
        def setex(self, k, ttl, payload):
            raise AttributeError("no setex here")

        def set(self, k, payload):
            calls.append(k)

    monkeypatch.setattr(ts, "_get_redis", lambda: _Redis())
    ts.kv_set("k", {"a": 1}, ttl=60)
    assert calls == ["k"]
