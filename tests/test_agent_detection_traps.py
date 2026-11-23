"""AI agent detection rev 8, step R3: traps from the tag
(docs/specs/agent-impersonation-defense.md section 2.4, collector routes in 9).

The trap secret stays on the server. The collector hands each session a
stable, rotating layout, records the codes it issued, judges trap hits itself
(own code, another session's code, anything else), and answers canary links.
Codes are per tenant: one tenant's codes say nothing about another's.
"""

import json

import pytest
from starlette.testclient import TestClient

from core.agent_detection import collector, sitekeys, stream, traps
from storage import tenant_store as ts

SHOP = "https://shop.acme.example"
A = "0123456789abcdef01234567"
B = "fedcba9876543210fedcba98"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "test-salt")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "test-trap-secret")
    for name in ("SHIELD_AGENT_DETECTION", "SHIELD_AGENT_DETECTION_COLLECTOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()
    traps._reset_memory_for_tests()
    yield monkeypatch
    sitekeys._reset_memory_for_tests()
    stream._reset_memory_for_tests()
    traps._reset_memory_for_tests()


@pytest.fixture
def col(env):
    return TestClient(collector.create_app(), base_url="https://collect.example")


@pytest.fixture
def key(env):
    return sitekeys.create("acme", origins=[SHOP])["site_key"]


def _layout(col, key, shs=A, headers=None):
    return col.get("/t", params={"k": key, "s": shs}, headers={"origin": SHOP, **(headers or {})})


# ── layouts and codes ────────────────────────────────────────────────


def test_a_layout_is_stable_for_a_session_and_rotates_across_sessions(env):
    assert traps.layout("acme", A) == traps.layout("acme", A)
    many = [traps.layout("acme", f"{i:024x}") for i in range(200)]
    assert {m["inert"] for m in many} == {True, False}
    assert {m["position"] for m in many} == {0, 1}
    assert {m["t4"] is None for m in many} == {True, False}
    assert len({m["t1"]["field"] for m in many}) == len(traps.T1_FIELDS)
    assert len({m["t1"]["text"].split("{")[0][:20] for m in many}) > 1


def test_the_t1_text_carries_the_sessions_own_code(env):
    lay = traps.layout("acme", A)
    [own] = {traps.code(traps.tenant_key("acme"), A, "T1", traps.day())}
    assert own in lay["t1"]["text"]
    assert own != lay["t2"]["code"]


def test_codes_are_per_tenant_and_need_the_secret(env):
    assert traps.layout("acme", A)["t2"]["code"] != traps.layout("globex", A)["t2"]["code"]
    assert traps.layout("acme", A, master="other")["t2"]["code"] != traps.layout("acme", A)["t2"]["code"]


def test_the_layout_route_answers_the_allowed_origin_only(col, key):
    r = _layout(col, key)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.headers["access-control-allow-origin"] == SHOP
    assert r.json() == traps.layout("acme", A)
    for bad in (_layout(col, key, headers={"origin": "https://evil.example"}),
                _layout(col, "shs_pk_" + "0" * 24),
                _layout(col, key, shs="nope")):
        assert bad.json()["t1"] is None


def test_a_same_origin_request_is_checked_by_its_referer(col, key):
    r = col.get("/_shs/t", params={"k": key, "s": A}, headers={"referer": SHOP + "/signup?x=1"})
    assert r.json()["t1"] is not None
    r = col.get("/_shs/t", params={"k": key, "s": A}, headers={"referer": "https://evil.example/"})
    assert r.json()["t1"] is None


def test_traps_off_on_the_site_key_gives_an_empty_layout(col, env):
    k = sitekeys.create("acme", origins=[SHOP], traps=False)["site_key"]
    r = _layout(col, k)
    assert r.json()["t1"] is None and r.headers["access-control-allow-origin"] == SHOP


def test_issued_codes_are_recorded_for_the_session(col, key):
    _layout(col, key)
    for c in traps.issued_codes("acme", A):
        assert traps.owner_of("acme", c) == A
        assert traps.owner_of("globex", c) is None


def test_the_first_session_shown_a_code_keeps_it(env):
    traps.record("acme", ["aaaaaaaa"], A)
    traps.record("acme", ["aaaaaaaa"], B)
    assert traps.owner_of("acme", "aaaaaaaa") == A


def test_the_collector_needs_the_trap_secret(env):
    env.delenv("SHIELD_AGENT_DETECTION_TRAP_SECRET")
    with pytest.raises(RuntimeError, match="TRAP_SECRET"):
        collector.create_app()


# ── hits are judged on the server ────────────────────────────────────


def _owner(tenant):
    return lambda c: traps.owner_of(tenant, c)


def test_hit_verdicts(env):
    own = traps.code(traps.tenant_key("acme"), A, "T1", traps.day())
    yesterday = traps.code(traps.tenant_key("acme"), A, "T1", traps.days()[1])
    other = traps.code(traps.tenant_key("acme"), B, "T1", traps.day())
    traps.record("acme", [other], B)
    hits = [{"trap": "T1", "code": own}, {"trap": "T1", "code": yesterday},
            {"trap": "T1", "code": other}, {"trap": "T1", "code": "12345678"},
            {"trap": "T4"}, {"trap": "T1"}, {"trap": "T2", "code": own}]
    assert traps.check_hits("acme", A, hits, _owner("acme")) == [
        {"trap": "T1", "code_match": True}, {"trap": "T1", "code_match": True},
        {"trap": "T1", "code_match": False, "code_from": B}, {"trap": "T4"},
        {"trap": "T4"}, {"trap": "T4"}]


def _submit(col, key, shs, hits):
    body = {"v": 1, "site_key": key, "shs": shs, "page": "/signup", "t": 900, "kind": "submit",
            "traps": {"shown": ["T1", "T2"], "hit": hits}}
    return col.post("/b", content=json.dumps(body), headers={"origin": SHOP, "content-type": "text/plain"})


def test_a_beacon_keeps_the_verdict_not_the_code(col, key):
    _layout(col, key, shs=B)                                    # B was shown its codes
    own = traps.code(traps.tenant_key("acme"), A, "T1", traps.day())
    b_code = traps.code(traps.tenant_key("acme"), B, "T1", traps.day())
    _submit(col, key, A, [{"trap": "T1", "code": own, "code_match": False}])
    _submit(col, key, A, [{"trap": "T1", "code": b_code}])     # controller passed B's code to A
    first, second = stream.memory_entries("acme")
    assert first["traps"]["hit"] == [{"trap": "T1", "code_match": True}]
    assert second["traps"]["hit"] == [{"trap": "T1", "code_match": False, "code_from": B}]
    assert own not in json.dumps(first) and b_code not in json.dumps(second)


# ── canary links (T2) ────────────────────────────────────────────────


def test_a_canary_hit_is_queued_for_the_session_shown_the_link(col, key):
    c2 = _layout(col, key).json()["t2"]["code"]
    r = col.get(f"/_shs/v/{c2}", params={"k": key})
    assert r.status_code == 204 and r.content == b""
    [e] = stream.memory_entries("acme")
    assert e["kind"] == "canary" and e["shs"] == A
    assert e["traps"]["hit"] == [{"trap": "T2", "code_match": True}]


def test_a_canary_followed_from_another_session_names_it(col, key):
    c2 = _layout(col, key).json()["t2"]["code"]
    col.cookies.set("_shs", B)
    col.get(f"/v/{c2}", params={"k": key})
    [e] = stream.memory_entries("acme")
    assert e["shs"] == A and e["traps"]["hit"][0]["cookie_shs"] == B


@pytest.mark.parametrize("path", ["/v/deadbeef", "/v/NOTACODE", "/v/12345"])
def test_unknown_or_malformed_canaries_queue_nothing(col, key, path):
    assert col.get(path, params={"k": key}).status_code == 204
    assert stream.memory_entries("acme") == []


def test_a_canary_needs_the_site_key_of_the_tenant_that_issued_it(col, key):
    c2 = _layout(col, key).json()["t2"]["code"]
    other = sitekeys.create("globex", origins=[SHOP])["site_key"]
    col.get(f"/v/{c2}", params={"k": other})
    col.get(f"/v/{c2}")
    assert stream.memory_entries("acme") == [] and stream.memory_entries("globex") == []
