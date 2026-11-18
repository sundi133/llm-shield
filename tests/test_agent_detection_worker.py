"""AI agent detection rev 8, step R4: session summaries, tier 2 scoring and
the worker (docs/specs/agent-impersonation-defense.md sections 2.3, 2.4, 2.7,
6 and 7).

A person's session stays human-like (VDI graphics alone included); a
scripted one is flagged with reasons in plain words; trap verdicts from the
collector score and link sessions; cumulative page counters are not double
counted; the worker resumes from its cursor and never loses an entry it
hasn't saved.
"""

import json

import pytest
from starlette.testclient import TestClient

from core.agent_detection import collector, scoring, sitekeys, stream, traps, worker
from storage import tenant_store as ts

A = "0123456789abcdef01234567"
B = "fedcba9876543210fedcba98"
GPU = {"renderer": "ANGLE (Apple, Apple M2, OpenGL 4.1)", "renderer_class": "gpu", "cores": 8,
       "memory": 8, "screen": "1512x982", "dpr": 2, "tz": "Europe/Berlin", "canvas_hash": "aa", "fonts_hash": "bb"}
SWIFT = {**GPU, "renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device))", "renderer_class": "software"}
REQ = {"ts": 1000.0, "net_hash": "n1", "ua": "Mozilla/5.0 Chrome/157", "hints": {"ua": '"Chromium";v="157"',
       "platform": '"macOS"', "mobile": "?0"}, "origin": "https://shop.example"}
PERSON = {"keys": 31, "inputs": 29, "inputs_without_keys": 0, "fields_touched": 3, "corrections": 3,
          "clicks": 4, "centre_clicks": 0, "clicks_without_move": 0, "click_centre_offset_px": 9.5,
          "pointer_moves": 240, "pointer_straightness": 0.71, "untrusted_events": 0,
          "key_gap_mean_ms": 180, "key_gap_cv": 0.62, "first_input_ms": 4100}
SCRIPT = {"keys": 0, "inputs": 7, "inputs_without_keys": 7, "fields_touched": 7, "corrections": 0,
          "clicks": 5, "centre_clicks": 5, "clicks_without_move": 5, "click_centre_offset_px": 0.3,
          "pointer_moves": 0, "pointer_straightness": 1.0, "untrusted_events": 1,
          "key_gap_mean_ms": 0, "key_gap_cv": 0, "first_input_ms": 300}


def _e(kind, shs=A, t=500, page="/signup", req=None, **extra):
    return {"v": 1, "site_key": "k", "shs": shs, "kind": kind, "page": page, "t": t,
            "req": {**REQ, **(req or {})}, **extra}


def _session(*entries, shs=A):
    s = scoring.new_session(shs)
    for e in entries:
        scoring.add(s, e)
    return s


# ── scoring ──────────────────────────────────────────────────────────


def test_a_person_is_human_like():
    s = _session(_e("load", device=GPU, automation={"webdriver": False}),
                 _e("submit", t=30_000, interaction=PERSON, req={"ts": 1029.5}))
    v = scoring.score(s)
    assert v["band"] == "human_like" and v["score"] == 0 and v["reasons"] == []


def test_a_scripted_browser_is_a_clear_agent_with_reasons():
    s = _session(_e("load", device=SWIFT, automation={"webdriver": True}),
                 _e("submit", t=4000, interaction=SCRIPT, req={"ts": 1003.5}))
    v = scoring.score(s)
    assert v["band"] == "clear_agent" and v["score"] >= 0.8
    text = " | ".join(v["reasons"])
    assert "7 fields changed with no key presses" in text
    assert "5 of 5 clicks within 2 px" in text
    assert "navigator.webdriver is set" in text
    assert "A9: software graphics" in text
    assert v["pack"] == scoring.pack()["version"]


def test_vdi_graphics_alone_never_flag_a_person():
    s = _session(_e("load", device={**GPU, "renderer": "VMware SVGA 3D", "renderer_class": "vm"}),
                 _e("submit", t=30_000, interaction=PERSON, req={"ts": 1029.5}))
    v = scoring.score(s)
    assert v["band"] == "human_like" and v["signals"]["A9"] == 0


def test_trap_verdicts_score_and_link():
    own = _session(_e("submit", traps={"shown": ["T1"], "hit": [{"trap": "T1", "code_match": True}]}))
    assert scoring.score(own)["band"] == "clear_agent"
    assert "this session's own code (T1)" in scoring.score(own)["reasons"][0]
    reused = _session(_e("submit", traps={"hit": [{"trap": "T1", "code_match": False, "code_from": B}]}))
    assert scoring.score(reused)["band"] == "clear_agent" and reused["links"] == [B]
    canary = _session(_e("canary", traps={"hit": [{"trap": "T2", "code_match": True, "cookie_shs": B}]}))
    assert canary["links"] == [B] and canary["traps"]["canaries"] == 1
    assert "one controller" in scoring.score(canary)["reasons"][0]
    honeypot = _session(_e("submit", traps={"hit": [{"trap": "T4"}]}))
    assert scoring.score(honeypot)["band"] == "human_like"            # autofill can do this


def test_two_clients_in_one_session_is_a10():
    s = _session(_e("load", device=GPU), _e("leave", req={"ua": "Mozilla/5.0 HeadlessChrome/157"}))
    v = scoring.score(s)
    assert v["signals"]["A10"] == 1.0 and "2 different clients" in " ".join(v["reasons"])


def test_cumulative_page_counters_are_not_double_counted():
    submit = _e("submit", t=4000, interaction=SCRIPT, req={"ts": 1003.5})
    leave = _e("leave", t=4100, interaction=SCRIPT, req={"ts": 1003.6})     # same view, same totals
    s = _session(submit, leave)
    assert scoring.interaction(s)["inputs_without_keys"] == 7
    other_view = _e("submit", page="/checkout", t=2000, interaction=SCRIPT, req={"ts": 1100.0})
    scoring.add(s, other_view)
    assert scoring.interaction(s)["inputs_without_keys"] == 14


def test_a_session_is_capped(monkeypatch):
    monkeypatch.setitem(scoring.pack()["session"], "max_beacons", 3)
    s = _session(*[_e("load", device=GPU) for _ in range(5)])
    assert s["n"] == 3 and s["dropped"] == 2


def test_the_pack_is_well_formed():
    pk = scoring.pack()
    assert set(pk["weights"]) == {did for did, _ in scoring.DETECTORS}
    assert 0 < pk["bands"]["grey"] < pk["bands"]["clear_agent"] <= 1
    assert all(0 < w <= 1 for w in pk["weights"].values())


# ── the worker ───────────────────────────────────────────────────────


@pytest.fixture
def mem(monkeypatch):
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    stream._reset_memory_for_tests()
    sitekeys._reset_memory_for_tests()
    traps._reset_memory_for_tests()
    yield worker.MemoryStore()
    stream._reset_memory_for_tests()
    sitekeys._reset_memory_for_tests()
    traps._reset_memory_for_tests()


def test_the_worker_scores_and_resumes_from_its_cursor(mem):
    stream.append("acme", _e("load", device=SWIFT, automation={"webdriver": True}))
    stream.append("acme", _e("submit", t=4000, interaction=SCRIPT, req={"ts": 1003.5}))
    stream.append("acme", _e("load", shs=B, device=GPU))
    out = worker.process_tenant(mem, "acme", now=1010.0)
    assert out["entries"] == 3 and out["sessions"] == 2 and out["clear_agent"] == 1
    assert mem.sessions["acme"][A]["verdict"]["band"] == "clear_agent"
    assert mem.sessions["acme"][B]["verdict"]["band"] == "human_like"
    assert set(mem.index["acme"]) == {A, B}
    assert mem.stats["acme"]["beacons"] == 3 and mem.stats["acme"]["clear_agent"] == 1

    assert worker.process_tenant(mem, "acme", now=1020.0)["entries"] == 0     # nothing new
    stream.append("acme", _e("submit", shs=B, t=30_000, interaction=PERSON, req={"ts": 1029.5}))
    assert worker.process_tenant(mem, "acme", now=1030.0)["entries"] == 1
    assert mem.sessions["acme"][B]["n"] == 2 and mem.sessions["acme"][A]["n"] == 2


def test_a_failed_save_does_not_move_the_cursor(mem, monkeypatch):
    stream.append("acme", _e("load", device=GPU))

    def boom(*a, **k):
        raise ConnectionError("redis went away")
    monkeypatch.setattr(mem, "put_sessions", boom)
    with pytest.raises(ConnectionError):
        worker.process_tenant(mem, "acme", now=1010.0)
    assert mem.cursor("acme") is None
    monkeypatch.undo()


def test_a_held_lock_skips_the_tenant(mem, monkeypatch):
    monkeypatch.setattr(mem, "lock", lambda *a: False)
    stream.append("acme", _e("load", device=GPU))
    assert worker.process_tenant(mem, "acme")["skipped"] == 1
    assert mem.cursor("acme") is None


def test_one_tenant_failing_does_not_stop_the_others(mem, monkeypatch):
    stream.append("ok", _e("load", device=GPU))
    real = mem.read
    monkeypatch.setattr(mem, "read", lambda t, *a: (_ for _ in ()).throw(RuntimeError()) if t == "bad" else real(t, *a))
    out = worker.run_cycle(mem, ["bad", "ok"], now=1010.0)
    assert out["bad"] == {"error": "RuntimeError"} and out["ok"]["entries"] == 1


def test_old_sessions_leave_the_index(mem):
    stream.append("acme", _e("load", device=GPU))
    worker.process_tenant(mem, "acme", now=1010.0)
    stream.append("acme", _e("load", shs=B, device=GPU, req={"ts": 1010.0 + 2 * 86400}))
    worker.process_tenant(mem, "acme", now=1010.0 + 2 * 86400)
    assert set(mem.index["acme"]) == {B}


def test_stream_replies_from_both_clients_are_read_alike():
    body = json.dumps({"shs": A})
    redis_py = [(b"1-0", {b"b": body.encode()})]
    upstash = [["1-0", ["b", body]]]
    assert worker._entry_pairs(redis_py) == worker._entry_pairs(upstash) == [("1-0", {"shs": A})]
    assert worker._entry_pairs([["2-0", ["b", "{broken"]]]) == [("2-0", {})]


def test_collector_to_worker_end_to_end(mem, monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_HASH_SALT", "s")
    monkeypatch.setenv("SHIELD_AGENT_DETECTION_TRAP_SECRET", "t")
    key = sitekeys.create("acme", origins=["https://shop.example"])["site_key"]
    col = TestClient(collector.create_app(), base_url="https://collect.example")
    h = {"origin": "https://shop.example", "content-type": "text/plain"}
    own = traps.code(traps.tenant_key("acme"), A, "T1", traps.day())
    for body in ({"v": 1, "site_key": key, "shs": A, "kind": "load", "page": "/signup", "t": 50,
                  "device": SWIFT, "automation": {"webdriver": True}},
                 {"v": 1, "site_key": key, "shs": A, "kind": "submit", "page": "/signup", "t": 4000,
                  "interaction": SCRIPT, "traps": {"shown": ["T1"], "hit": [{"trap": "T1", "code": own}]}}):
        assert col.post("/b", content=json.dumps(body), headers=h).status_code == 204
    out = worker.run_cycle(mem)
    assert out["acme"]["clear_agent"] == 1
    v = mem.sessions["acme"][A]["verdict"]
    assert v["signals"]["A5"] == 1.0 and v["signals"]["A7"] == 1.0 and v["signals"]["A8"] == 1.0
