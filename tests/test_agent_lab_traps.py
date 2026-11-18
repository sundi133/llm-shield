"""Rotating traps T1 to T4 (spec 2.4 and 12), lab version.

Pins: only the session's own code counts as T1, another session's code links
the two, any other value is the weak T4 (autofill), canary codes resolve to
their session, every rotation stays hidden from people (aria-hidden,
off-screen, out of the tab order), and A5 grades the evidence.
"""

import re
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic"
sys.path.insert(0, str(LAB / "analysis"))
sys.path.insert(0, str(LAB / "shop"))

import detect  # noqa: E402
import trapcheck  # noqa: E402
import traps  # noqa: E402
from sessions import build_sessions  # noqa: E402

KEY = b"test-secret"
D = "20261116"
A, B = "a" * 24, "b" * 24


def test_codes_are_per_session_per_trap_per_day():
    c = traps.code(KEY, A, "T1", D)
    assert re.fullmatch(r"[0-9a-f]{8}", c)
    assert c == traps.code(KEY, A, "T1", D)
    assert len({c, traps.code(KEY, B, "T1", D), traps.code(KEY, A, "T2", D), traps.code(KEY, A, "T1", "20261117"),
                traps.code(b"other-tenant", A, "T1", D)}) == 5


def test_check_form_own_code_other_code_and_autofill():
    own, theirs = traps.code(KEY, A, "T1", D), traps.code(KEY, B, "T1", D)
    owner = {own: A, theirs: B}.get
    assert traps.check_form(KEY, A, {"ref_code": own.upper()}, owner, D) == ["T1"]
    assert traps.check_form(KEY, A, {"verification": theirs}, owner, D) == [f"T1x:{B}"]
    assert traps.check_form(KEY, A, {"website": "https://me.example"}, owner, D) == ["T4"]
    assert traps.check_form(KEY, A, {"session_check": "Jane Doe"}, owner, D) == ["T4"]
    assert traps.check_form(KEY, A, {"name": "Jane", "website": " "}, owner, D) == []


def test_every_rotation_is_hidden_from_people():
    for i in range(64):
        shs = f"{i:024x}"
        for snippet in (traps.form_traps(KEY, shs, D), traps.page_traps(KEY, shs, D)):
            body = re.sub(r"<!--.*?-->", "", snippet, flags=re.S)
            for box in re.findall(r"<div[^>]*>", body):
                assert 'class="sx"' in box and 'aria-hidden="true"' in box
            for ctl in re.findall(r"<(?:input|a)\b[^>]*>", body):
                assert 'tabindex="-1"' in ctl
    assert "left:-10000px" in traps.TRAP_CSS


def test_rotation_varies_across_sessions():
    layouts = [traps.layout(f"{i:024x}") for i in range(64)]
    for k in ("t1_field", "t1_wording", "position", "inert", "t4"):
        assert len({str(lay[k]) for lay in layouts}) > 1, k


def test_t3_lives_only_in_a_comment():
    snippet = traps.page_traps(KEY, A, D)
    t3 = "/_shs/v/" + traps.code(KEY, A, "T3", D)
    comment = re.search(r"<!--(.*?)-->", snippet, re.S).group(1)
    assert t3 in comment and t3 not in snippet.replace(comment, "")


def ev(sid, t, uri, shs="", trip="", ip="73.1.2.3"):
    return {"msec": t, "ip": ip, "method": "GET", "uri": uri, "status": 200, "ua": "UA", "chua": "",
            "chua_platform": "", "al": "", "sid": sid, "sid_set": "", "acct": "", "event": "", "trip": trip,
            "enforced": "", "shs": shs}


def test_canaries_resolve_to_own_reused_or_unknown(monkeypatch):
    monkeypatch.setattr(traps, "day", lambda ts=None: D)
    rows = [ev("s1", 1, "/", shs=A), ev("s1", 2, "/_shs/v/" + traps.code(KEY, A, "T2", D), shs=A),
            ev("s2", 1, "/", shs=B, ip="24.1.1.1"), ev("s2", 2, "/_shs/v/" + traps.code(KEY, A, "T3", D), shs=B, ip="24.1.1.1"),
            ev("s3", 1, "/", ip="50.1.1.1"), ev("s3", 2, "/_shs/v/deadbeef", ip="50.1.1.1")]
    ss = {s.key: s for s in build_sessions(rows)}
    trapcheck.resolve(list(ss.values()), KEY)
    assert ss["s1"].trap_hits == ["T2"] and ss["s1"].tripwire
    assert ss["s2"].trap_hits == [f"T3x:{A}"] and ss["s2"].reused_codes == {A}
    assert ss["s3"].trap_hits == ["T2?"]
    assert [e["uri"] for e in ss["s1"].events] == ["/"]      # canaries are not page actions


def test_a5_grades_evidence():
    def a5(trip):
        s = build_sessions([ev("s", 1, "/", trip=trip)])[0]
        return detect.score_session(s).signals["A5"]
    assert a5("T1") == 1.0
    assert a5(f"T1x:{B}") == 1.0
    assert a5("T4") == 0.35                                    # autofill-level evidence only
    assert a5("") == 0.0
    s = build_sessions([ev("s", 1, "/", trip="T4")])[0]
    assert detect.score_session(s).band != "clear_agent"
