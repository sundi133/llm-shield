"""Tier 2 lab tests: the beacon collector and the beacon-to-session join.

Spec sections 2.3 and 12 (tier 2 tests). Lab code only (lab/agent-traffic),
no browser or Nginx: the collector's validation is a pure function and the
join works on synthetic log rows and beacons.
"""

import importlib.util
import json
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic"
sys.path.insert(0, str(LAB / "analysis"))

import beacons  # noqa: E402
from sessions import build_sessions  # noqa: E402

_spec = importlib.util.spec_from_file_location("lab_collector", LAB / "collector" / "app.py")
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)

ORIGIN = "http://localhost:8180"
SHS = "a" * 24


def beacon(**over):
    b = {"v": 1, "site_key": "lab-site", "shs": SHS, "page": "/signup", "t": 900, "kind": "submit",
         "interaction": {"keys": 0, "inputs": 4, "inputs_without_keys": 4, "clicks": 1, "centre_clicks": 1,
                         "click_centre_offset_px": 0.4, "pointer_straightness": 1.0}}
    b.update(over)
    return b


def test_valid_beacon_is_kept_and_cleaned():
    raw = beacon(extra="dropped", interaction={"keys": -5, "inputs": 10**9, "typed_text": "secret"})
    b = collector.validate(json.dumps(raw).encode(), ORIGIN)
    assert b is not None
    assert "extra" not in b and "typed_text" not in b["interaction"]
    assert b["interaction"]["keys"] == 0 and b["interaction"]["inputs"] == 100_000


def test_wrong_origin_unknown_key_oversize_and_garbage_are_dropped():
    good = json.dumps(beacon()).encode()
    assert collector.validate(good, "https://evil.example") is None
    assert collector.validate(json.dumps(beacon(site_key="nope")).encode(), ORIGIN) is None
    assert collector.validate(b"{" + b" " * (17 * 1024) + b"}", ORIGIN) is None
    assert collector.validate(b"not json", ORIGIN) is None
    assert collector.validate(b"[1,2]", ORIGIN) is None
    assert collector.validate(json.dumps(beacon(shs="short")).encode(), ORIGIN) is None
    assert collector.validate(json.dumps(beacon(kind="steal")).encode(), ORIGIN) is None


def test_trap_results_keep_only_known_traps_and_strict_code_match():
    raw = beacon(traps={"shown": ["T1", "T9", 3], "hit": [{"trap": "T1", "code_match": "yes"},
                                                          {"trap": "T4", "code_match": True}, {"trap": "X"}]})
    b = collector.validate(json.dumps(raw).encode(), ORIGIN)
    assert b["traps"] == {"shown": ["T1"], "hit": [{"trap": "T1", "code_match": False},
                                                   {"trap": "T4", "code_match": True}]}


def test_beacon_route_always_answers_204_with_no_body():
    from fastapi.testclient import TestClient
    client = TestClient(collector.app)
    for body, origin in [(json.dumps(beacon()), "https://evil.example"), ("garbage", ORIGIN)]:
        r = client.post("/_shs/b", content=body, headers={"Origin": origin})
        assert r.status_code == 204 and r.content == b""


def test_rate_limit():
    rl = collector.RateLimit(3)
    assert [rl.allow("ip", now=100.0) for _ in range(4)] == [True, True, True, False]
    assert rl.allow("ip", now=161.0)


def ev(sid, t, uri, shs="", ip="73.1.2.3", ua="UA", method="GET"):
    return {"msec": t, "ip": ip, "method": method, "uri": uri, "status": 200, "ua": ua, "chua": "",
            "chua_platform": "", "al": "", "sid": sid, "sid_set": "", "acct": "", "event": "", "trip": "",
            "enforced": "", "shs": shs}


def test_tag_requests_are_not_page_actions():
    s = build_sessions([ev("s1", 1, "/"), ev("s1", 1.1, "/_shs/shs.js"), ev("s1", 1.5, "/_shs/b", shs=SHS, method="POST"),
                        ev("s1", 5, "/signup", shs=SHS)])[0]
    assert [e["uri"] for e in s.events] == ["/", "/signup"]
    assert s.tag_requests == 2 and s.shs_ids == {SHS}


def test_join_by_shs_then_fallback_then_missing():
    rows = [ev("s1", 100, "/", shs=SHS), ev("s2", 100, "/", ip="24.5.6.7", ua="UA2"), ev("s3", 100, "/", ip="50.1.1.1")]
    sessions = build_sessions(rows)
    bs = [dict(beacon(), recv=101, ip="73.1.2.3", ua="UA"),
          dict(beacon(shs="b" * 24, kind="load", device={"renderer": "SwiftShader", "cores": 4}),
               recv=102, ip="24.5.6.7", ua="UA2")]
    tags = beacons.attach(sessions, bs)
    assert tags["s1"].join == "shs" and tags["s1"].counts["inputs_without_keys"] == 4
    assert tags["s2"].join == "fallback" and tags["s2"].device["renderer"] == "SwiftShader"
    assert tags["s3"].join == "missing"


def test_device_hash_ignores_order_and_changes_with_device():
    a = {"renderer": "r", "cores": 8, "screen": "1x1"}
    assert beacons.device_hash(a) == beacons.device_hash(dict(reversed(list(a.items()))))
    assert beacons.device_hash(a) != beacons.device_hash(dict(a, cores=4))


def test_tag_stays_small_and_reads_no_values():
    js = (LAB / "tag" / "shs.js").read_text()
    assert len(js.encode()) < 15 * 1024
    # The tag must never read what people type or the page text.
    for forbidden in (".value", "innerText", "textContent", "innerHTML", "location.search", "location.hash"):
        assert forbidden not in js, forbidden
