"""Tier 2 detectors and device linking in the lab (spec 2.3, 3.2, 3.4, 12).

Pins: A7 fires on a programmatic fill and stays quiet on human typing; A9
alone never raises anything; a missing tag counts only on a form submit; a
common device fingerprint never links sessions; trap code reuse links two
sessions on its own; the logs-only score ignores the tag entirely.
"""

import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic"
sys.path.insert(0, str(LAB / "analysis"))

import beacons  # noqa: E402
import detect  # noqa: E402
import tier2  # noqa: E402
from sessions import build_sessions  # noqa: E402

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/157.0.0.0 Safari/537.36"
CHUA = '"Google Chrome";v="157", "Chromium";v="157"'
HUMAN_DEV = {"renderer": "ANGLE (Apple M3)", "renderer_class": "gpu", "cores": 8, "memory": 16, "screen": "1512x982",
             "dpr": 2, "canvas_hash": "aa", "fonts_hash": "bb", "tz": "America/Chicago", "touch": 0}
SANDBOX_DEV = dict(HUMAN_DEV, renderer="Google SwiftShader", renderer_class="software", cores=4, memory=8,
                   screen="1366x860", dpr=1, canvas_hash="cc")


def ev(sid, t, uri, method="GET", ip="73.1.2.3", shs="", trip=""):
    return {"msec": t, "ip": ip, "method": method, "uri": uri, "status": 200, "ua": UA, "chua": CHUA,
            "chua_platform": '"macOS"', "al": "", "sid": sid, "sid_set": "", "acct": "", "event": "", "trip": trip,
            "enforced": "", "shs": shs}


def tag_with(device=None, ua=UA, **interaction):
    t = beacons.TagData(join="shs")
    t.add({"kind": "load", "page": "/signup", "ua": ua, "device": device or HUMAN_DEV, "automation": {}})
    it = {"keys": 0, "inputs": 0, "inputs_without_keys": 0, "clicks": 0, "centre_clicks": 0,
          "clicks_without_move": 0, "corrections": 0, "key_gap_mean_ms": 0, "key_gap_cv": 0}
    it.update(interaction)
    t.add({"kind": "submit", "page": "/signup", "ua": ua, "interaction": it})
    return t


PROGRAMMATIC = dict(inputs=4, inputs_without_keys=4, clicks=3, centre_clicks=3, clicks_without_move=3)
HUMAN_TYPING = dict(keys=62, inputs=58, inputs_without_keys=0, corrections=4, clicks=4, centre_clicks=0,
                    clicks_without_move=0, key_gap_mean_ms=180, key_gap_cv=0.71, pointer_moves=240)


def session(sid="s1", ip="73.1.2.3", shs="", post=True, trip=""):
    rows = [ev(sid, 1, "/signup", ip=ip, shs=shs)]
    if post:
        rows.append(ev(sid, 30, "/signup", method="POST", ip=ip, shs=shs, trip=trip))
    return build_sessions(rows)[0]


def test_a7_fires_on_programmatic_fill_and_not_on_human_typing():
    s = session()
    value, why = tier2.a7_interaction(s, tag_with(**PROGRAMMATIC), {})
    assert value == 1.0 and "no key presses" in why
    assert tier2.a7_interaction(s, tag_with(**HUMAN_TYPING), {}) == (0.0, None)


def test_a7_ignores_pointer_checks_on_touch_devices():
    s = session()
    phone = dict(HUMAN_DEV, touch=5)
    assert tier2.a7_interaction(s, tag_with(phone, clicks=4, centre_clicks=4, clicks_without_move=4), {}) == (0.0, None)


def test_a9_alone_never_raises():
    s = session()
    sandbox_human = tag_with(SANDBOX_DEV, **HUMAN_TYPING)          # a VDI user typing normally
    v = detect.score_session(s, sandbox_human)
    assert v.signals["A9"] == 0.0 and v.band == "human_like"
    v = detect.score_session(s, tag_with(SANDBOX_DEV, **PROGRAMMATIC))
    assert v.signals["A9"] == 1.0                                 # supporting once A7 fired


def test_missing_tag_counts_only_on_a_form_submit_and_weakly():
    assert tier2.a10_tag_state(session(post=False), beacons.TagData(), {}) == (0.0, None)
    value, _ = tier2.a10_tag_state(session(post=True), beacons.TagData(), {})
    assert value == 0.5
    assert detect.score_session(session(post=True), beacons.TagData()).band == "human_like"


def test_beacons_from_a_different_client_contradict():
    t = tag_with(**HUMAN_TYPING)
    t.add({"kind": "leave", "ua": "Mozilla/5.0 HeadlessChrome/157"})
    value, why = tier2.a10_tag_state(session(), t, {})
    assert value == 1.0 and "different client" in why


def test_logs_only_score_ignores_the_tag():
    s = session()
    assert detect.score_session(s).score == detect.score_session(s, None).score
    assert "A7" not in detect.score_session(s).signals


def test_device_baseline_prevalence(tmp_path):
    b = tier2.DeviceBaseline(tmp_path / "b.json")
    common = beacons.device_hash(HUMAN_DEV)
    b.add([common] * 30 + [f"other{i}" for i in range(970)])
    b.save()
    b = tier2.DeviceBaseline(tmp_path / "b.json")
    assert b.share(common) == 0.03 and not b.rare(common)
    assert b.rare(beacons.device_hash(SANDBOX_DEV)) and not b.rare("")


def _pair(dev_a, dev_b, *, shs_a="a" * 24, shs_b="b" * 24, trip_b=""):
    a = build_sessions([ev("a", 1, "/", ip="24.1.1.1", shs=shs_a), ev("a", 50, "/help", ip="24.1.1.1", shs=shs_a)])[0]
    b = build_sessions([ev("b", 900, "/about", ip="50.2.2.2", shs=shs_b),
                        ev("b", 990, "/signup", method="POST", ip="50.2.2.2", shs=shs_b, trip=trip_b)])[0]
    tags = {"a": tag_with(dev_a), "b": tag_with(dev_b)}
    sh = {s.key: detect._shingles(s.path_sequence()) for s in (a, b)}
    return a, b, sh, tags


def test_common_device_never_links_but_rare_one_counts_as_environment():
    a, b, sh, tags = _pair(HUMAN_DEV, HUMAN_DEV)
    a.ua, b.ua = "UA-a", "UA-b"                                     # different client fingerprints
    common = detect.link_traits(a, b, sh, tags, rare_device=lambda h: False)
    rare = detect.link_traits(a, b, sh, tags, rare_device=lambda h: True)
    assert "environment" not in common and "environment" in rare


def test_trap_code_reuse_links_two_sessions_on_its_own():
    a, b, sh, tags = _pair(HUMAN_DEV, SANDBOX_DEV, trip_b="T1x:" + "a" * 24)
    assert "controller" in detect.link_traits(a, b, sh, tags)
    fleets = detect.find_fleets([a, b], min_size=2, min_networks=2, tags=tags)
    assert len(fleets) == 1 and fleets[0]["linking_traits"].get("controller")
