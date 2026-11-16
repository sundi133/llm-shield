"""Unit tests for the agent-detection lab's analysis (lab/agent-traffic/analysis).

Synthetic access-log events only; no browser, model or Nginx. These pin the
safety properties the spec depends on: a shared office IP alone never forms a
fleet, a fingerprint shared with other sessions is never published, and the
client-hint version check catches a spoofed user agent.
"""

import sys
from pathlib import Path

ANALYSIS = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic" / "analysis"
sys.path.insert(0, str(ANALYSIS))

import analyze  # noqa: E402
import detect  # noqa: E402
import siem_rules  # noqa: E402
from sessions import build_sessions  # noqa: E402

CHUA = '"Google Chrome";v="157", "Chromium";v="157"'
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/157.0.0.0 Safari/537.36"
UA_SPOOF = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"


def ev(sid, t, uri, *, method="GET", ip="73.1.2.3", ua=UA_MAC, status=200, event="", acct="", plat='"macOS"'):
    return {"msec": t, "ip": ip, "method": method, "uri": uri, "status": status, "bytes": 100, "req_len": 200,
            "rt": 0.01, "ua": ua, "ref": "", "chua": CHUA, "chua_platform": plat, "al": "en-US", "sid": sid,
            "sid_set": "", "acct": acct, "event": event, "trip": "", "enforced": ""}


def agent_session(sid, start, ip, ua=UA_SPOOF, gap=5.0):
    """Sign-up, promo and checkout at a steady model-latency pace, no browsing."""
    steps = [("GET", "/", ""), ("GET", "/signup", ""), ("POST", "/signup", "signup"), ("GET", "/account", ""),
             ("GET", "/promo", ""), ("POST", "/promo", "promo"), ("GET", "/product/6", ""),
             ("POST", "/cart/add/6", ""), ("GET", "/checkout", ""), ("POST", "/checkout", "order")]
    out, t = [], start
    for method, uri, event in steps:
        out.append(ev(sid, t, uri, method=method, ip=ip, ua=ua, event=event, acct="u1" if event else "",
                      plat='"Windows"' if "Windows" in ua else '"macOS"'))
        out.append(ev(sid, t + 0.05, "/static/style.css", ip=ip, ua=ua))
        t += gap * (4 if method == "GET" and uri in ("/signup", "/checkout") else 1)
    return out


def human_session(sid, start, ip="192.168.65.1"):
    gaps = [0.6, 9.0, 2.5, 31.0, 0.9, 14.0, 3.2, 47.0]
    uris = ["/", "/product/2", "/", "/help", "/product/5", "/", "/about", "/product/1", "/"]
    out, t = [], start
    for uri, g in zip(uris, gaps + [0]):
        out.append(ev(sid, t, uri, ip=ip))
        t += g
    return out


def test_version_mismatch_is_flagged():
    s = build_sessions(agent_session("a1", 1000, "73.1.2.3"))[0]
    v = detect.score_session(s)
    assert any("claims Chrome 131 but client hints say 157" in r for r in v.reasons)


def test_human_browsing_is_not_flagged():
    s = build_sessions(human_session("h1", 1000))[0]
    v = detect.score_session(s)
    assert v.band == "human_like", v.reasons


def test_fleet_forms_across_networks():
    events = []
    for i in range(12):
        events += agent_session(f"a{i}", 1000 + i * 2, f"{24 + i}.10.{i}.5")
    fleets = detect.find_fleets(build_sessions(sorted(events, key=lambda e: e["msec"])))
    assert len(fleets) == 1 and fleets[0]["size"] == 12 and fleets[0]["networks"] == 12


def test_office_nat_alone_never_forms_a_fleet():
    """Twelve people behind one IP with the same browser, browsing differently: no fleet."""
    events = []
    for i in range(12):
        h = human_session(f"h{i}", 1000 + i * 400)
        events += [dict(e, uri=e["uri"] if j % (i % 3 + 2) else "/help") for j, e in enumerate(h)]
    fleets = detect.find_fleets(build_sessions(sorted(events, key=lambda e: e["msec"])))
    assert fleets == []


def test_fingerprint_shared_with_people_is_withheld():
    events = []
    for i in range(12):
        events += agent_session(f"a{i}", 1000 + i * 2, f"{24 + i}.10.{i}.5", ua=UA_MAC)
    events += human_session("h1", 1000)          # same Mac Chrome as the fleet
    sessions = build_sessions(sorted(events, key=lambda e: e["msec"]))
    verdicts = {s.key: detect.score_session(s) for s in sessions}
    fleets = detect.find_fleets(sessions)
    ind = analyze.indicators(fleets, verdicts, sessions)
    assert ind["fingerprints"] == []
    assert any(w["type"] == "fingerprint" for w in ind["withheld"])
    assert "h1" not in ind["sessions"]


def test_siem_rules_miss_a_slow_spread_fleet():
    events = []
    for i in range(12):
        events += agent_session(f"a{i}", 1000 + i * 2, f"{24 + i}.10.{i}.5")
    assert siem_rules.run(events) == []


def test_nginx_map_key_escaping():
    assert analyze._nginx_key('a"b\\c') == '"a\\"b\\\\c"'
