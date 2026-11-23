"""AI agent detection rev 8, step R5: fleets from tag sessions
(docs/specs/agent-impersonation-defense.md sections 3.2 to 3.4).

One controller's agents link into a fleet on behavior plus a second trait;
people sharing an office network, a popular device or a busy minute do not;
a fleet needs enough members across enough networks; trap-code reuse links
on its own; ids stay stable as a fleet grows; the work stays near-linear.
"""

import random
import time

import pytest

from core.agent_detection import fleets, scoring, stream, worker
from storage import tenant_store as ts

T0 = 1_000_000.0
PAGES = ["/", "/signup", "/promo", "/checkout"]
SCRIPT = {"keys": 0, "inputs": 7, "inputs_without_keys": 7, "fields_touched": 7, "corrections": 0,
          "clicks": 5, "centre_clicks": 5, "clicks_without_move": 5, "untrusted_events": 1}
PERSON = {"keys": 31, "inputs": 29, "inputs_without_keys": 0, "fields_touched": 3, "corrections": 3,
          "clicks": 4, "centre_clicks": 0, "clicks_without_move": 0, "untrusted_events": 0}


def _sess(i, *, kind="agent", first=T0, net=None, device=None, client=None, pages=PAGES, links=()):
    s = scoring.new_session(f"{kind[0]}{i:023x}")
    s.update(first=first, last=first + 40, pages=list(pages), nets=[net or f"net{i}"],
             clients=[client or f"cl-{kind}"], device_hashes=[device or f"dev-{kind}"],
             views={"/signup|1": dict(SCRIPT if kind == "agent" else PERSON)}, links=list(links))
    s["verdict"] = {"band": "clear_agent" if kind == "agent" else "human_like"}
    return s


def _agents(n, start=T0, spread=2.0, **kw):
    return [_sess(i, first=start + i * spread, **kw) for i in range(n)]


def _people(n, **kw):
    rnd = random.Random(7)
    return [_sess(i, kind="person", first=T0 + rnd.uniform(0, 6 * 3600), **kw) for i in range(n)]


def test_one_controllers_agents_form_one_fleet():
    found = fleets.find_fleets(_agents(12) + _people(200))
    assert len(found) == 1
    f = found[0]
    assert f["size"] == 12 and f["networks"] == 12
    assert {"behavior", "time", "environment"} <= set(f["traits"])
    assert f["devices"][0]["rare"] is True and f["bands"] == {"clear_agent": 12}


@pytest.mark.parametrize("sessions", [
    _agents(9),                                                 # under the minimum size
    [_sess(i, net=f"net{i % 2}") for i in range(12)],           # two networks only
])
def test_below_the_fleet_minimum_is_not_a_fleet(sessions):
    assert fleets.find_fleets(sessions) == []


def test_an_office_starting_together_is_not_a_fleet():
    office = [_sess(i, kind="person", first=T0 + i, net="office") for i in range(30)]
    assert fleets.find_fleets(office) == []


def test_a_popular_device_never_links_people():
    crowd = _people(3000, device="iphone-15", client="safari-18")      # one popular phone
    found = fleets.find_fleets(crowd)
    assert found == []
    # agents on that same popular device, spread out in time: behavior alone, no fleet
    spread = [_sess(i, first=T0 + i * 600, device="iphone-15", client="safari-18") for i in range(12)]
    assert fleets.find_fleets(crowd + spread) == []


def test_rare_device_plus_behavior_links_without_shared_timing():
    spread = [_sess(i, first=T0 + i * 600, device="swiftshader-x") for i in range(12)]
    [f] = fleets.find_fleets(spread + _people(500))
    assert f["size"] == 12 and "time" not in f["traits"] and f["traits"]["environment"] >= 11


def test_trap_code_reuse_links_on_its_own():
    chain = [_sess(i, kind="person", first=T0 + i * 900, pages=[f"/p{i}"],
                   links=[f"p{i + 1:023x}"] if i < 11 else []) for i in range(12)]
    [f] = fleets.find_fleets(chain)
    assert f["size"] == 12 and set(f["traits"]) == {"controller"}


def test_the_fleet_id_is_stable_as_it_grows():
    first = fleets.find_fleets(_agents(10))[0]["id"]
    assert fleets.find_fleets(_agents(16))[0]["id"] == first


def test_ten_thousand_people_stay_fast():
    crowd = _people(10_000, device=None)
    for i, s in enumerate(crowd):
        s["device_hashes"] = [f"dev-{i % 50}"]
    started = time.time()
    assert fleets.find_fleets(crowd) == []
    assert time.time() - started < 10


def test_prevalence_counts_people_only():
    p = fleets.Prevalence(_people(3, device="d1") + _agents(50, device="d2"))
    assert p.humans == 3
    assert p.rare_device("d1") is False             # carried by people: never a linking trait
    assert p.rare_device("d2") is True              # agents don't make their own device common
    assert fleets.Prevalence([]).rare_device("d1") is True


def test_people_on_a_popular_funnel_never_chain_into_a_fleet():
    """At volume, people share a path, an ordinary profile and a 30 s window
    all the time. Behavior links only on a profile that is rare among them."""
    rnd = random.Random(3)
    crowd = [_sess(i, kind="person", first=T0 + rnd.uniform(0, 3600), device=f"d{i % 40}") for i in range(10_000)]
    found = fleets.find_fleets(crowd + _agents(12))
    assert [f["size"] for f in found] == [12] and found[0]["bands"] == {"clear_agent": 12}


def test_perfect_mimics_link_only_through_a_trap_code():
    """The documented trade-off: agents that type like people and score
    human-like don't link on behavior; a reused trap code still links them."""
    mimics = [_sess(i, kind="person", first=T0 + i, device="swift") for i in range(12)]
    assert fleets.find_fleets(mimics) == []
    for i, m in enumerate(mimics[:-1]):
        m["links"] = [mimics[i + 1]["shs"]]
    assert fleets.find_fleets(mimics)[0]["size"] == 12


# ── through the worker ───────────────────────────────────────────────


@pytest.fixture
def mem(monkeypatch):
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    stream._reset_memory_for_tests()
    worker._last_fleet_run.clear()
    yield worker.MemoryStore()
    stream._reset_memory_for_tests()
    worker._last_fleet_run.clear()


SWIFT = {"renderer": "SwiftShader", "renderer_class": "software", "cores": 4, "memory": 8,
         "screen": "1280x720", "dpr": 1, "tz": "UTC", "canvas_hash": "cc", "fonts_hash": "ff"}


def test_the_worker_finds_and_stores_the_fleet(mem):
    for i in range(12):
        shs = f"{i:024x}"
        req = {"ts": T0 + i * 2, "net_hash": f"net{i}", "ua": "UA", "hints": {}}
        for page in PAGES:
            stream.append("acme", {"shs": shs, "kind": "load", "page": page, "t": 10, "req": req,
                                   "device": SWIFT, "automation": {"webdriver": True}})
        stream.append("acme", {"shs": shs, "kind": "submit", "page": "/signup", "t": 4000,
                               "req": {**req, "ts": T0 + i * 2 + 4}, "interaction": SCRIPT})
    out = worker.process_tenant(mem, "acme", now=T0 + 60)
    assert out["fleets"] == 1
    [f] = mem.list_fleets("acme")
    assert f["size"] == 12 and f["networks"] == 12
    assert worker.process_tenant(mem, "acme", now=T0 + 70)["fleets"] is None   # not due yet


def test_a_fleet_lists_every_client_its_members_showed():
    """Agent sessions often show two clients (spoofed on page loads, real on
    exit beacons); the spoofed one is what the edge sees, so both count."""
    agents = _agents(12)
    for a in agents:
        a["clients"] = ["spoofed-chrome", f"real-{a['shs'][-3:]}"]
        a["client_strings"] = {"spoofed-chrome": "Mozilla/5.0 Windows Chrome|x|y|?0"}
    [f] = fleets.find_fleets(agents + _people(200))
    top = f["clients"][0]
    assert top["hash"] == "spoofed-chrome" and top["sessions"] == 12 and top["rare"]
    assert top["value"] == "Mozilla/5.0 Windows Chrome|x|y|?0"


def test_a_client_people_also_show_is_never_rare():
    people = _people(1500)
    for p in people[:5]:
        p["clients"] = ["cl-person", "spoofed-chrome"]
    agents = _agents(12)
    for a in agents:
        a["clients"] = ["spoofed-chrome"]
    [f] = fleets.find_fleets(agents + people)
    assert f["clients"][0]["hash"] == "spoofed-chrome" and f["clients"][0]["rare"] is False
