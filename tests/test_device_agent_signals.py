"""Agent signals for alerts (R2, task 2): blocks uploaded within seconds, a stop
heartbeat on shutdown, and uptime fields that tell sleep from a stopped agent.

Spec: docs/specs/device-block-and-stop-alerts.md, sections 2, 4 and 7.
"""
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "packages" / "votal-device-agent", ROOT / "packages" / "shield-mavlink"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from votal_device_agent import sync as vsync  # noqa: E402
from votal_device_agent.agent import Agent, system_uptime_s  # noqa: E402

CREDS = vsync.Credentials(device_id="dev_1", api_key="vdk_x", tenant_id="acme", fleet="eng")


class FakeHttp:
    def __init__(self, delay=0.0):
        self.calls, self.delay = [], delay

    def __call__(self, method, url, headers, body=None):
        time.sleep(self.delay)
        self.calls.append((method, url, json.loads(body) if body else None))
        if url.endswith("/v1/shield/runtime/events"):
            return 202, {}, b"{}"
        if url.endswith("/v1/devices/heartbeat"):
            return 204, {}, b""
        return 404, {}, b""


def _agent(tmp_path, http, creds=CREDS):
    cfg = vsync.AgentConfig(shield_url="https://s.invalid", tenant_id="acme", fleet="eng",
                            pinned_public_key="a" * 64, state_dir=str(tmp_path / "a"))
    store = SimpleNamespace(load=lambda: creds)
    offline = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))  # noqa: E731
    return Agent(cfg, http=http, model_http=offline, credentials=store)


def test_a_block_wakes_the_upload_and_an_allow_does_not(tmp_path):
    agent = _agent(tmp_path, FakeHttp())
    agent._on_decision(SimpleNamespace(action="allow"))
    assert not agent._push_soon.is_set()
    agent._on_decision(SimpleNamespace(action="block"))
    assert agent._push_soon.is_set()


def test_engine_calls_the_hook_and_survives_its_errors(tmp_path):
    agent = _agent(tmp_path, FakeHttp())
    seen = []
    agent.engine.on_record = lambda d: seen.append(d.action) or 1 / 0
    agent.engine.note("chatgpt.com", "block", "test")                  # recorded, hook raises
    assert seen == ["block"] and agent.audit.records()


def test_the_upload_loop_pushes_soon_after_a_block(tmp_path):
    http = FakeHttp()
    agent = _agent(tmp_path, http)
    agent.PUSH_DEBOUNCE_S = 0.05
    agent.engine.note("chatgpt.com", "block", "test")      # a real block record (also wakes the loop)
    t = threading.Thread(target=agent._push_loop, daemon=True)
    t.start()
    agent._on_decision(SimpleNamespace(action="block"))
    deadline = time.time() + 3
    while time.time() < deadline and not any(u.endswith("/runtime/events") for _m, u, _b in http.calls):
        time.sleep(0.02)
    agent._stop.set()
    t.join(2)
    assert any(u.endswith("/runtime/events") for _m, u, _b in http.calls)
    assert not agent._push_soon.is_set()


def test_lifecycle_fields_are_durations(tmp_path, monkeypatch):
    agent = _agent(tmp_path, FakeHttp())
    agent._t0_wall -= 3600                                  # an hour of wall time...
    agent._t0_mono -= 600                                   # ...but only 10 minutes awake
    lc = agent.lifecycle()
    assert lc["agent_uptime_s"] >= 600 and 2990 <= lc["slept_s"] <= 3010
    hb = agent.heartbeat_payload()
    assert {"agent_uptime_s", "slept_s"} <= set(hb)
    if system_uptime_s() is not None:
        assert hb["system_uptime_s"] > 0


def test_stop_heartbeat_carries_lifecycle_and_never_hangs(tmp_path):
    http = FakeHttp()
    agent = _agent(tmp_path, http)
    assert agent.send_stop("signal") is True
    body = http.calls[-1][2]
    assert body["lifecycle"] == {"event": "stop", "reason": "signal"} and "agent_uptime_s" in body
    slow = _agent(tmp_path / "slow", FakeHttp(delay=2.0))
    t0 = time.time()
    assert slow.send_stop("signal", timeout_s=0.2) is False
    assert time.time() - t0 < 1.0
    assert _agent(tmp_path / "new", FakeHttp(), creds=None).send_stop() is False   # not enrolled


def test_stop_only_announces_a_started_enrolled_agent(tmp_path):
    http = FakeHttp()
    agent = _agent(tmp_path, http)
    agent.stop()                                            # never started: no network
    assert not http.calls
    agent2 = _agent(tmp_path / "b", http)
    agent2.local_api = SimpleNamespace(stop=lambda: None)
    agent2.stop()
    assert http.calls and http.calls[-1][2]["lifecycle"]["event"] == "stop"
