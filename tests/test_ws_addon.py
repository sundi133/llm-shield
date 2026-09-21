"""The mitmproxy binding (icap/ws_addon.py).

`test_ws_screen.py` covers the decision; this covers the wiring around it,
because the wiring is where a screening feature silently becomes a no-op: a
hook that never fires, a direction filter that drops the client's own messages,
or a block path that logs "block" without closing anything.

Skipped where mitmproxy is not installed, which is the CI case by design: it
lives in requirements-ws.txt so neither plane grows that dependency tree.
"""
from __future__ import annotations

import asyncio
import json
import types

import pytest

pytest.importorskip("mitmproxy", reason="mitmproxy lives in requirements-ws.txt")

from icap.policy import compile_bundle  # noqa: E402
from icap.ws_addon import ShieldWebSocketScreen  # noqa: E402

BUNDLE = compile_bundle({
    "tenant_id": "bankco", "version": "test",
    "rules": [{"id": "email-mask", "regex": r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}",
               "action": "block", "severity": "medium"}],
})


class FakeMessage:
    def __init__(self, content: str, *, from_client=True, is_text=True):
        self.content = content.encode() if isinstance(content, str) else content
        self.from_client = from_client
        self.is_text = is_text
        self.dropped = False

    def drop(self):
        self.dropped = True


class FakeWS:
    def __init__(self, *messages):
        self.messages = list(messages)
        self.close_code = None
        self.close_reason = None


class FakeFlow:
    def __init__(self, *messages, host="api.openai.com", path="/v1/x"):
        self.websocket = FakeWS(*messages)
        self.request = types.SimpleNamespace(pretty_host=host, path=path)
        self.killed = False

    def kill(self):
        self.killed = True


def addon(mode="enforce", fail_open=False, monkeypatch=None):
    a = ShieldWebSocketScreen()
    a.enforcing = mode == "enforce"
    a.fail_open = fail_open
    a.cache = types.SimpleNamespace(bundle=BUNDLE)
    return a


def prompt(text: str) -> str:
    return json.dumps({"messages": [{"role": "user", "content": text}]})


def deliver(a, f):
    """Drive the now-async websocket_message hook from a sync test."""
    asyncio.run(a.websocket_message(f))


def test_clean_client_message_passes_untouched():
    a = addon()
    m = FakeMessage(prompt("weather in Paris"))
    f = FakeFlow(m)
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is False and f.killed is False
    assert a.counters["screened"] == 1


def test_violating_message_is_dropped_and_the_socket_closed():
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"))
    f = FakeFlow(m)
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is True, "the message still reached the provider"
    assert f.killed is True
    assert f.websocket.close_code == 4403
    assert "email-mask" in f.websocket.close_reason
    assert a.counters["blocked"] == 1


def test_monitor_mode_reports_without_closing():
    a = addon(mode="monitor")
    m = FakeMessage(prompt("mail bob@corp.com"))
    f = FakeFlow(m)
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is False and f.killed is False
    assert a.counters["blocked"] == 0


def test_server_messages_are_not_screened():
    """v1 screens outbound only; screening the stream would double the work."""
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"), from_client=False)
    f = FakeFlow(m)
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is False and a.counters["screened"] == 0


def test_non_ai_host_is_left_alone():
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"))
    f = FakeFlow(m, host="chat.internal.example")
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is False and f.killed is False


def test_binary_frames_are_counted_as_skipped_not_screened():
    a = addon()
    m = FakeMessage(b"\x00\x01binary", is_text=False)
    f = FakeFlow(m)
    a.websocket_start(f)
    deliver(a, f)
    assert m.dropped is False
    assert a.counters["skipped"] == 1 and a.counters["screened"] == 0


def test_screening_error_fails_closed_by_default():
    """A message we could not judge is not a message we approved."""
    a = addon()
    f = FakeFlow(FakeMessage(prompt("hello")))
    f.websocket.messages = []          # forces an IndexError inside _screen
    deliver(a, f)
    assert f.killed is True and a.counters["errors"] == 1


def test_screening_error_can_fail_open_when_chosen():
    a = addon(fail_open=True)
    f = FakeFlow(FakeMessage(prompt("hello")))
    f.websocket.messages = []
    deliver(a, f)
    assert f.killed is False and a.counters["errors"] == 1


def test_session_state_is_released_at_the_end():
    a = addon()
    f = FakeFlow(FakeMessage(prompt("hi")))
    a.websocket_start(f)
    assert id(f) in a.sessions
    a.websocket_end(f)
    assert id(f) not in a.sessions


# ── Tier 2 on the socket (SHIELD_WS_SYNC_SCREEN) ────────────────────────────

import httpx  # noqa: E402

from icap.config import IcapConfig  # noqa: E402
from icap.extract import PROVIDER_COPILOT  # noqa: E402
from icap.shield import ShieldClient  # noqa: E402

RS = b"\x1e"
COPILOT_PATH = "/m365Copilot/Chathub/abc@def"


def copilot_frame(text: str) -> str:
    turn = {"arguments": [{"message": {"author": "user", "text": text, "messageType": "Chat"}}],
            "target": "chat", "type": 4}
    return json.dumps(turn) + RS.decode()


def sync_addon(handler, *, enforcing=True):
    """An addon with Tier 2 on, its ShieldClient pointed at a stub endpoint.

    substrate.office.com is added to ai_hosts because at runtime the M365
    opt-in (SHIELD_M365_COPILOT) is what routes and admits it; without that the
    addon correctly ignores the host entirely.
    """
    a = addon(mode="enforce" if enforcing else "monitor")
    a.cache = types.SimpleNamespace(bundle=BUNDLE)
    cfg = IcapConfig(
        api_key="tenant-key", api_base="https://shield.test",
        ai_hosts=IcapConfig().ai_hosts + ("substrate.office.com",),
    )
    a.cfg = cfg
    a.shield = ShieldClient(cfg, httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return a


def test_tier2_blocks_a_socket_turn_with_no_tier1_pattern():
    """The whole point for Copilot: the pricing sentence has no regex to hit,
    so only the policy engine catches it. Before this, shield-ws ran Tier 1
    only and it went through."""
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={
            "action": "block",
            "guardrail_results": [{"guardrail": "custom_policy_input", "passed": False,
                                   "message": "disclosure of margin and supplier cost"}],
        })

    a = sync_addon(handler)
    m = FakeMessage(copilot_frame("our margin is 62% and supplier cost 400 AED"))
    f = FakeFlow(m, host="substrate.office.com", path=COPILOT_PATH)
    a.websocket_start(f)
    deliver(a, f)

    assert m.dropped is True and f.killed is True
    assert a.counters["blocked"] == 1
    # Tier 2 saw the typed turn alone, not the SignalR envelope.
    assert [s["message"] for s in seen] == ["our margin is 62% and supplier cost 400 AED"]


def test_tier2_allows_a_clean_socket_turn():
    def handler(request):
        return httpx.Response(200, json={"action": "pass", "guardrail_results": []})

    a = sync_addon(handler)
    m = FakeMessage(copilot_frame("what is the weather in Paris"))
    f = FakeFlow(m, host="substrate.office.com", path=COPILOT_PATH)
    a.websocket_start(f)
    deliver(a, f)

    assert m.dropped is False and f.killed is False
    assert a.counters["screened"] == 1


def test_tier2_is_not_called_when_sync_is_off():
    """Default posture: Tier 1 only. A clean-to-Tier-1 turn is allowed without
    ever touching the network."""
    called = []

    def handler(request):
        called.append(1)
        return httpx.Response(200, json={"action": "pass"})

    a = addon()                      # sync off, no shield client
    assert a.shield is None
    a.cfg = IcapConfig(ai_hosts=IcapConfig().ai_hosts + ("substrate.office.com",))
    m = FakeMessage(copilot_frame("margin 62% supplier 400 AED"))
    f = FakeFlow(m, host="substrate.office.com", path=COPILOT_PATH)
    a.websocket_start(f)
    deliver(a, f)

    assert called == []
    assert m.dropped is False        # Tier 1 has no pattern for it


def test_tier2_monitor_mode_reports_but_does_not_close():
    def handler(request):
        return httpx.Response(200, json={
            "action": "block",
            "guardrail_results": [{"guardrail": "custom_policy_input", "passed": False}],
        })

    a = sync_addon(handler, enforcing=False)
    m = FakeMessage(copilot_frame("margin 62% supplier 400 AED"))
    f = FakeFlow(m, host="substrate.office.com", path=COPILOT_PATH)
    a.websocket_start(f)
    deliver(a, f)

    assert m.dropped is False and f.killed is False   # monitor never closes
