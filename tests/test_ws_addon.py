"""The mitmproxy binding (icap/ws_addon.py).

`test_ws_screen.py` covers the decision; this covers the wiring around it,
because the wiring is where a screening feature silently becomes a no-op: a
hook that never fires, a direction filter that drops the client's own messages,
or a block path that logs "block" without closing anything.

Skipped where mitmproxy is not installed, which is the CI case by design: it
lives in requirements-ws.txt so neither plane grows that dependency tree.
"""
from __future__ import annotations

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


def test_clean_client_message_passes_untouched():
    a = addon()
    m = FakeMessage(prompt("weather in Paris"))
    f = FakeFlow(m)
    a.websocket_start(f)
    a.websocket_message(f)
    assert m.dropped is False and f.killed is False
    assert a.counters["screened"] == 1


def test_violating_message_is_dropped_and_the_socket_closed():
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"))
    f = FakeFlow(m)
    a.websocket_start(f)
    a.websocket_message(f)
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
    a.websocket_message(f)
    assert m.dropped is False and f.killed is False
    assert a.counters["blocked"] == 0


def test_server_messages_are_not_screened():
    """v1 screens outbound only; screening the stream would double the work."""
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"), from_client=False)
    f = FakeFlow(m)
    a.websocket_start(f)
    a.websocket_message(f)
    assert m.dropped is False and a.counters["screened"] == 0


def test_non_ai_host_is_left_alone():
    a = addon()
    m = FakeMessage(prompt("mail bob@corp.com"))
    f = FakeFlow(m, host="chat.internal.example")
    a.websocket_start(f)
    a.websocket_message(f)
    assert m.dropped is False and f.killed is False


def test_binary_frames_are_counted_as_skipped_not_screened():
    a = addon()
    m = FakeMessage(b"\x00\x01binary", is_text=False)
    f = FakeFlow(m)
    a.websocket_start(f)
    a.websocket_message(f)
    assert m.dropped is False
    assert a.counters["skipped"] == 1 and a.counters["screened"] == 0


def test_screening_error_fails_closed_by_default():
    """A message we could not judge is not a message we approved."""
    a = addon()
    f = FakeFlow(FakeMessage(prompt("hello")))
    f.websocket.messages = []          # forces an IndexError inside _screen
    a.websocket_message(f)
    assert f.killed is True and a.counters["errors"] == 1


def test_screening_error_can_fail_open_when_chosen():
    a = addon(fail_open=True)
    f = FakeFlow(FakeMessage(prompt("hello")))
    f.websocket.messages = []
    a.websocket_message(f)
    assert f.killed is False and a.counters["errors"] == 1


def test_session_state_is_released_at_the_end():
    a = addon()
    f = FakeFlow(FakeMessage(prompt("hi")))
    a.websocket_start(f)
    assert id(f) in a.sessions
    a.websocket_end(f)
    assert id(f) not in a.sessions
