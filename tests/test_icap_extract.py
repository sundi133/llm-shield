"""Prompt extraction tests (task 2 of docs/spec-swg-icap-adapter.md).

Two invariants run through all of these:
  * `text` carries EVERYTHING screenable, because a leaked credential in a
    replayed assistant turn is just as leaked as one the user typed.
  * `last_user` carries only the turn being sent, because that is the shape
    /guardrails/input is built for.
"""
from __future__ import annotations

import json

import pytest

from icap.extract import (
    PROVIDER_ANTHROPIC,
    PROVIDER_GOOGLE,
    PROVIDER_JSON,
    PROVIDER_OPENAI,
    PROVIDER_RAW,
    extract,
)


# ── OpenAI ───────────────────────────────────────────────────────────────────


def test_openai_chat_completions():
    body = json.dumps(
        {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "first question"},
                {"role": "assistant", "content": "an answer"},
                {"role": "user", "content": "second question"},
            ],
        }
    ).encode()
    got = extract(body, host="api.openai.com", path="/v1/chat/completions")

    assert got.provider == PROVIDER_OPENAI
    assert got.parsed is True
    assert got.turns == 4
    assert got.last_user == "second question", "must be the LAST user turn, not the first"
    # Everything is screenable, including the system prompt and the replayed answer.
    for fragment in ("You are helpful.", "first question", "an answer", "second question"):
        assert fragment in got.text


def test_openai_content_blocks_and_images():
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "what is in this picture"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                    ],
                }
            ]
        }
    ).encode()
    got = extract(body, host="api.openai.com")

    assert got.last_user == "what is in this picture"
    assert got.has_non_text is True
    assert "image_url" in got.non_text_kinds
    # The base64 payload must NOT be treated as prompt text.
    assert "AAAA" not in got.text


def test_openai_responses_api():
    body = json.dumps({"model": "gpt-4o", "instructions": "be terse", "input": "hello there"}).encode()
    got = extract(body, host="api.openai.com", path="/v1/responses")

    assert got.provider == PROVIDER_OPENAI
    assert got.last_user == "hello there"
    assert "be terse" in got.text


def test_openai_legacy_completions():
    got = extract(json.dumps({"prompt": "once upon a time"}).encode(), host="api.openai.com")
    assert got.provider == PROVIDER_OPENAI
    assert got.last_user == "once upon a time"


# ── Anthropic ────────────────────────────────────────────────────────────────


def test_anthropic_messages_with_system_string():
    body = json.dumps(
        {
            "model": "claude-opus-4",
            "system": "You are a support agent.",
            "messages": [{"role": "user", "content": "reset my password"}],
        }
    ).encode()
    got = extract(body, host="api.anthropic.com", path="/v1/messages")

    assert got.provider == PROVIDER_ANTHROPIC
    assert got.last_user == "reset my password"
    assert "You are a support agent." in got.text


def test_anthropic_system_blocks_and_tool_result():
    body = json.dumps(
        {
            "system": [{"type": "text", "text": "system block text"}],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "content": [{"type": "text", "text": "tool said this"}]},
                        {"type": "text", "text": "and my question"},
                    ],
                }
            ],
        }
    ).encode()
    got = extract(body, host="api.anthropic.com", path="/v1/messages")

    assert "system block text" in got.text
    # Nested tool results are content too: indirect injection arrives exactly here.
    assert "tool said this" in got.text
    assert "and my question" in got.last_user


def test_host_disambiguates_identical_shapes():
    """OpenAI and Anthropic both use `messages`; the host is the tiebreaker."""
    body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
    assert extract(body, host="api.anthropic.com").provider == PROVIDER_ANTHROPIC
    assert extract(body, host="api.openai.com").provider == PROVIDER_OPENAI


# ── Google ───────────────────────────────────────────────────────────────────


def test_google_contents_and_system_instruction():
    body = json.dumps(
        {
            "systemInstruction": {"parts": [{"text": "be brief"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "earlier turn"}]},
                {"role": "model", "parts": [{"text": "a reply"}]},
                {"role": "user", "parts": [{"text": "latest turn"}]},
            ],
        }
    ).encode()
    got = extract(body, host="generativelanguage.googleapis.com")

    assert got.provider == PROVIDER_GOOGLE
    assert got.turns == 3
    assert got.last_user == "latest turn"
    assert "be brief" in got.text
    assert "a reply" in got.text


def test_google_single_turn_without_role():
    body = json.dumps({"contents": {"parts": [{"text": "one shot"}]}}).encode()
    got = extract(body, host="generativelanguage.googleapis.com")
    assert got.last_user == "one shot"


def test_google_inline_data_is_non_text():
    body = json.dumps(
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "describe this"},
                        {"inline_data": {"mime_type": "image/png", "data": "SECRETBLOB"}},
                    ],
                }
            ]
        }
    ).encode()
    got = extract(body, host="gemini.google.com")

    assert got.last_user == "describe this"
    assert got.has_non_text is True
    assert "SECRETBLOB" not in got.text


# ── fallbacks ────────────────────────────────────────────────────────────────


def test_unknown_json_collapses_to_string_leaves():
    """A shape we do not know still has to feed Tier 1 DLP."""
    body = json.dumps({"query": "AKIAIOSFODNN7EXAMPLE", "nested": {"note": "call me"}}).encode()
    got = extract(body, host="ai.internal.example.com")

    assert got.provider == PROVIDER_JSON
    assert got.parsed is False, "unknown shapes must skip Tier 2 (spec §7)"
    assert "AKIAIOSFODNN7EXAMPLE" in got.text
    assert "call me" in got.text
    assert got.last_user == ""


def test_non_json_body_falls_back_to_raw_text():
    got = extract(b"key=AKIAIOSFODNN7EXAMPLE&x=1", host="api.openai.com")
    assert got.provider == PROVIDER_RAW
    assert got.parsed is False
    assert "AKIAIOSFODNN7EXAMPLE" in got.text


def test_json_array_body():
    got = extract(b'["alpha", "beta"]', host="api.openai.com")
    assert got.provider == PROVIDER_JSON
    assert "alpha" in got.text and "beta" in got.text


@pytest.mark.parametrize("body", [b"", b"   ", b"\n"])
def test_empty_body(body):
    got = extract(body)
    assert got.text == ""
    assert bool(got) is False


def test_invalid_utf8_does_not_raise():
    got = extract(b'{"messages":[{"role":"user","content":"caf\xff"}]}', host="api.openai.com")
    assert got.text  # replaced, not raised


def test_extraction_is_capped():
    huge = "x" * 50_000
    body = json.dumps({"messages": [{"role": "user", "content": huge}]}).encode()
    got = extract(body, host="api.openai.com", max_chars=1000)

    assert got.truncated is True
    assert len(got.text) <= 1000


def test_deeply_nested_json_terminates():
    node: object = "bottom"
    for _ in range(200):
        node = {"n": node}
    got = extract(json.dumps(node).encode(), host="ai.example.com")
    assert got.provider == PROVIDER_JSON  # depth-limited, not a RecursionError


# ── the server-side seam ─────────────────────────────────────────────────────


def test_icap_request_prompt_property_is_memoized():
    from icap.server import IcapRequest

    req = IcapRequest(
        method="REQMOD",
        service="/screen",
        headers={},
        body=json.dumps({"messages": [{"role": "user", "content": "seam check"}]}).encode(),
        http_headers={"host": "api.anthropic.com"},
    )
    first = req.prompt
    assert first.last_user == "seam check"
    assert req.prompt is first, "extraction must run once per transaction"


# ── web apps, which are not the same as the vendors' APIs ────────────────────


def test_chatgpt_web_app_body():
    """chatgpt.com nests role under `author` and text under `content.parts`.

    Before this was handled the extractor returned parsed=True with an empty
    string: the request read as clean, Tier 1 swept nothing, and the most
    common ChatGPT surface in an enterprise was silently invisible.
    """
    body = json.dumps(
        {
            "action": "next",
            "model": "gpt-4o",
            "messages": [
                {
                    "id": "aaa",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["my key is AKIAIOSFODNN7EXAMPLE"]},
                }
            ],
        }
    ).encode()
    got = extract(body, host="chatgpt.com", path="/backend-api/conversation")

    assert got.parsed is True
    assert got.last_user == "my key is AKIAIOSFODNN7EXAMPLE"
    assert "AKIAIOSFODNN7EXAMPLE" in got.text


def test_chatgpt_web_multimodal_asset_is_not_text():
    body = json.dumps(
        {
            "messages": [
                {
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [{"asset_pointer": "file-service://BLOB"}, "describe it"],
                    },
                }
            ]
        }
    ).encode()
    got = extract(body, host="chatgpt.com")

    assert got.last_user == "describe it"
    assert got.has_non_text is True
    assert "BLOB" not in got.text


def test_claude_web_app_body():
    body = json.dumps({"prompt": "secret AKIAIOSFODNN7EXAMPLE", "attachments": [], "files": []}).encode()
    got = extract(body, host="claude.ai", path="/api/organizations/x/chat_conversations/y/completion")

    assert got.provider == PROVIDER_ANTHROPIC
    assert got.last_user == "secret AKIAIOSFODNN7EXAMPLE"


# ── claude.ai Connect-RPC (binary protobuf) ─────────────────────────────────
#
# A structural twin of a real PerformAction request: same field numbers, same
# nesting, fake values. The captured original is not committed -- it carries a
# live session id, connector UUIDs and a user's whole tool inventory.

CLAUDE_TURN_PATH = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction"
PRICING_PROMPT = (
    "our margin on this handbag is 62% and the supplier cost is 400 AED, "
    "how do i send this to my new partner create a deck"
)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | 0x80 if n else byte)
        if not n:
            return bytes(out)


def pb_len(field: int, payload: bytes | str) -> bytes:
    payload = payload.encode() if isinstance(payload, str) else payload
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def pb_int(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def claude_turn(prompt: str | None, tools=("srv-1:DEMO_account_lookup", "srv-2:exploit_with_metasploit")) -> bytes:
    ids = pb_len(1, pb_len(1, pb_len(1, "sess_0000test") + pb_int(2, 1))
                 + pb_len(2, "00000000-0000-4000-8000-000000000001"))
    toolset = pb_len(8, pb_len(1, pb_len(8, b"".join(pb_len(1, pb_len(1, t)) for t in tools))))
    action = (
        pb_len(1, "00000000-0000-4000-8000-000000000002")
        + pb_len(2, "00000000-0000-4000-8000-000000000003")
        + (pb_len(3, prompt) if prompt is not None else b"")
        + pb_len(7, pb_len(2, "claude-opus-5"))
        + toolset
    )
    return ids + pb_len(2, action)


def test_claude_rpc_turn_is_exactly_what_was_typed():
    """claude.ai moved chat to Connect-RPC with the protobuf codec. Before this,
    json.loads failed on byte one, the body parsed as `raw`, and Tier 2 -- the
    only layer that catches a sentence with no pattern in it -- never ran."""
    got = extract(claude_turn(PRICING_PROMPT), host="claude.ai", path=CLAUDE_TURN_PATH)

    assert got.provider == PROVIDER_ANTHROPIC
    assert got.parsed is True, "parsed=False is what skips Tier 2"
    assert got.last_user == PRICING_PROMPT


def test_claude_rpc_sends_the_turn_not_the_tool_inventory():
    """~16 KB of every request is the user's enabled tool names. Tier 2 gets
    the turn; the inventory is not part of what was said."""
    got = extract(claude_turn(PRICING_PROMPT), host="claude.ai", path=CLAUDE_TURN_PATH)

    assert "exploit_with_metasploit" not in got.last_user
    assert "sess_0000test" not in got.last_user


def test_claude_rpc_still_gives_tier_1_the_whole_body():
    """`text` carries everything screenable, as before this handler existed. A
    key pasted anywhere in the request is just as leaked."""
    got = extract(claude_turn("hello", tools=("srv:AKIAIOSFODNN7EXAMPLE",)),
                  host="claude.ai", path=CLAUDE_TURN_PATH)

    assert "AKIAIOSFODNN7EXAMPLE" in got.text


@pytest.mark.parametrize("version", ["v1alpha", "v1beta", "v1", "v2"])
def test_claude_rpc_survives_a_package_version_bump(version):
    path = f"/claudeai-rpc/anthropic.bard.api.{version}.ConversationService/PerformAction"
    assert extract(claude_turn(PRICING_PROMPT), host="claude.ai", path=path).parsed is True


def test_claude_rpc_action_without_typed_text_falls_back():
    """PerformAction also carries small actions with no turn in them."""
    got = extract(claude_turn(None), host="claude.ai", path=CLAUDE_TURN_PATH)

    assert got.parsed is False
    assert got.provider == PROVIDER_RAW


@pytest.mark.parametrize("body", [
    b"\x0a\xff\xff\xff\xff\x0f",            # length far past the end
    b"\x0b\x00",                             # wire type 3, a proto2 group
    b"\x00\x01",                             # field number 0
    b"not protobuf at all, just text",
    claude_turn(PRICING_PROMPT)[:-7],        # truncated mid-field
])
def test_claude_rpc_malformed_body_falls_back_and_never_raises(body):
    got = extract(body, host="claude.ai", path=CLAUDE_TURN_PATH)

    assert got.parsed is False, "a body we could not walk must not claim a turn"


def test_claude_rpc_shape_is_not_claimed_on_another_host():
    """Keyed on claude.ai. The same bytes elsewhere are someone else's
    protocol, and guessing at it is how a confident wrong answer happens."""
    got = extract(claude_turn(PRICING_PROMPT), host="api.example.com", path=CLAUDE_TURN_PATH)

    assert got.parsed is False


# ── gemini.google.com (form-encoded, JSON inside a JSON string) ─────────────
#
# Structural twin of a real StreamGenerate request with fake tokens. The
# original carries a Google anti-abuse attestation token and is not committed.

GEMINI_TURN_PATH = "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate"
FAKE_ATTESTATION = "!FAKE-attestation-" + "x" * 64
FAKE_XSRF = "FAKE_XSRF_TOKEN:1789000000000"


def gemini_turn(prompt, at: str = FAKE_XSRF) -> bytes:
    from urllib.parse import urlencode

    inner = [None] * 30
    inner[0] = [prompt, 0, None, None, None, None, 0]
    inner[1] = ["en"]
    inner[2] = ["", "", "", None, None, None, None, None, None, ""]
    inner[3] = FAKE_ATTESTATION
    inner[4] = "0" * 32
    inner[6], inner[7] = [0], 1
    freq = json.dumps([None, json.dumps(inner)])
    return (urlencode({"f.req": freq, "at": at}) + "&").encode()


def test_gemini_turn_is_exactly_what_was_typed():
    """Gemini's form body failed json.loads, parsed as raw, and skipped Tier 2:
    the margin prompt blocked on ChatGPT and was answered on Gemini."""
    got = extract(gemini_turn(PRICING_PROMPT), host="gemini.google.com", path=GEMINI_TURN_PATH)

    assert got.provider == PROVIDER_GOOGLE
    assert got.parsed is True
    assert got.last_user == PRICING_PROMPT


def test_gemini_tokens_never_reach_the_turn():
    """The form carries a login-bound anti-forgery token and a ~2.7 KB
    attestation token. Neither is something the user said."""
    got = extract(gemini_turn(PRICING_PROMPT), host="gemini.google.com", path=GEMINI_TURN_PATH)

    assert FAKE_XSRF not in got.last_user
    assert FAKE_ATTESTATION not in got.last_user


def test_gemini_tier_1_sees_decoded_text():
    """The raw fallback handed the regexes the URL-ENCODED body, so an address
    typed into Gemini arrived as `name%40bank.com` and no email rule matched.
    Tier 1 gets the decoded turn now."""
    got = extract(gemini_turn("email john.doe@bankco.com about his account"),
                  host="gemini.google.com", path=GEMINI_TURN_PATH)

    assert "john.doe@bankco.com" in got.text


@pytest.mark.parametrize("body", [
    b"at=only-a-token&",                                      # no f.req
    b"f.req=not%20json&",                                     # f.req is not JSON
    b"f.req=%5Bnull%2C%22not%20json%20either%22%5D&",         # inner is not JSON
    b"f.req=%5Bnull%2C%22%5B%5B42%5D%5D%22%5D&",              # turn is not a string
    b"f.req=%5Bnull%5D&",                                     # outer too short
    b"\xff\xfe binary",
])
def test_gemini_unexpected_body_falls_back_and_never_raises(body):
    got = extract(body, host="gemini.google.com", path=GEMINI_TURN_PATH)

    assert got.parsed is False


def test_gemini_empty_turn_is_not_claimed():
    assert extract(gemini_turn("   "), host="gemini.google.com", path=GEMINI_TURN_PATH).parsed is False


def test_gemini_shape_is_not_claimed_on_another_host():
    got = extract(gemini_turn(PRICING_PROMPT), host="example.com", path=GEMINI_TURN_PATH)

    assert got.parsed is False


# ── Microsoft Copilot (SignalR over a WebSocket) ────────────────────────────
#
# Consumer Copilot and Microsoft 365 Copilot both frame the turn in SignalR's
# JSON hub protocol. This twin matches a real M365 frame; the captured original
# carried a live Entra bearer token in the socket URL and is not committed.

from icap.extract import PROVIDER_COPILOT

COPILOT_SOCKET_PATH = "/m365Copilot/Chathub/14b54f0d-03e5@7dd39627"
RS = b"\x1e"


def signalr_turn(prompt, extra_records=True) -> bytes:
    turn = {
        "arguments": [{
            "source": "officeweb",
            "optionsSets": ["cwc_flux_v3", "rich_responses"],
            "message": {
                "author": "user", "inputMethod": "Keyboard",
                "text": prompt, "messageType": "Chat",
            },
        }],
        "target": "chat", "type": 4,
    }
    records = [json.dumps(turn).encode()]
    if extra_records:
        metrics = {"arguments": [{"Timestamps": {"ConnectionStart": "2026-09-21T08:09:32Z"}}],
                   "target": "Metrics", "type": 1}
        records.append(json.dumps(metrics).encode())
    return RS.join(records) + RS


def test_copilot_signalr_turn_is_exactly_what_was_typed():
    """M365/consumer Copilot carry the turn over a socket in SignalR frames.
    Squid excludes socket upgrades from adaptation, so before this Copilot got
    NO screening -- not even the regex tier the other web apps had."""
    got = extract(signalr_turn(PRICING_PROMPT), host="substrate.office.com", path=COPILOT_SOCKET_PATH)

    assert got.provider == PROVIDER_COPILOT
    assert got.parsed is True
    assert got.last_user == PRICING_PROMPT


def test_copilot_ignores_the_metrics_frame_in_the_same_buffer():
    """A SignalR buffer holds several 0x1e-separated records: the turn (type 4)
    and a Metrics frame (type 1). Only the turn is the turn."""
    got = extract(signalr_turn(PRICING_PROMPT), host="substrate.office.com", path=COPILOT_SOCKET_PATH)

    assert "Timestamps" not in got.last_user
    assert "ConnectionStart" not in got.last_user


def test_copilot_matches_consumer_host_too():
    got = extract(signalr_turn(PRICING_PROMPT), host="copilot.microsoft.com",
                  path="/c/api/chat/chathub")
    assert got.provider == PROVIDER_COPILOT and got.parsed is True


def test_copilot_is_not_claimed_on_substrate_non_chat_paths():
    """substrate.office.com also carries Outlook and calendar APIs. A mail call
    is not a Copilot turn, even though the host matches."""
    got = extract(signalr_turn(PRICING_PROMPT), host="substrate.office.com",
                  path="/api/v2.0/me/messages")
    assert got.parsed is False


def test_copilot_token_in_a_frame_never_reaches_the_turn():
    """Defense in depth: the token rides in the socket URL, not the body, but a
    crafted frame with a JWT-shaped field must not end up in last_user."""
    jwt = "eyJ0eXAiOiJKV1QiLIVE_BEARER"
    turn = {"arguments": [{"access_token": jwt,
                           "message": {"author": "user", "text": "hello", "messageType": "Chat"}}],
            "target": "chat", "type": 4}
    got = extract(json.dumps(turn).encode() + RS, host="substrate.office.com", path=COPILOT_SOCKET_PATH)

    assert got.last_user == "hello"
    assert jwt not in got.last_user


@pytest.mark.parametrize("body", [
    b"not signalr at all",
    b"\x1e\x1e",                                              # only separators
    json.dumps({"type": 1, "target": "Metrics"}).encode() + RS,   # no turn record
    json.dumps({"type": 4, "arguments": []}).encode() + RS,        # empty arguments
    json.dumps({"type": 4, "arguments": [{"message": {"author": "bot", "text": "x"}}]}).encode() + RS,
])
def test_copilot_malformed_or_non_turn_falls_back(body):
    got = extract(body, host="substrate.office.com", path=COPILOT_SOCKET_PATH)
    assert got.parsed is False


def test_copilot_shape_is_not_claimed_on_another_host():
    got = extract(signalr_turn(PRICING_PROMPT), host="example.com", path=COPILOT_SOCKET_PATH)
    assert got.parsed is False


def test_recognised_shape_with_no_readable_text_is_salvaged():
    """The general guard behind the chatgpt.com fix.

    If a provider changes its body shape, the failure must be loud and must
    still feed DLP. Reporting success on an empty haystack is the one outcome
    that reads as safe while being blind.
    """
    body = json.dumps(
        {"messages": [{"unknown": "shape", "buried": "AKIAIOSFODNN7EXAMPLE"}]}
    ).encode()
    got = extract(body, host="api.openai.com")

    assert got.parsed is False, "an unreadable shape must not claim to be screened"
    assert "AKIAIOSFODNN7EXAMPLE" in got.text, "DLP must still get the body"
    assert any(k.startswith("unread-shape:") for k in got.non_text_kinds)


# ── compressed request bodies ────────────────────────────────────────────────


def test_compressed_body_is_decoded_before_extraction():
    """The claude.ai failure, in one test.

    Browsers compress REQUEST bodies, not just responses. Without decoding,
    the body is not JSON, so it extracts as `raw`, skips the server screen,
    and hands the DLP sweep compressed bytes that match no rule -- while the
    transaction logs decision=allow like a clean prompt. chatgpt.com blocked
    correctly and claude.ai did not, with identical policy.
    """
    import gzip as _gzip

    from icap.decompress import decode

    body = json.dumps({"prompt": "our margin is 62% and supplier cost 400 AED"}).encode()
    blob = _gzip.compress(body)

    # Undecoded, this is what the adapter used to see.
    assert extract(blob, host="claude.ai").provider == PROVIDER_RAW

    decoded, enc = decode(blob, "gzip")
    assert enc == "gzip"
    got = extract(decoded, host="claude.ai")
    assert got.parsed is True
    assert "margin" in got.last_user


def test_encoding_detected_without_a_header():
    """Content-Encoding is a declaration, and requests do not always carry a
    correct one. Magic bytes are the fallback."""
    import gzip as _gzip

    from icap.decompress import decode, sniff

    blob = _gzip.compress(b'{"prompt":"hello"}')
    assert sniff(blob) == "gzip"
    decoded, enc = decode(blob, "")          # no header at all
    assert enc == "gzip" and b"hello" in decoded


def test_undecodable_body_is_passed_through_not_dropped():
    """A body we cannot read must still reach the DLP sweep. Unreadable is a
    coverage gap to report, not a reason to fail an employee's request."""
    from icap.decompress import decode

    junk = b"\x1f\x8b" + b"not actually gzip"
    out, enc = decode(junk, "gzip")
    assert out == junk
    assert enc == ""


def test_decompression_is_bounded():
    """A small body that expands to gigabytes is a zip bomb, and this runs
    inline on a gateway."""
    import gzip as _gzip

    from icap.decompress import MAX_DECOMPRESSED, decode

    bomb = _gzip.compress(b"A" * (MAX_DECOMPRESSED + 5_000_000))
    out, enc = decode(bomb, "gzip")
    assert enc == "gzip"
    assert len(out) == MAX_DECOMPRESSED
