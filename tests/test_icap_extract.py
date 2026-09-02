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
