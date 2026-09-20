"""WebSocket message screening (icap/ws_screen.py).

The gap these cover: Codex CLI carries its prompt inside a WebSocket, so the
ICAP path sees only the client's analytics and screens nothing that matters.
These tests pin the decision half of the fix. No mitmproxy import, so they run
in CI without the proxy stack.
"""
from __future__ import annotations

import json

import pytest

from icap.policy import compile_bundle
from icap.ws_screen import (
    ALLOW,
    BLOCK,
    MAX_CLOSE_REASON_BYTES,
    POLICY_CLOSE_CODE,
    SKIP,
    SKIP_BINARY,
    SKIP_COMPRESSED,
    SKIP_EMPTY_POLICY,
    SKIP_NO_TEXT,
    WOULD_BLOCK,
    AssembledMessage,
    MessageAssembler,
    close_reason,
    decide,
)

BUNDLE = compile_bundle(
    {
        "tenant_id": "bankco",
        "version": "test",
        "rules": [
            {"id": "email-mask", "regex": r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}",
             "action": "block", "severity": "medium"},
        ],
        "blocklists": ["project titan"],
    }
)
EMPTY = compile_bundle({"tenant_id": "t", "version": "v", "rules": []})


def msg(text_or_obj, *, opcode="text", frames=1, truncated=False) -> AssembledMessage:
    raw = text_or_obj if isinstance(text_or_obj, str) else json.dumps(text_or_obj)
    data = raw.encode()
    return AssembledMessage(data=data, opcode=opcode, frames=frames,
                            size=len(data), truncated=truncated)


# ── assembly ─────────────────────────────────────────────────────────────


def test_fragmented_message_is_assembled_before_screening():
    """A prompt split across continuation frames must be judged whole.

    Screening frame by frame would miss any rule whose match straddles the
    boundary, which is the default way a long paste arrives.
    """
    a = MessageAssembler(cap=1024)
    assert a.add(b'{"content":"email joh', fin=False, opcode="text") is None
    out = a.add(b'n.doe@bankco.com now"}', fin=True)
    assert out is not None
    assert out.frames == 2
    assert b"john.doe@bankco.com" in out.data
    assert decide(BUNDLE, out).action == BLOCK


def test_assembler_resets_between_messages():
    a = MessageAssembler(cap=1024)
    a.add(b"first", fin=True, opcode="text")
    second = a.add(b"second", fin=True, opcode="text")
    assert second.data == b"second" and second.frames == 1


def test_oversize_message_is_capped_but_still_screened():
    """The retained prefix is screened, and the message is marked truncated.

    Dropping it instead would make a large paste a silent bypass: the bigger
    the leak, the less likely it is to be looked at.
    """
    a = MessageAssembler(cap=64)
    out = a.add(b"email john.doe@bankco.com " + b"x" * 500, fin=True, opcode="text")
    assert out.truncated is True
    assert out.size == 526
    d = decide(BUNDLE, out)
    assert d.action == BLOCK and d.truncated is True


# ── what cannot be read is named, not called clean ───────────────────────


def test_binary_frames_are_skipped_not_allowed():
    d = decide(BUNDLE, msg("ignored", opcode="binary"))
    assert d.action == SKIP and d.reason == SKIP_BINARY


def test_compressed_messages_are_skipped_not_allowed():
    d = decide(BUNDLE, msg({"content": "email john.doe@bankco.com"}), compressed=True)
    assert d.action == SKIP and d.reason == SKIP_COMPRESSED


def test_empty_policy_is_skipped_with_its_own_reason():
    d = decide(EMPTY, msg({"content": "email john.doe@bankco.com"}))
    assert d.action == SKIP and d.reason == SKIP_EMPTY_POLICY


def test_message_with_no_readable_text_is_skipped():
    d = decide(BUNDLE, msg("   "))
    assert d.action == SKIP and d.reason == SKIP_NO_TEXT


# ── verdicts ─────────────────────────────────────────────────────────────


def test_clean_message_is_allowed():
    d = decide(BUNDLE, msg({"messages": [{"role": "user", "content": "weather in Paris"}]}))
    assert d.action == ALLOW and d.rule_id == ""


def test_rule_match_blocks_in_enforce():
    d = decide(BUNDLE, msg({"messages": [{"role": "user", "content": "mail bob@corp.com"}]}))
    assert d.action == BLOCK and d.rule_id == "email-mask"
    assert "bob@corp.com" not in json.dumps(d.payload), "the payload must not echo the prompt"


def test_blocklist_term_blocks():
    d = decide(BUNDLE, msg({"content": "summarise Project Titan for me"}))
    assert d.action == BLOCK and d.rule_id == "project titan"


def test_monitor_mode_reports_without_blocking():
    d = decide(BUNDLE, msg({"content": "mail bob@corp.com"}), enforcing=False)
    assert d.action == WOULD_BLOCK and d.rule_id == "email-mask"
    assert d.blocks is False


def test_unknown_shape_still_screens_via_string_leaves():
    """An unrecognised socket protocol must not become an unscreened one."""
    d = decide(BUNDLE, msg({"weird": {"nested": ["mail bob@corp.com"]}}))
    assert d.action == BLOCK
    assert d.parsed is False


def test_non_json_text_frame_is_screened_as_raw_text():
    d = decide(BUNDLE, msg("plain text with bob@corp.com inside"))
    assert d.action == BLOCK


def test_scan_timeout_allows_and_is_named():
    """A pattern that cannot finish is a broken pattern, not a verdict."""
    class Exploding:
        empty = False
        version = "v"

        @property
        def rules(self):
            raise TimeoutError("budget exhausted")

    d = decide(Exploding(), msg({"content": "anything"}))
    assert d.action == ALLOW and d.reason == "scan_timeout"


# ── the close frame ──────────────────────────────────────────────────────


def test_close_reason_fits_the_protocol_limit():
    r = close_reason("email-mask", "3f3ed7c5-a3ae-44a3-b3b3-863e87ecc3db")
    assert len(r.encode()) <= MAX_CLOSE_REASON_BYTES
    assert "3f3ed7c5" in r


def test_close_reason_keeps_the_reference_when_the_rule_is_long():
    """Support can resolve a reference; it cannot resolve a truncated sentence."""
    txn = "3f3ed7c5-a3ae-44a3-b3b3-863e87ecc3db"
    r = close_reason("a-very-long-rule-name-" * 10, txn)
    assert len(r.encode()) <= MAX_CLOSE_REASON_BYTES
    assert txn in r


def test_close_reason_never_splits_a_character():
    r = close_reason("policy-" + "é" * 200, "ref")
    assert len(r.encode()) <= MAX_CLOSE_REASON_BYTES
    r.encode("utf-8").decode("utf-8")  # raises if a sequence was cut


def test_policy_close_code_is_in_the_private_range():
    assert 4000 <= POLICY_CLOSE_CODE <= 4999


# ── the rule that outranks all of the above ──────────────────────────────


@pytest.mark.parametrize("content", [
    "please handle john.doe@bankco.com before the quarterly review",
    "please handle Project Titan before the quarterly review",
])
def test_decision_never_carries_what_the_user_typed(content):
    """The decision may name the POLICY; it must never quote the PROMPT.

    The distinction matters and is easy to get wrong. A blocklist rule's id is
    the configured term itself, so "project titan" legitimately appears in the
    message the user sees, exactly as it does on the ICAP path. What must never
    appear is the surrounding text the employee wrote, or a matched value the
    policy did not already contain, such as the address behind `email-mask`.
    """
    d = decide(BUNDLE, msg({"content": content}))
    rendered = f"{d.reason} {d.rule_id} {json.dumps(d.payload or {})}".lower()

    assert "quarterly review" not in rendered, "the user's own words leaked"
    assert "please handle" not in rendered, "the user's own words leaked"
    assert "john.doe@bankco.com" not in rendered, "a matched value leaked"
