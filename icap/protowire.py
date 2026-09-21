"""Just enough of the protobuf wire format to read one known field, schemaless.

Some AI web apps speak Connect-RPC or gRPC-web with the binary codec, so their
request bodies are protobuf rather than JSON. claude.ai is one: its chat turns
go to `ConversationService/PerformAction` as `application/proto`. `json.loads`
fails on the first byte, the body falls through to `raw`, and Tier 2 never sees
the prompt (spec §7).

Deliberately tiny. No schema, no descriptor pool, no dependency: it walks
fields by number and returns the strings at one path. Anything that is not a
well-formed message is refused outright rather than guessed at, so a body that
merely starts with plausible bytes cannot produce a confident wrong answer.
"""
from __future__ import annotations

from typing import Iterator

VARINT, I64, LEN, I32 = 0, 1, 2, 5


class WireError(ValueError):
    """The bytes are not a well-formed protobuf message."""


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    val = 0
    for shift in range(0, 70, 7):
        if i >= len(buf):
            raise WireError("truncated varint")
        byte = buf[i]
        i += 1
        val |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return val, i
    raise WireError("varint longer than 10 bytes")


def iter_fields(buf: bytes) -> Iterator[tuple[int, int, object]]:
    """Yield (field number, wire type, value) for one message level."""
    i, end = 0, len(buf)
    while i < end:
        key, i = _varint(buf, i)
        num, wire = key >> 3, key & 7
        if num == 0:
            raise WireError("field number 0")
        if wire == VARINT:
            val, i = _varint(buf, i)
        elif wire == I64:
            val, i = buf[i:i + 8], i + 8
        elif wire == I32:
            val, i = buf[i:i + 4], i + 4
        elif wire == LEN:
            size, i = _varint(buf, i)
            val, i = buf[i:i + size], i + size
        else:
            # 3 and 4 are proto2 groups, long deprecated; 6 and 7 do not exist.
            # Seeing one almost always means this is not protobuf at all.
            raise WireError(f"wire type {wire}")
        if i > end:
            raise WireError("field runs past the end of the message")
        yield num, wire, val


def strings_at(buf: bytes, path: tuple[int, ...]) -> list[str]:
    """Every UTF-8 string found at `path`, as field numbers from the root.

    Returns [] when the body is not a message of that shape. Never raises.
    """
    if not buf or not path:
        return []
    try:
        return list(_walk(buf, path))
    except (WireError, UnicodeDecodeError):
        return []


def _walk(buf: bytes, path: tuple[int, ...]) -> Iterator[str]:
    head, rest = path[0], path[1:]
    # Parse the whole level before yielding anything: a message with a
    # malformed tail is rejected as a whole, not half-read.
    for num, wire, val in list(iter_fields(buf)):
        if num != head or wire != LEN:
            continue
        if rest:
            yield from _walk(val, rest)
        else:
            yield val.decode("utf-8")
