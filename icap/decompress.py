"""Decode a compressed request body before anything tries to read it.

Browsers increasingly compress REQUEST bodies, not just responses. claude.ai
does; chatgpt.com does not. The failure mode is quiet and total: the body is
not JSON, so extraction falls back to raw, Tier 2 is skipped for an unparsed
shape, and Tier 1 sweeps compressed bytes that match no rule. The transaction
logs `decision=allow` and looks like a clean prompt.

That is how claude.ai went uninspected while chatgpt.com blocked correctly,
with the same policy and the same proxy.

Content-Encoding is the declaration, but it is not always present or correct on
a request, so magic bytes are checked too. Decompression is bounded: a small
body that expands to gigabytes is a zip bomb, and this runs inline on a
gateway.
"""
from __future__ import annotations

import gzip
import logging
import zlib
from typing import Optional

log = logging.getLogger("shield.icap")

# Ceiling on the DECOMPRESSED size. A 1 MiB request that expands past this is
# not a prompt, and expanding it would be the attack rather than the defence.
MAX_DECOMPRESSED = 8 * 1024 * 1024


def _gzip(raw: bytes) -> bytes:
    return gzip.decompress(raw)


def _deflate(raw: bytes) -> bytes:
    try:
        return zlib.decompress(raw)
    except zlib.error:
        # Raw deflate without a zlib header, which some clients send.
        return zlib.decompress(raw, -zlib.MAX_WBITS)


def _brotli(raw: bytes) -> bytes:
    import brotli  # optional dependency

    return brotli.decompress(raw)


def _zstd(raw: bytes) -> bytes:
    try:
        from compression import zstd  # Python 3.14+

        return zstd.decompress(raw)
    except ImportError:
        import zstandard

        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=MAX_DECOMPRESSED)


_DECODERS = {
    "gzip": _gzip,
    "x-gzip": _gzip,
    "deflate": _deflate,
    "br": _brotli,
    "zstd": _zstd,
}

# Checked when Content-Encoding is absent or lying, which happens.
_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x78\x01", "deflate"),
    (b"\x78\x9c", "deflate"),
    (b"\x78\xda", "deflate"),
)


def sniff(raw: bytes) -> Optional[str]:
    """Guess the encoding from magic bytes. Brotli has none, hence the header."""
    for prefix, name in _MAGIC:
        if raw.startswith(prefix):
            return name
    return None


def decode(raw: bytes, content_encoding: str = "") -> tuple[bytes, str]:
    """Return (decoded bytes, encoding actually applied).

    Never raises. A body that will not decode is returned untouched, because a
    request we cannot read must still reach Tier 1's regex sweep rather than
    being dropped: unreadable is a coverage gap to report, not a reason to
    fail the employee's request.
    """
    if not raw:
        return raw, ""

    # Content-Encoding can be a list ("gzip, br"); the last applied is the
    # outermost, which is what we have to undo first.
    declared = [e.strip().lower() for e in (content_encoding or "").split(",") if e.strip()]
    order = list(reversed(declared)) or ([sniff(raw)] if sniff(raw) else [])

    data = raw
    applied: list[str] = []
    for enc in order:
        if enc in ("identity", "", None):
            continue
        decoder = _DECODERS.get(enc)
        if decoder is None:
            log.warning("icap unknown content-encoding=%s, body left as-is", enc)
            break
        try:
            out = decoder(data)
        except ImportError:
            # The image is missing an optional codec. Loud, because it means a
            # whole provider is silently uninspected until it is installed.
            log.error(
                "icap cannot decode content-encoding=%s: codec not installed. "
                "Requests from this provider are NOT being screened.", enc,
            )
            break
        except Exception as exc:
            log.warning("icap failed to decode content-encoding=%s: %s", enc, exc)
            break
        if len(out) > MAX_DECOMPRESSED:
            log.warning(
                "icap decompressed body over cap (%d bytes, encoding=%s); truncating",
                len(out), enc,
            )
            out = out[:MAX_DECOMPRESSED]
        data = out
        applied.append(enc)

    return data, "+".join(applied)
