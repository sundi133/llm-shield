"""The tag file, its version, SRI hash and install snippet (spec sections 2.3
and 11). One source of truth for the collector's /shs.js, the release script's
check and the portal's Tag page.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import html
import pathlib
import re

PATH = pathlib.Path(__file__).resolve().parents[2] / "static" / "agent-detection" / "shs.js"
MAX_BYTES = 15 * 1024
_VERSION_RE = re.compile(r"@version (\d+\.\d+\.\d+)")


@functools.lru_cache(maxsize=1)
def source() -> bytes:
    return PATH.read_bytes()


def version(src: bytes | None = None) -> str:
    m = _VERSION_RE.search((src or source())[:400].decode("utf-8", "replace"))
    if not m:
        raise ValueError("shs.js has no @version x.y.z in its first comment")
    return m.group(1)


def sri(src: bytes | None = None) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(src or source()).digest()).decode()


def filename(src: bytes | None = None) -> str:
    return f"shs-{version(src)}.js"


def snippet(site_key: str, tag_base: str, collector: str = "", consent: str = "none") -> str:
    """The <script> line a customer pastes. `tag_base` is where released
    files live (our CDN, or the collector for self-hosting)."""
    attrs = [f'src="{html.escape(tag_base.rstrip("/") + "/" + filename())}"',
             f'integrity="{sri()}"', 'crossorigin="anonymous"',
             f'data-site="{html.escape(site_key)}"']
    if collector:
        attrs.append(f'data-collector="{html.escape(collector.rstrip("/"))}"')
    if consent == "required":
        attrs.append('data-consent="required"')
    return "<script " + " ".join(attrs) + " async></script>"
