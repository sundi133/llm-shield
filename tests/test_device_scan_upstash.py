"""Production Redis is the Upstash REST client, which has `scan` and no
`scan_iter`. The rollout kit list and enrollment token revoke called scan_iter
and answered 500 there; the in-memory and redis-py stores used in tests hid it.
"""

import fnmatch
import pathlib
import re

from core.dlp import devices as dv
from core.dlp import kits

ROOT = pathlib.Path(__file__).resolve().parent.parent


class UpstashLike:
    """SCAN in pages of two with string cursors, as the REST client returns
    them, and no scan_iter."""

    def __init__(self, keys):
        self.keys = list(keys)

    def scan(self, cursor, match="*", count=10):
        start = int(cursor)
        page = self.keys[start:start + 2]
        nxt = start + 2
        return (str(nxt) if nxt < len(self.keys) else "0",
                [k for k in page if fnmatch.fnmatch(k, match)])


def test_scan_keys_pages_without_scan_iter():
    r = UpstashLike(["device_kit:t:1", "other:1", b"device_kit:t:2", "device_kit:u:9",
                     "device_kit:t:3"])
    r.keys = [k if isinstance(k, str) else k for k in r.keys]
    r.scan = lambda cursor, match="*", count=10: (
        (str(int(cursor) + 2) if int(cursor) + 2 < len(r.keys) else "0"),
        [k for k in r.keys[int(cursor):int(cursor) + 2]
         if fnmatch.fnmatch(dv._decode(k), match)])
    assert not hasattr(r, "scan_iter")
    assert dv.scan_keys(r, "device_kit:t:*") == ["device_kit:t:1", "device_kit:t:2",
                                                 "device_kit:t:3"]


def test_kit_list_scan_works_on_an_upstash_like_client(monkeypatch):
    r = UpstashLike(["device_kit:acme:kit_a", "device_enroll:acme:x", "device_kit:acme:kit_b"])
    monkeypatch.setattr(dv, "_redis", lambda: r)
    assert kits._scan("device_kit:acme:") == ["device_kit:acme:kit_a", "device_kit:acme:kit_b"]


def test_nothing_on_the_server_calls_scan_iter():
    hits = []
    for folder in ("core", "api", "storage", "icap"):
        for path in (ROOT / folder).rglob("*.py"):
            if re.search(r"\.scan_iter\(", path.read_text(errors="replace")):
                hits.append(str(path.relative_to(ROOT)))
    assert hits == [], f"scan_iter is not available on the Upstash REST client: {hits}"
