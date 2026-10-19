"""The proxy's AI discovery shipper.

Spec: docs/specs/ai-discovery.md, task 3. It runs next to Squid and does two
things:

1. Reads Squid's discovery access log (UDP from Squid, or a file it tails),
   keeps only the hosts the AI catalog recognizes, aggregates them per user or
   client and host for five minutes, and posts the result to Shield as a
   `proxy` discovery batch. Every other host is dropped as it is read; nothing
   of the log is written anywhere.
2. Every five minutes, fetches the lists Shield keeps for the proxy and writes
   them for Squid: `ai_hosts.txt` (decrypted and inspected) and
   `blocked_hosts.txt` (denied). Squid's entrypoint reloads when they change.

Squid log line (squid.conf `logformat shield_discovery`):

    <epoch> <client ip> <sni or -> <url host or -> <user or ->

Standard library only. Configuration (environment):

    SHIELD_URL            https://api.guardrails.votal.ai
    SHIELD_API_KEY        a tenant key (a key scoped to discovery is enough)
    SHIELD_API_KEY_FILE   or read it from this file (a Docker secret)
    SHIPPER_LISTEN        udp listen address, default 0.0.0.0:5140
    SHIPPER_LOG_FILE      tail this file instead of listening on UDP
    SHIPPER_LISTS_DIR     where the list files go, default /lists
    SHIPPER_FLUSH_S       aggregation window, default 300
    SHIPPER_REFRESH_S     list refresh interval, default 300
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional

log = logging.getLogger("shield.discovery-shipper")

BATCH_MAX = 1000
KEEP_MAX = 20_000            # observations held while Shield is unreachable
PLACEHOLDER = "never-matches.invalid"
SHIELD_DOMAINS = ("votal.ai",)


# ── host matching (same rules as core/discovery/catalog.py) ──────────


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h in ("", "-"):
        return ""
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0].split("@")[-1]
    h = re.sub(r":\d+$", "", h)
    return h.rstrip(".")


def _matches(pattern: str, host: str) -> bool:
    p = pattern.lower().split("/")[0]
    if p.startswith("*."):
        return host.endswith(p[1:]) and host != p[2:]
    if "*" in p:
        rx = "^" + re.escape(p).replace(r"\*", "[a-z0-9-]+") + "$"
        return re.match(rx, host) is not None
    return host == p or host.endswith("." + p)


class Matcher:
    def __init__(self, patterns: Iterable[str]):
        self.patterns = sorted(set(patterns))
        self._cache: dict[str, bool] = {}

    def __call__(self, host: str) -> bool:
        if not host or any(host == d or host.endswith("." + d) for d in SHIELD_DOMAINS):
            return False
        hit = self._cache.get(host)
        if hit is None:
            if len(self._cache) > 50_000:
                self._cache.clear()
            hit = self._cache[host] = any(_matches(p, host) for p in self.patterns)
        return hit


def parse_line(line: str) -> Optional[tuple[int, str, str, str]]:
    """(epoch, host, subject type, subject id) or None."""
    parts = line.strip().split(None, 4)
    if len(parts) < 4:
        return None
    ts, client, sni, url_host = parts[:4]
    user = parts[4].strip() if len(parts) > 4 else "-"
    try:
        at = int(float(ts))
    except ValueError:
        return None
    host = normalize_host(sni) or normalize_host(url_host)
    if not host:
        return None
    if user and user != "-":
        return at, host, "user", user[:200]
    return at, host, "device", client[:200]


class Aggregator:
    """{(host, subject type, subject id): {seen_at, count}}, flushed as batches."""

    def __init__(self, matcher: Callable[[str], bool]):
        self.matcher = matcher
        self._agg: dict[tuple, dict] = {}
        self._lock = threading.Lock()
        self.dropped = 0

    def add(self, line: str) -> bool:
        p = parse_line(line)
        if p is None or not self.matcher(p[1]):
            return False
        at, host, st, sid = p
        with self._lock:
            a = self._agg.get((host, st, sid))
            if a is None:
                if len(self._agg) >= KEEP_MAX:
                    self.dropped += 1
                    return False
                a = self._agg[(host, st, sid)] = {"seen_at": at, "count": 0}
            a["count"] += 1
            a["seen_at"] = max(a["seen_at"], at)
        return True

    def take(self) -> list[dict]:
        with self._lock:
            agg, self._agg = self._agg, {}
        return [{"kind": "domain", "domain": h, "subject": {"type": st, "id": sid},
                 "seen_at": v["seen_at"], "count": v["count"]} for (h, st, sid), v in agg.items()]

    def put_back(self, obs: list[dict]) -> None:
        """Keep a batch Shield did not accept, for the next flush."""
        with self._lock:
            for o in obs:
                k = (o["domain"], o["subject"]["type"], o["subject"]["id"])
                a = self._agg.get(k)
                if a is None:
                    if len(self._agg) >= KEEP_MAX:
                        self.dropped += 1
                        continue
                    self._agg[k] = {"seen_at": o["seen_at"], "count": o["count"]}
                else:
                    a["count"] += o["count"]
                    a["seen_at"] = max(a["seen_at"], o["seen_at"])


# ── Shield ───────────────────────────────────────────────────────────


class Shield:
    def __init__(self, url: str, api_key: str, timeout: float = 15.0):
        self.url, self.api_key, self.timeout = url.rstrip("/"), api_key, timeout

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "X-API-Key": self.api_key, "Content-Type": "application/json",
            "User-Agent": "shield-discovery-shipper/1"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def lists(self) -> dict:
        return self._call("GET", "/v1/shield/discovery/lists")

    def post(self, observations: list[dict]) -> dict:
        return self._call("POST", "/v1/shield/discovery/batch",
                          {"source": "proxy", "observations": observations})


def flush(agg: Aggregator, shield: Shield) -> int:
    """Post what was aggregated. A batch Shield does not take (unreachable,
    503, 429) is kept for the next flush; a batch it rejects (4xx) is not."""
    obs = agg.take()
    sent = 0
    for i in range(0, len(obs), BATCH_MAX):
        chunk = obs[i:i + BATCH_MAX]
        try:
            shield.post(chunk)
            sent += len(chunk)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                agg.put_back(obs[i:])
                log.warning("Shield answered %s; keeping %d observations", e.code, len(obs) - i)
                break
            log.warning("Shield rejected a batch (%s); dropping it", e.code)
        except (urllib.error.URLError, OSError, ValueError) as e:
            agg.put_back(obs[i:])
            log.warning("Shield unreachable (%s); keeping %d observations", e, len(obs) - i)
            break
    return sent


# ── the list files Squid reads ───────────────────────────────────────


def squid_list(hosts: Iterable[str]) -> str:
    """One `.host` per line (the host and its subdomains), with hosts already
    covered by a parent left out, since Squid warns about overlaps. Never
    empty: an empty ACL file is a startup warning on some Squid versions."""
    clean = sorted({normalize_host(h) for h in hosts if normalize_host(h)}, key=lambda h: (h.count("."), h))
    keep: list[str] = []
    for h in clean:
        if not any(h == k or h.endswith("." + k) for k in keep):
            keep.append(h)
    return "\n".join("." + h for h in sorted(keep) or [PLACEHOLDER]) + "\n"


def write_lists(lists_dir: Path, lists: dict) -> bool:
    """Write ai_hosts.txt and blocked_hosts.txt atomically. True when either changed."""
    lists_dir.mkdir(parents=True, exist_ok=True)
    changed = False
    for name, hosts in (("ai_hosts.txt", lists.get("ai_hosts") or []),
                        ("blocked_hosts.txt", lists.get("blocked_hosts") or [])):
        text = squid_list(hosts)
        path = lists_dir / name
        try:
            if path.read_text() == text:
                continue
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=lists_dir, prefix=f".{name}.")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        changed = True
    return changed


# ── inputs ───────────────────────────────────────────────────────────


def listen_udp(addr: str, agg: Aggregator, stop: threading.Event) -> None:
    host, _, port = addr.rpartition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "0.0.0.0", int(port)))
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        for line in data.decode("utf-8", errors="replace").splitlines():
            agg.add(line)


def tail_file(path: Path, agg: Aggregator, stop: threading.Event, poll_s: float = 1.0) -> None:
    """Follow a log file across rotation (a new inode or a truncation). The
    file found at start is read from its end; a file that replaces it, from
    its start."""
    f, ino, first = None, None, True
    while not stop.is_set():
        if f is None:
            try:
                f = open(path, "r", encoding="utf-8", errors="replace")
                if first:
                    f.seek(0, os.SEEK_END)
                first = False
                ino = os.fstat(f.fileno()).st_ino
            except OSError:
                stop.wait(poll_s)
                continue
        line = f.readline()
        if line:
            agg.add(line)
            continue
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():
                f.close()
                f = None
                continue
        except OSError:
            pass
        stop.wait(poll_s)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    url, key = os.environ.get("SHIELD_URL", ""), os.environ.get("SHIELD_API_KEY", "")
    if not key and os.environ.get("SHIELD_API_KEY_FILE"):
        try:
            key = Path(os.environ["SHIELD_API_KEY_FILE"]).read_text().strip()
        except OSError as e:
            print(f"cannot read SHIELD_API_KEY_FILE: {e}", file=sys.stderr)
            return 2
    if not url or not key:
        print("set SHIELD_URL and SHIELD_API_KEY", file=sys.stderr)
        return 2
    shield = Shield(url, key)
    lists_dir = Path(os.environ.get("SHIPPER_LISTS_DIR", "/lists"))
    flush_s = float(os.environ.get("SHIPPER_FLUSH_S", "300"))
    refresh_s = float(os.environ.get("SHIPPER_REFRESH_S", "300"))
    agg = Aggregator(Matcher([]))
    stop = threading.Event()

    def refresh() -> None:
        try:
            lists = shield.lists()
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("could not fetch the lists (%s); keeping the current ones", e)
            return
        agg.matcher = Matcher(lists.get("domains") or [])
        if write_lists(lists_dir, lists):
            log.info("lists updated: %d inspected, %d blocked", len(lists.get("ai_hosts") or []),
                     len(lists.get("blocked_hosts") or []))

    def _term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)     # docker stop: send what was aggregated

    refresh()
    log_file = os.environ.get("SHIPPER_LOG_FILE", "")
    if log_file:
        reader = threading.Thread(target=tail_file, args=(Path(log_file), agg, stop), daemon=True)
    else:
        reader = threading.Thread(target=listen_udp,
                                  args=(os.environ.get("SHIPPER_LISTEN", "0.0.0.0:5140"), agg, stop),
                                  daemon=True)
    reader.start()
    next_flush, next_refresh = time.time() + flush_s, time.time() + refresh_s
    try:
        while True:
            time.sleep(1)
            now = time.time()
            if now >= next_flush:
                n = flush(agg, shield)
                if n:
                    log.info("sent %d observations", n)
                next_flush = now + flush_s
            if now >= next_refresh:
                refresh()
                next_refresh = now + refresh_s
    except KeyboardInterrupt:
        stop.set()
        flush(agg, shield)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
