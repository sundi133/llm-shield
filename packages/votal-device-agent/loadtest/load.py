"""The load generator and resource sampler (docs/specs/device-agent-load-test.md).

N concurrent "tabs" by profile. Each request is sent once through the agent's
proxy and once directly to the fake AI service, in random order, and the
difference is the agent's added latency. Request classes:

  prompt_s / prompt_l   a chat POST (0.2-2 KB / 10-30 KB prompt), keep-alive
  sse                   a streamed reply: time to first event and to the end
  ws                    a chat frame over a WebSocket, send to echo
  tunnel                a non-AI host (127.0.0.1) through the proxy: must be a
                        plain tunnel, so the client trusts only the service's CA
                        (a decrypted tunnel fails the handshake) and the echoed
                        bytes must be identical
  upload / upload_over  256 KiB-1 MiB / just over 1 MiB (passes unscreened)

Imports psutil and websockets lazily, inside the functions that need them.
"""
from __future__ import annotations

import http.client
import json
import os
import random
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parents[3]
DATASET = REPO / "dlp-bench" / "dlp_eval.jsonl"
TIMEOUT_S = 30.0


def load_prompts(path: Path = DATASET, *, benign_only: bool = False) -> list[str]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [r["text"] for r in rows if not (benign_only and r.get("sensitive"))]


def sample_prompt(rng: random.Random, prompts: list[str], lo: int, hi: int) -> str:
    """Deterministic for a seeded rng: prompts joined until the target size."""
    target = rng.randint(lo, hi)
    parts, n = [], 0
    while n < target:
        p = prompts[rng.randrange(len(prompts))]
        parts.append(p)
        n += len(p) + 1
    return " ".join(parts)[:target]


class Endpoints:
    """Everything a tab needs to reach the agent and the fake service."""

    def __init__(self, proxy_port: int, http_port: int, ws_port: int, device_ca: str, upstream_ca: str):
        self.proxy_port, self.http_port, self.ws_port = proxy_port, http_port, ws_port
        self.ai_ctx = ssl.create_default_context(cafile=device_ca)       # what the agent signs
        self.ai_ctx.load_verify_locations(cafile=upstream_ca)
        self.up_ctx = ssl.create_default_context(cafile=upstream_ca)     # the service itself

    def conn(self, via_proxy: bool, host: str, ctx: Optional[ssl.SSLContext] = None):
        if via_proxy:
            c = http.client.HTTPSConnection("127.0.0.1", self.proxy_port, timeout=TIMEOUT_S,
                                            context=ctx or self.ai_ctx)
            c.set_tunnel(host, self.http_port)
            return c
        return http.client.HTTPSConnection(host, self.http_port, timeout=TIMEOUT_S,
                                           context=ctx or self.up_ctx)


def _chat(text: str) -> bytes:
    return json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": text}]}).encode()


class Tab:
    def __init__(self, ep: Endpoints, rng: random.Random, prompts: list[str],
                 benign: Optional[list[str]] = None):
        self.ep, self.rng, self.prompts = ep, rng, prompts
        # WebSocket frames use benign prompts only: the agent does not send the
        # 4403 close for a frame it blocks (the client waits until its own
        # timeout; a follow-up), so a sensitive frame would make the latency
        # class measure that bug at random instead of frame delay.
        self.benign = benign or prompts
        self._c: dict = {}
        self._ws: dict = {}

    def close(self):
        for c in self._c.values():
            try:
                c.close()
            except Exception:
                pass
        for w in self._ws.values():
            try:
                w.close()
            except Exception:
                pass

    # one timed request; returns (ms, status, body) or raises
    def _post(self, key, via_proxy, host, path, body, ctx=None):
        c = self._c.get(key)
        if c is None:
            c = self._c[key] = self.ep.conn(via_proxy, host, ctx)
        t0 = time.perf_counter()
        try:
            c.request("POST", path, body=body, headers={"Content-Type": "application/json",
                                                       "Host": f"{host}:{self.ep.http_port}"})
            r = c.getresponse()
            data = r.read()
        except Exception:
            self._c.pop(key, None)
            c.close()
            raise
        return (time.perf_counter() - t0) * 1000.0, r.status, data

    def _pair(self, fn) -> dict:
        """Proxied and direct, in random order."""
        out = {}
        for via in self.rng.sample([True, False], 2):
            name = "proxied" if via else "direct"
            try:
                out[name] = fn(via)
            except Exception as e:
                out[name] = e
        return out

    def run(self, cls: str) -> dict:
        r = self.rng
        if cls in ("prompt_s", "prompt_l"):
            lo, hi = (200, 2000) if cls == "prompt_s" else (10_000, 30_000)
            body = _chat(sample_prompt(r, self.prompts, lo, hi))
            res = self._pair(lambda via: self._post(("chat", via), via, "localhost",
                                                    "/v1/chat/completions", body))
            return _http_sample(res)
        if cls in ("upload", "upload_over"):
            size = r.randint(256 * 1024, 1024 * 1024) if cls == "upload" else r.randint(1_100_000, 1_500_000)
            body = (sample_prompt(r, self.prompts, 2000, 4000) * (size // 2000 + 1))[:size].encode()
            res = self._pair(lambda via: self._post(("up", via), via, "localhost", "/upload", body))
            return _http_sample(res)
        if cls == "tunnel":
            body = os.urandom(r.randint(1024, 8192))
            res = self._pair(lambda via: self._post(("tun", via), via, "127.0.0.1", "/echo", body,
                                                    ctx=self.ep.up_ctx))
            s = _http_sample(res)
            p = res.get("proxied")
            s["identical"] = not isinstance(p, Exception) and p[2] == body
            return s
        if cls == "sse":
            res = self._pair(self._sse)
            s = _http_sample({k: (v if isinstance(v, Exception) else (v[0], v[2], b""))
                              for k, v in res.items()})
            if not isinstance(res.get("proxied"), Exception) and not isinstance(res.get("direct"), Exception):
                s["ttfb_proxied_ms"], s["ttfb_direct_ms"] = res["proxied"][1], res["direct"][1]
            return s
        if cls == "ws":
            frame = _chat(sample_prompt(r, self.benign, 200, 2000)).decode()
            res = self._pair(lambda via: self._ws_round(via, frame))
            return _http_sample({k: (v if isinstance(v, Exception) else (v, 200, b""))
                                 for k, v in res.items()})
        raise ValueError(cls)

    def _sse(self, via_proxy: bool):
        c = self.ep.conn(via_proxy, "localhost")
        t0 = time.perf_counter()
        try:
            c.request("POST", "/v1/stream?chunks=10&ms=500", body=b"{}",
                      headers={"Content-Type": "application/json"})
            resp = c.getresponse()
            ttfb = None
            while True:
                line = resp.readline()
                if not line:
                    break
                if ttfb is None and line.startswith(b"data:"):
                    ttfb = (time.perf_counter() - t0) * 1000.0
                if line.startswith(b"data: [DONE]"):
                    break
            return (time.perf_counter() - t0) * 1000.0, ttfb, resp.status
        finally:
            c.close()

    def _ws_round(self, via_proxy: bool, frame: str) -> float:
        from websockets.sync.client import connect
        ws = self._ws.get(via_proxy)
        if ws is None:
            url = f"wss://localhost:{self.ep.ws_port}/chat"
            if via_proxy:
                sock = socket.create_connection(("127.0.0.1", self.ep.proxy_port), timeout=TIMEOUT_S)
                sock.sendall(f"CONNECT localhost:{self.ep.ws_port} HTTP/1.1\r\n"
                             f"Host: localhost:{self.ep.ws_port}\r\n\r\n".encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("proxy closed during CONNECT")
                    head += chunk
                if b" 200" not in head.split(b"\r\n", 1)[0]:
                    raise ConnectionError(head.split(b"\r\n", 1)[0].decode(errors="replace"))
                ws = connect(url, sock=sock, ssl=self.ep.ai_ctx, server_hostname="localhost",
                             open_timeout=TIMEOUT_S)
            else:
                ws = connect(url, ssl=self.ep.up_ctx, open_timeout=TIMEOUT_S)
            self._ws[via_proxy] = ws
        t0 = time.perf_counter()
        try:
            ws.send(frame)
            ws.recv(timeout=TIMEOUT_S)
        except Exception as e:
            self._ws.pop(via_proxy, None)
            code = getattr(getattr(e, "rcvd", None), "code", None)
            if code == 4403:                               # blocked by policy: expected
                return PolicyOutcome((time.perf_counter() - t0) * 1000.0)
            raise
        return (time.perf_counter() - t0) * 1000.0


class PolicyOutcome(float):
    """A WebSocket frame the agent blocked (close 4403): an expected outcome."""


def _http_sample(res: dict) -> dict:
    """{proxied_ms, direct_ms, outcome, error, direct_error} from a pair."""
    p, d = res.get("proxied"), res.get("direct")
    s: dict = {}
    if isinstance(d, Exception) or (isinstance(d, tuple) and d[1] >= 500):
        s["direct_error"] = repr(d)[:200]
    else:
        s["direct_ms"] = d[0]
    if isinstance(p, Exception):
        s["error"] = f"{type(p).__name__}: {str(p)[:160]}"
        s["outcome"] = "proxy_error"
        return s
    ms, status, body = p
    s["proxied_ms"] = ms
    if isinstance(ms, PolicyOutcome) or (status == 403 and b"votal" in (body or b"").lower()):
        s["outcome"] = "blocked"
        s.pop("proxied_ms", None)                          # a block is not a latency sample
    elif status >= 500:
        s["error"], s["outcome"] = f"HTTP {status}", "proxy_error"
    else:
        s["outcome"] = "ok" if status < 400 else f"http_{status}"
    if "direct_error" in s:
        s.pop("proxied_ms", None)                          # unpaired: not a latency sample
    return s


# ── the workload ──────────────────────────────────────────────────────

def run_workload(profile: dict, ep: Endpoints, *, seed: int = 7, stop: Optional[threading.Event] = None,
                 prompts: Optional[list[str]] = None) -> dict:
    """{class: [samples]}, {achieved_rps, t_start, t_end}. Samples in warm-up are dropped."""
    prompts = prompts or load_prompts()
    benign = load_prompts(benign_only=True)
    stop = stop or threading.Event()
    mix = profile["mix"]
    classes, weights = list(mix), [mix[c] for c in mix]
    t_start = time.time()
    t_end = t_start + profile["duration_s"]
    warm_until = t_start + profile.get("warmup_s", 0)
    out: dict = {c: [] for c in classes}
    lock = threading.Lock()
    total = {"n": 0}

    def tab(i: int):
        rng = random.Random(seed * 1000 + i)
        start_at = t_start + profile.get("ramp_s", 0) * i / max(1, profile["tabs"])
        while time.time() < start_at and not stop.is_set():
            time.sleep(0.05)
        t = Tab(ep, rng, prompts, benign)
        try:
            while time.time() < t_end and not stop.is_set():
                cls = rng.choices(classes, weights)[0]
                s = t.run(cls)
                s["t"] = time.time()
                with lock:
                    total["n"] += 1
                    if s["t"] >= warm_until:
                        out[cls].append(s)
                time.sleep(profile.get("think_ms", 200) / 1000.0)
        finally:
            t.close()

    threads = [threading.Thread(target=tab, args=(i,), daemon=True) for i in range(profile["tabs"])]
    for th in threads:
        th.start()
    for th in threads:
        th.join(profile["duration_s"] + 120)
    elapsed = max(1e-6, time.time() - t_start)
    return {"samples": out, "achieved_rps": round(total["n"] / elapsed, 2), "t_start": t_start,
            "t_end": time.time()}


class Sampler:
    """1 s samples of the agent (and Ollama), plus this generator's own CPU."""

    def __init__(self, agent_pid: int, with_ollama: bool = False):
        import psutil
        self.psutil = psutil
        self.agent = psutil.Process(agent_pid)
        self.me = psutil.Process()
        self.with_ollama = with_ollama
        self.samples: list[dict] = []
        self.gen_cpu: list[float] = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.agent.cpu_percent(None)
        self.me.cpu_percent(None)
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        self._t.join(5)

    def _ollama_rss_mb(self) -> Optional[float]:
        total = 0
        for p in self.psutil.process_iter(["name", "memory_info"]):
            if "ollama" in (p.info.get("name") or "").lower() and p.info.get("memory_info"):
                total += p.info["memory_info"].rss
        return total / 1e6 if total else None

    def _loop(self):
        while not self._stop.wait(1.0):
            try:
                s = {"t": time.time(), "cpu": self.agent.cpu_percent(None),
                     "rss_mb": self.agent.memory_info().rss / 1e6, "threads": self.agent.num_threads()}
            except self.psutil.Error:
                break
            if self.with_ollama:
                s["ollama_rss_mb"] = self._ollama_rss_mb()
            self.samples.append(s)
            self.gen_cpu.append(self.me.cpu_percent(None))
