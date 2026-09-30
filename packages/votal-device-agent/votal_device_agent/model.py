"""The local decision model: Tev1 0.8B on the agent's own Ollama (spec §3.2).

One call per judged chunk to `POST {ollama}/v1/systemone`. The agent starts a
dedicated Ollama on 127.0.0.1:11535, so a user's own Ollama is never touched.

`parse` and `model_verdict` are exactly what task 1 calibrated against
(dlp-bench/run_dlp_bench.py parse and decide); a test holds them equal, because
the thresholds in the bundle only mean something under that decision rule.
"""

from __future__ import annotations

import json
import platform
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable, Optional

DEFAULT_OLLAMA = "http://127.0.0.1:11535"
# Latency gates from spec §2.6: above them the model runs after sending.
GATE_MS = {"apple_silicon": 300.0, "x86_cpu": 800.0}

Http = Callable[[str, str, dict, Optional[bytes], float], tuple]


class ModelUnavailable(Exception):
    """state is model_unavailable, model_unsupported or model_mismatch."""

    def __init__(self, state: str, detail: str = ""):
        super().__init__(f"{state}: {detail}" if detail else state)
        self.state = state


def _urllib(method: str, url: str, headers: dict, body: Optional[bytes], timeout: float) -> tuple:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except OSError:
            return e.code, b""


def hardware_class() -> str:
    return ("apple_silicon" if platform.system() == "Darwin" and platform.machine() == "arm64"
            else "x86_cpu")


def parse(response: dict) -> dict:
    """{category, choice, p_category, confidence, probabilities, exfil}.
    The signal is 1 - P(none), labelled by the most likely other category."""
    a = response.get("answers") or {}
    cat = a.get("category") or {}
    probs = {k: float(v) for k, v in (cat.get("probabilities") or {}).items()}
    sensitive = {k: v for k, v in probs.items() if k != "none"}
    label = max(sensitive, key=sensitive.get) if sensitive else cat.get("choice")
    ex = a.get("exfil_intent") or {}
    return {"category": label,
            "choice": cat.get("choice"),
            "p_category": round(1.0 - probs.get("none", 0.0), 6) if probs else 0.0,
            "confidence": float(cat.get("confidence", 0.0)),
            "probabilities": probs,
            "exfil": float(ex.get("noul", 0.0))}


def model_verdict(p: dict, t: dict) -> str:
    """block, justify, allow or uncertain: the model rows of spec §3.2."""
    confident = p["confidence"] >= t["min_confidence"]
    cat = p["category"]
    if confident and cat in t["block_categories"] and p["p_category"] >= t["block_p"]:
        return "block"
    if confident and cat not in (None, "none") and p["p_category"] >= t["justify_p"]:
        return "justify"
    if p["exfil"] >= t["exfil_intent"]:
        return "justify"
    return "allow" if confident else "uncertain"


def _version_tuple(v: str) -> tuple:
    out = []
    for part in str(v).split("-")[0].split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out + [0] * (3 - len(out)))


class LatencyGate:
    """Whether the model may sit on the send path, from its own measured p95.

    Spec §2.6: hardware that misses the gate runs the model after sending
    (monitor), rules still inline. Until enough calls are measured the model
    runs after sending: an unmeasured model must not hold users' prompts.
    """

    def __init__(self, gate_ms: Optional[float] = None, window: int = 50, min_samples: int = 20,
                 override: str = "auto"):
        self.gate_ms = gate_ms if gate_ms is not None else GATE_MS[hardware_class()]
        self.samples: deque = deque(maxlen=window)
        self.min_samples = min_samples
        self.override = override              # auto | always | never
        self._lock = threading.Lock()

    def observe(self, ms: float) -> None:
        with self._lock:
            self.samples.append(ms)

    def p95(self) -> Optional[float]:
        with self._lock:
            s = sorted(self.samples)
        if not s:
            return None
        return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]

    def inline(self) -> bool:
        if self.override == "always":
            return True
        if self.override == "never":
            return False
        with self._lock:
            enough = len(self.samples) >= self.min_samples
        p = self.p95()
        return enough and p is not None and p <= self.gate_ms


class DecisionModel:
    """Client for the agent's dedicated Ollama."""

    def __init__(self, base_url: str = DEFAULT_OLLAMA, http: Http = _urllib,
                 gate: Optional[LatencyGate] = None):
        self.base = base_url.rstrip("/")
        self.http = http
        self.gate = gate or LatencyGate()
        self.state = "unknown"               # set by health()

    def _failed(self, state: str, detail: str) -> ModelUnavailable:
        # What the heartbeat reports: a model that stopped answering is not "ok"
        # just because it passed its last hourly check.
        if self.state not in ("model_mismatch",):
            self.state = state
        return ModelUnavailable(state, detail)

    def load(self, model: str, timeout_s: float = 120.0) -> bool:
        """Load the model into memory. The first call after Ollama starts pays the
        load (seconds); doing it here keeps that off every user's prompt."""
        try:
            status, _ = self.http("POST", f"{self.base}/api/generate",
                                  {"Content-Type": "application/json"},
                                  json.dumps({"model": model, "keep_alive": "24h"}).encode(),
                                  timeout_s)
        except (OSError, TimeoutError):
            return False
        return status == 200

    def decide(self, model: str, state: dict, questions: dict, timeout_s: float,
               observe: bool = True) -> dict:
        """parse()d answers. Raises ModelUnavailable."""
        body = json.dumps({"model": model, "state": state, "questions": questions}).encode()
        t0 = time.perf_counter()
        try:
            status, raw = self.http("POST", f"{self.base}/v1/systemone",
                                    {"Content-Type": "application/json"}, body, timeout_s)
        except (OSError, TimeoutError) as e:
            raise self._failed("model_unavailable", str(e)[:200])
        ms = (time.perf_counter() - t0) * 1000.0
        if status == 404:
            raise self._failed("model_unsupported",
                               "no /v1/systemone: Ollama too old, or the model is not pulled")
        if status != 200:
            raise self._failed("model_unavailable", f"HTTP {status}")
        try:
            parsed = parse(json.loads(raw))
        except (ValueError, TypeError, AttributeError) as e:
            raise self._failed("model_unavailable", f"unreadable answer: {e}")
        if self.state in ("model_unavailable", "unknown"):
            self.state = "ok"                 # answering again
        if observe:
            self.gate.observe(ms)
        parsed["ms"] = round(ms, 1)
        return parsed

    def health(self, name: str, digest: str, min_ollama: str) -> str:
        """ok, model_unsupported (Ollama too old), model_mismatch (digest is not
        the pinned one) or model_unavailable. Run at start and hourly (spec §7)."""
        try:
            status, raw = self.http("GET", f"{self.base}/api/version", {}, None, 5.0)
            if status != 200:
                self.state = "model_unavailable"
                return self.state
            version = json.loads(raw).get("version", "0")
            if _version_tuple(version) < _version_tuple(min_ollama or "0"):
                self.state = "model_unsupported"
                return self.state
            status, raw = self.http("GET", f"{self.base}/api/tags", {}, None, 5.0)
            models = json.loads(raw).get("models", []) if status == 200 else []
        except (OSError, TimeoutError, ValueError, AttributeError):
            self.state = "model_unavailable"
            return self.state
        want = (digest or "").removeprefix("sha256:")
        for m in models:
            if name in (m.get("name"), m.get("model")):
                have = str(m.get("digest", "")).removeprefix("sha256:")
                self.state = "ok" if not want or have == want else "model_mismatch"
                return self.state
        self.state = "model_unavailable"
        return self.state
