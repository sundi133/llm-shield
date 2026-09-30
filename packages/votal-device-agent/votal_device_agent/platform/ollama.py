"""The agent's own Ollama (spec §3.2): started, watched and stopped by the agent,
on 127.0.0.1:11535 with its own model directory, so a user's Ollama (port
11434, ~/.ollama) is never touched.

The installers ship a pinned Ollama build next to the agent. The model is
pulled by name at first start and then checked against the digest the signed
bundle pins; a different digest is removed and reported as model_mismatch.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

PORT = 11535


class OllamaSupervisor:
    def __init__(self, binary: str | Path, models_dir: str | Path, *, port: int = PORT,
                 keep_alive: str = "24h", log_path: Optional[str | Path] = None,
                 popen: Callable = subprocess.Popen, restart_delay_s: float = 5.0):
        self.binary, self.models_dir, self.port = str(binary), str(models_dir), port
        self.keep_alive, self.log_path = keep_alive, log_path
        self.popen, self.restart_delay_s = popen, restart_delay_s
        self.proc = None
        self.restarts = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def env(self) -> dict:
        return {**os.environ, "OLLAMA_HOST": f"127.0.0.1:{self.port}",
                "OLLAMA_MODELS": self.models_dir, "OLLAMA_KEEP_ALIVE": self.keep_alive}

    def _spawn(self):
        Path(self.models_dir).mkdir(parents=True, exist_ok=True)
        out = open(self.log_path, "ab") if self.log_path else subprocess.DEVNULL
        return self.popen([self.binary, "serve"], env=self.env(), stdout=out,
                          stderr=subprocess.STDOUT)

    def start(self) -> None:
        """Start it and keep it running until stop()."""
        self.proc = self._spawn()

        def watch():
            while not self._stop.wait(1.0):
                if self.proc is not None and self.proc.poll() is not None:
                    self.restarts += 1
                    if self._stop.wait(self.restart_delay_s):
                        return
                    self.proc = self._spawn()

        self._thread = threading.Thread(target=watch, daemon=True, name="votal-ollama")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    # ── the model ──────────────────────────────────────────────────────

    def _api(self, method: str, path: str, body: Optional[dict] = None, timeout: float = 10.0):
        req = urllib.request.Request(self.url + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")

    def wait_ready(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._api("GET", "/api/version", timeout=2.0)
                return True
            except (OSError, ValueError):
                time.sleep(0.5)
        return False

    def ensure_model(self, name: str, digest: str, pull_timeout_s: float = 1800.0) -> str:
        """ok, pulled, model_mismatch or model_unavailable."""
        want = (digest or "").removeprefix("sha256:")

        def have() -> Optional[str]:
            for m in self._api("GET", "/api/tags").get("models", []):
                if name in (m.get("name"), m.get("model")):
                    return str(m.get("digest", "")).removeprefix("sha256:")
            return None

        try:
            got = have()
            pulled = False
            if got is None:
                self._api("POST", "/api/pull", {"model": name, "stream": False},
                          timeout=pull_timeout_s)
                got, pulled = have(), True
            if got is None:
                return "model_unavailable"
            if want and got != want:
                # Not the model the tenant's bundle pins: never judge with it.
                self._api("DELETE", "/api/delete", {"model": name})
                return "model_mismatch"
            return "pulled" if pulled else "ok"
        except (OSError, ValueError, urllib.error.HTTPError):
            return "model_unavailable"
