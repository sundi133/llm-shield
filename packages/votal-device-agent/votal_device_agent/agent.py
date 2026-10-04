"""The agent: trust, model, engine, audit and sync wired together.

    agent = Agent(AgentConfig.load("/Library/Application Support/Votal/agent.json"))
    agent.enroll_if_needed(token)          # first run, token from MDM
    agent.start()                          # loopback API + background sync
    agent.engine.check(text, destination)  # what capture (task 5) calls per prompt

State directory layout:
  agent.json         MDM-written config (tenant, fleet, pinned key, Shield URL)
  credentials.json   the device key (keychain / DPAPI in task 6)
  bundle.json        last verified DLP bundle, trust_state.json, bundle.etag
  fallback.json      optional MDM-shipped secrets-only rules
  audit/             hash-chained decision log, uploaded.json
  local_secret       the loopback API secret
  ca/                the per-device CA (mitmproxy confdir layout)
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from votal_device_agent import model as model_mod
from votal_device_agent import sync
from votal_device_agent.agent_hooks import AgentHooks, HookPaths, default_paths
from votal_device_agent.audit import AuditLog
from votal_device_agent.engine import Engine
from votal_device_agent.local_api import LocalApi, load_or_create_secret
from votal_device_agent.model import DecisionModel, LatencyGate
from votal_device_agent.trust import TrustStore

WARMUP_PROMPTS = ("How do I write a for loop in Python?", "Summarise the plot of Hamlet.",
                  "What is the capital of Australia?", "Explain what a REST API is.")


def serial_hash(serial: str) -> str:
    """SHA-256 of the hardware serial, trimmed and uppercased: the same rule
    Shield applies to an MDM's serial export (core/dlp/devices.serial_hash), so
    the company inventory matches whatever case the firmware reports."""
    s = (serial or "").strip().upper()
    return hashlib.sha256(s.encode()).hexdigest() if s else ""


def device_info() -> dict:
    """hostname, os, os_version and a SHA-256 of the hardware serial (never the
    serial itself), for enrollment."""
    system = platform.system()
    os_name = {"Darwin": "macos", "Windows": "windows"}.get(system, system.lower())
    version = platform.mac_ver()[0] if system == "Darwin" else platform.version()
    serial = ""
    try:
        if system == "Darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if "IOPlatformSerialNumber" in line:
                    serial = line.split("=", 1)[1].strip().strip('"')
        elif system == "Windows":
            serial = subprocess.run(["powershell", "-NoProfile", "-Command",
                                     "(Get-CimInstance Win32_BIOS).SerialNumber"],
                                    capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        serial = ""
    return {"hostname": platform.node()[:255] or "unknown", "os": os_name,
            "os_version": (version or "unknown")[:64],
            "serial_hash": serial_hash(serial)}


def _hook_urllib(method: str, url: str, headers: dict, body) -> tuple:
    """sync._urllib with a 3 s timeout: the hook script waits 4 s for this agent."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""


class Agent:
    def __init__(self, cfg: sync.AgentConfig, *, http: sync.Http = sync._urllib,
                 model_http: Optional[model_mod.Http] = None, credentials=None,
                 hook_paths: Optional[HookPaths] = None, hook_http: Optional[sync.Http] = None):
        self.cfg, self.http = cfg, http
        # Coding-agent hooks (agent_hooks.py). Hook calls go to Shield with a
        # short timeout, so the agent answers before the hook script gives up.
        from votal_device_agent import platform as plat
        os_name = plat.system()
        self.hooks = AgentHooks(hook_paths or default_paths(os_name, plat.paths(os_name).install_dir),
                                cfg.state_dir, local_port=cfg.local_port, os_name=os_name)
        self.hook_http = hook_http or _hook_urllib
        self.store = TrustStore(cfg.state_dir, tenant_id=cfg.tenant_id, fleet=cfg.fleet,
                                pinned_key_hex=cfg.pinned_public_key,
                                fallback_path=cfg.fallback_path or None)
        # The keychain or DPAPI in an installed agent (platform/credentials.py).
        self.credentials = credentials or sync.CredentialStore(cfg.state_dir)
        self.creds = self.credentials.load()
        self.audit = AuditLog(Path(cfg.state_dir) / "audit",
                              device_id=self.creds.device_id if self.creds else "")
        try:
            os.chmod(self.audit.dir, 0o700)   # which sites were used, and when: not for other users
        except OSError:
            pass
        self.model = DecisionModel(cfg.ollama_url, http=model_http or model_mod._urllib,
                                   gate=LatencyGate(override=cfg.model_inline))
        self.engine = Engine(self.store.load(), self.model, audit=self.audit)
        self.revoked = False
        self.enroll_error = ""
        self.last: dict = {}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.local_api: Optional[LocalApi] = None
        self.proxy = None
        self.proxy_port: Optional[int] = None
        self.ca_dir = Path(cfg.state_dir) / "ca"
        self.ca_trust_pending = False
        self.ca_error = ""
        # Called with the CA certificate path when a new CA is issued; the
        # installer (task 6) sets it to add the CA to the system trust store.
        self.on_ca_rotated = None

    # ── lifecycle ──────────────────────────────────────────────────────

    ENROLL_RETRY_S = 3600

    def enroll_if_needed(self, token: str = "", info: Optional[dict] = None) -> sync.Credentials:
        if self.creds is None:
            if not token:
                raise sync.SyncError("not enrolled and no enrollment token given")
            # Kept so sync_once can retry: a refusal can be temporary (Shield
            # unreachable, or the old install of this laptop still reporting).
            self._enroll_token, self._enroll_info = token, info
            self._enroll_tried = time.time()
            try:
                self.creds = sync.enroll(self.cfg, token, info or device_info(), http=self.http,
                                         store=self.credentials)
            except sync.SyncError as e:
                self.enroll_error = str(e)[:300]
                raise
            self.enroll_error = ""
            self.audit.device_id = self.creds.device_id
        return self.creds

    def _retry_enroll(self) -> None:
        token = getattr(self, "_enroll_token", "")
        if self.creds is not None or not token:
            return
        if time.time() - getattr(self, "_enroll_tried", 0) < self.ENROLL_RETRY_S:
            return
        try:
            self.enroll_if_needed(token, getattr(self, "_enroll_info", None))
        except sync.SyncError:
            pass

    def reload(self) -> None:
        before = self.engine.ai_hosts
        self.engine.set_trust(self.store.load())
        if self.proxy is not None and self.engine.ai_hosts != before:
            self._ensure_ca(restart=True)
        self.apply_hooks()

    def apply_hooks(self) -> None:
        """Make Claude Code's hook match the fleet, from a bundle this agent
        trusts only. On fallback (no bundle, tampered, expired past grace) the
        last applied state stays: a broken bundle must not switch the hook off."""
        if self.engine.trust.status not in ("verified", "grace"):
            return
        try:
            self.hooks.apply(self.engine.policy.get("agent_hooks"))
        except Exception:
            pass

    # ── coding-agent hook calls (local_api: POST /v1/local/claude-code/hook) ──

    def _hook_setting(self) -> dict:
        s = self.engine.policy.get("agent_hooks") or {}
        return s if isinstance(s, dict) else {}

    def claude_code_hook(self, body: dict, user: str = "") -> dict:
        """Ask Shield about one Claude Code tool call, with this device's key.
        No answer, or an answer that is not Claude Code's format, gets the
        fleet's on_unreachable decision."""
        s = self._hook_setting()
        if s.get("mode") not in ("monitor", "enforce") or "claude_code" not in (s.get("agents") or {}):
            return {}
        if self.creds is not None and not self.revoked:
            try:
                status, _h, raw = self.hook_http(
                    "POST", f"{self.cfg.shield_url.rstrip('/')}/v1/shield/hooks/claude-code",
                    {"X-API-Key": self.creds.api_key, "Content-Type": "application/json",
                     "X-Shield-User": user[:200]}, json.dumps(body).encode())
                if status == 200:
                    answer = json.loads(raw or b"{}")
                    if isinstance(answer, dict) and (answer == {} or "hookSpecificOutput" in answer):
                        return answer
            except (OSError, ValueError):
                pass
        self.engine.counters["hook_unreachable"] = self.engine.counters.get("hook_unreachable", 0) + 1
        if s.get("on_unreachable") == "deny":
            return {"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": "Blocked by Votal Shield: Shield could not be reached, "
                                            "so this action is not allowed"}}
        return {}

    def ca_valid(self) -> bool:
        """Whether the proxy holds a CA it may intercept with right now."""
        if self.cfg.ca_mode != "tenant":
            return True
        from votal_device_agent import ca
        return ca.status(self.ca_dir, self.engine.ai_hosts, self.store.now()) in ("ok", "renew")

    def _ensure_tenant_ca(self, restart: bool) -> bool:
        """Tenant mode: renew this laptop's intermediate when due (daily)."""
        from votal_device_agent import ca
        state = ca.status(self.ca_dir, self.engine.ai_hosts, self.store.now())
        if state == "ok" or self.creds is None:
            return False
        code, body = sync.request_ca(self.cfg, self.creds,
                                     ca.csr_pem(self.ca_dir, self.creds.device_id), http=self.http)
        if code != 200:
            self.ca_error = f"HTTP {code}: {str(body.get('detail', ''))[:200]}"
            return False
        try:
            ca.install_intermediate(self.ca_dir, body["certificate_pem"], body["root_pem"])
        except (KeyError, ValueError) as e:
            self.ca_error = f"refused the issued CA: {e}"
            return False
        self.ca_error = ""
        self.ca_trust_pending = False          # the root is trusted through MDM
        if restart and self.proxy is not None:
            self.proxy.stop()
            self._start_proxy()
        elif restart and self.proxy is None and self.local_api is not None \
                and self.cfg.capture == "proxy":
            self._start_proxy()                # first intermediate: capture can begin
        return True

    def _ensure_ca(self, restart: bool = False) -> bool:
        """A CA constrained to the current AI hosts; a new one when they grew."""
        if self.cfg.ca_mode == "tenant":
            return self._ensure_tenant_ca(restart)
        from votal_device_agent import ca
        rotated = ca.ensure_ca(self.ca_dir, self.engine.ai_hosts,
                               device_name=self.creds.device_id if self.creds else "")
        if rotated:
            self.ca_trust_pending = True
            if self.on_ca_rotated:
                try:
                    self.on_ca_rotated(str(self.ca_dir / ca.CERT_FILE))
                    self.ca_trust_pending = False
                except Exception:
                    pass
            if restart and self.proxy is not None:
                self.proxy.stop()
                self._start_proxy()
        return rotated

    def _start_proxy(self) -> Optional[int]:
        try:
            from votal_device_agent.proxy import LocalProxy
        except ImportError:                 # mitmproxy not installed: extension-only capture
            return None
        base = f"http://127.0.0.1:{self.local_api.server.server_address[1]}" if self.local_api \
            else ""
        if not self.ca_valid() and self.cfg.ca_mode == "tenant":
            # Never let mitmproxy start without our CA: it would invent its own,
            # unconstrained and trusted by nobody.
            return None
        self.proxy = LocalProxy(self.engine, port=self.cfg.proxy_port, confdir=self.ca_dir,
                                justify_base=base, intercept_ok=self.ca_valid)
        self.proxy_port = self.proxy.start()
        return self.proxy_port

    def _ca_not_after(self) -> Optional[int]:
        from votal_device_agent import ca
        return ca.not_after(self.ca_dir)

    def pac(self) -> Optional[str]:
        if self.proxy_port is None:
            return None
        from votal_device_agent.pac import render
        return render(self.engine.ai_hosts, self.proxy_port,
                      fail_open=self.engine.policy.get("fail_mode") != "block")

    def check_model(self) -> str:
        m = self.engine.policy.get("model") or {}
        if not m.get("name") or self.engine.trust.status == "fallback":
            return "no_model"
        return self.model.health(m["name"], m.get("digest", ""), m.get("min_ollama", ""))

    def warm_up(self, rounds: int = 5) -> Optional[float]:
        """Measure the model's latency on harmless prompts, so the gate can decide
        whether it may sit on the send path. Returns p95 ms."""
        p = self.engine.policy
        if self.check_model() != "ok":
            return None
        self.model.load(p["model"]["name"])
        try:                               # the first answer after a load is slow; not measured
            self.model.decide(p["model"]["name"], {"prompt": WARMUP_PROMPTS[0], "destination": "",
                                                   "app": "warm-up"}, p["questions"], 60.0,
                              observe=False)
        except model_mod.ModelUnavailable:
            return None
        for _ in range(rounds):
            for text in WARMUP_PROMPTS:
                try:
                    self.model.decide(p["model"]["name"], {"prompt": text, "destination": "",
                                                           "app": "warm-up"},
                                      p["questions"], p.get("model_timeout_ms", 1500) / 1000.0)
                except model_mod.ModelUnavailable:
                    return None
        return self.model.gate.p95()

    def sync_once(self) -> dict:
        """Pull the bundle, push the audit log, send a heartbeat. Offline is fine."""
        self._retry_enroll()
        if self.creds is None:
            return {"skipped": "not enrolled", "enroll_error": self.enroll_error}
        out = {"bundle": sync.pull_bundle(self.cfg, self.creds, self.store, http=self.http)}
        if out["bundle"] == "updated":
            self.reload()
            out["model"] = self.check_model()
        else:
            self.reload()                   # an expiry or grace boundary may have passed
        if self.cfg.capture == "proxy" and self.cfg.ca_mode == "tenant":
            self._ensure_tenant_ca(restart=self.local_api is not None)
        out["audit"] = sync.push_audit(self.cfg, self.creds, self.audit, http=self.http)
        out["heartbeat"] = sync.heartbeat(self.cfg, self.creds, self.heartbeat_payload(),
                                          self.store, http=self.http)
        self.revoked = (out["bundle"] == "revoked" or out["audit"] == -1
                        or out["heartbeat"] == 401)
        self.last = {**out, "at": int(time.time())}
        return out

    def start(self, *, sync_every_s: float = 300.0, model_every_s: float = 3600.0) -> int:
        """Loopback API and background sync. Returns the loopback port."""
        self.local_api = LocalApi(self, load_or_create_secret(self.cfg.state_dir),
                                  port=self.cfg.local_port)
        port = self.local_api.start()
        if self.cfg.capture == "proxy":
            self._ensure_ca()
            self._start_proxy()

        def loop(every: float, fn):
            while not self._stop.is_set():
                try:
                    fn()
                except Exception:          # the agent keeps enforcing whatever sync does
                    pass
                self._stop.wait(every)

        for every, fn in ((sync_every_s, self.sync_once), (model_every_s, self.check_model)):
            t = threading.Thread(target=loop, args=(every, fn), daemon=True)
            t.start()
            self._threads.append(t)
        return port

    def stop(self) -> None:
        self._stop.set()
        if self.proxy:
            self.proxy.stop()
        if self.local_api:
            self.local_api.stop()
        self.engine.drain()

    # ── reporting ──────────────────────────────────────────────────────

    def state(self) -> str:
        trust_state = self.engine.trust.state
        if trust_state != "ok":
            return trust_state
        if self.model.state in ("model_unavailable", "model_unsupported", "model_mismatch"):
            return self.model.state
        return "ok"

    def heartbeat_payload(self) -> dict:
        digest = ""
        m = self.engine.policy.get("model") or {}
        if self.model.state == "ok":
            digest = m.get("digest", "")
        out = {"bundle_version": self.engine.trust.bundle_version,
               "model_digest": digest, "mode": self.engine.policy.get("mode", ""),
               "state": self.state(), "agent_version": sync.AGENT_VERSION,
               "counters": dict(list(self.engine.counters.items())[:20])}
        if self.hooks.report:
            out["agent_hooks"] = self.hooks.report
        return out

    def status(self) -> dict:
        t = self.engine.trust
        return {"device_id": self.creds.device_id if self.creds else None,
                "enroll_error": self.enroll_error,
                "tenant_id": self.cfg.tenant_id, "fleet": self.cfg.fleet,
                "state": self.state(), "revoked": self.revoked,
                "trust": {"status": t.status, "reason": t.reason, "bundle_version": t.bundle_version,
                          "expires_at": t.header.get("expires_at")},
                "mode": self.engine.policy.get("mode"),
                "model": {"state": self.model.state, "inline": self.model.gate.inline(),
                          "p95_ms": self.model.gate.p95(), "gate_ms": self.model.gate.gate_ms},
                "counters": dict(self.engine.counters), "last_sync": self.last,
                "capture": {"proxy_port": self.proxy_port, "ca_trust_pending": self.ca_trust_pending,
                            "ca_mode": self.cfg.ca_mode, "ca_valid": self.ca_valid(),
                            "ca_not_after": self._ca_not_after(), "ca_error": self.ca_error,
                            "ai_hosts": list(self.engine.ai_hosts)},
                "audit": self.audit.verify().detail}
