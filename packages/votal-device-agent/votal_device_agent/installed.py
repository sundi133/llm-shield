"""The agent as the installers run it (spec §8): configured by MDM, keys in the
keychain or DPAPI, its own Ollama, the CA handed to the trust store.

  install_hooks()   run by the .pkg postinstall / the .msi as root or SYSTEM
  run_installed()   the LaunchDaemon / Windows service entry point
  verify()          `votal-device-agent verify`: one line per check, for admins
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import threading
from pathlib import Path
from typing import Callable, Optional

from votal_device_agent import sync
from votal_device_agent.platform import Paths, Run, paths as os_paths, run as _run, system
from votal_device_agent.platform import credentials, managed, native_messaging, trust_store

NATIVE_HOST = {"macos": "bin/votal-native-host", "windows": "votal-native-host.cmd"}
OLLAMA_BIN = {"macos": "ollama/ollama", "windows": "ollama/ollama.exe"}


def _host_path(p: Paths, os_name: str) -> str:
    return str(p.install_dir / NATIVE_HOST.get(os_name, "bin/votal-native-host"))


def install_hooks(*, os_name: Optional[str] = None, p: Optional[Paths] = None,
                  settings: Optional[dict] = None, run: Run = _run, mac_dirs=None) -> dict:
    """Write agent.json from MDM settings and register the browser host. Safe to
    run again (upgrades, changed MDM settings)."""
    os_name = os_name or system()
    p = p or os_paths(os_name)
    m = settings if settings is not None else managed.read(os_name)
    out: dict = {"os": os_name}
    if not m:
        out["config"] = "no MDM settings yet: the agent waits for them"
        return out
    out["config"] = str(managed.write_agent_json(m, p, os_name))
    if os_name == "windows":
        # chmod means nothing on Windows, and ProgramData lets every user read
        # what the service writes: the CA key and the audit log would be
        # readable. SYSTEM and Administrators only; users may list the folder
        # and read the two files the native host needs.
        run(["icacls", str(p.state_dir), "/inheritance:r", "/grant:r",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:RX"])
        run(["icacls", str(p.config), "/grant", "*S-1-5-32-545:R"])
    else:
        os.chmod(p.state_dir, 0o755)      # the native host (the signed-in user) reads the port
    kw = {"mac_dirs": mac_dirs} if mac_dirs else {}
    out["native_messaging"] = native_messaging.install(
        _host_path(p, os_name), m.get("ExtensionIDs") or [], os_name=os_name,
        manifest_dir=p.install_dir, run=run, **kw)
    return out


def uninstall_hooks(*, os_name: Optional[str] = None, p: Optional[Paths] = None,
                    run: Run = _run) -> None:
    os_name = os_name or system()
    p = p or os_paths(os_name)
    native_messaging.uninstall(os_name=os_name, manifest_dir=p.install_dir, run=run)
    meta = p.state_dir / "ca" / "votal-ca.json"
    cert = p.state_dir / "ca" / "mitmproxy-ca-cert.pem"
    if cert.exists():
        trust_store.untrust(trust_store.sha1_thumbprint(cert), os_name=os_name, run=run)
    credentials.default_store(p.state_dir, os_name, run).clear()
    meta.unlink(missing_ok=True)


def build_agent(os_name: Optional[str] = None, p: Optional[Paths] = None, *, run: Run = _run,
                agent_cls=None, **agent_kw):
    """The Agent, configured from MDM settings (refreshed on every start)."""
    from votal_device_agent.agent import Agent
    os_name = os_name or system()
    p = p or os_paths(os_name)
    m = managed.read(os_name)
    if m:
        managed.write_agent_json(m, p, os_name)
    cfg = sync.AgentConfig.load(p.config)
    agent = (agent_cls or Agent)(cfg, credentials=credentials.default_store(p.state_dir, os_name,
                                                                             run), **agent_kw)
    previous: dict = {}

    def on_rotated(cert_path: str) -> None:
        result = trust_store.trust(cert_path, previous=previous.get("thumbprint"),
                                   os_name=os_name, run=run)
        previous["thumbprint"] = trust_store.sha1_thumbprint(cert_path)
        if result != "trusted":
            raise RuntimeError(result)          # keeps ca_trust_pending set

    agent.on_ca_rotated = on_rotated
    return agent, m.get("EnrollmentToken", "")


def run_installed(os_name: Optional[str] = None, stop: Optional[threading.Event] = None) -> int:
    """The service: its own Ollama, enrollment, model, capture, sync, until `stop`
    is set (the Windows service) or a signal arrives (launchd)."""
    from votal_device_agent.platform.ollama import OllamaSupervisor
    os_name = os_name or system()
    p = os_paths(os_name)
    agent, token = build_agent(os_name, p)
    binary = os.environ.get("VOTAL_OLLAMA_BIN") or str(p.install_dir / OLLAMA_BIN.get(os_name, ""))
    supervisor = None
    if Path(binary).exists():
        p.log_dir.mkdir(parents=True, exist_ok=True)
        supervisor = OllamaSupervisor(binary, p.ollama_models, log_path=p.log_dir / "ollama.log")
        supervisor.start()
        supervisor.wait_ready()
    if token and agent.creds is None:
        try:
            agent.enroll_if_needed(token)
        except sync.SyncError as e:
            print(f"votal-device-agent: enrollment failed: {e}", flush=True)
    agent.sync_once()
    m = agent.engine.policy.get("model") or {}
    if supervisor and m.get("name"):
        print(f"votal-device-agent: model {supervisor.ensure_model(m['name'], m.get('digest', ''))}",
              flush=True)
    agent.check_model()
    agent.warm_up()
    port = agent.start()
    print(f"votal-device-agent: running, loopback API 127.0.0.1:{port}, state {agent.state()}",
          flush=True)
    done = stop or threading.Event()
    if stop is None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: done.set())
            except ValueError:
                pass
    done.wait()
    agent.stop()
    if supervisor:
        supervisor.stop()
    return 0


# ── verify ───────────────────────────────────────────────────────────


def _local(port: int, secret: str, path: str) -> tuple:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request("GET", path, headers={"Host": f"127.0.0.1:{port}", "X-Votal-Local-Secret": secret})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def verify(*, os_name: Optional[str] = None, p: Optional[Paths] = None, run: Run = _run,
           local: Callable = _local) -> tuple[bool, list[tuple[str, bool, str]]]:
    """(all critical checks passed, [(check, ok, detail)])."""
    os_name = os_name or system()
    p = p or os_paths(os_name)
    checks: list[tuple[str, bool, str]] = []

    def add(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    m = managed.read(os_name)
    try:
        managed.validate(m)
        add("MDM settings", True, f"tenant {m['TenantID']}, fleet {m['Fleet']}")
    except managed.ManagedError as e:
        add("MDM settings", False, "; ".join(e.errors) if m else "none found")
    add("agent.json", p.config.exists(), str(p.config))
    creds = credentials.default_store(p.state_dir, os_name, run).load()
    enrolled_at = len(checks)
    add("enrolled", creds is not None, creds.device_id if creds else "no device key yet")
    status = {}
    try:
        cfg = json.loads(p.config.read_text())
        secret = (p.state_dir / "local_secret").read_text().strip()
        code, body = local(int(cfg.get("local_port", 47823)), secret, "/v1/local/status")
        status = json.loads(body) if code == 200 else {}
        add("agent running", code == 200, f"state {status.get('state')}" if status else f"HTTP {code}")
        if creds is None and status.get("enroll_error"):
            # Say why: e.g. the old install of this laptop is still reporting.
            checks[enrolled_at] = ("enrolled", False, status["enroll_error"])
    except (OSError, ValueError) as e:
        add("agent running", False, f"not reachable ({type(e).__name__})")
    t = status.get("trust") or {}
    add("policy bundle", t.get("status") == "verified",
        f"{t.get('status', '?')} v{t.get('bundle_version')}" + (f": {t['reason']}" if t.get("reason") else ""))
    model = status.get("model") or {}
    add("decision model", model.get("state") == "ok",
        f"{model.get('state', '?')}, p95 {model.get('p95_ms')} ms, inline {model.get('inline')}")
    cap = status.get("capture") or {}
    add("local proxy", bool(cap.get("proxy_port")), f"127.0.0.1:{cap.get('proxy_port')}")
    cert = p.state_dir / "ca" / "mitmproxy-ca-cert.pem"
    trusted = cert.exists() and trust_store.is_trusted(cert, os_name=os_name, run=run)
    add("device CA trusted", trusted, str(cert) if cert.exists() else "no CA yet")
    if m.get("ExtensionIDs"):
        present = (all((d / "ai.votal.device_agent.json").exists() for d in native_messaging.MAC_DIRS)
                   if os_name == "macos" else (p.install_dir / "ai.votal.device_agent.json").exists())
        add("browser extension host", present, ", ".join(m["ExtensionIDs"]))
    audit = status.get("audit") or ""
    add("audit chain", "intact" in audit, audit or "unknown")
    critical = {"MDM settings", "agent.json", "enrolled", "agent running", "policy bundle",
                "local proxy", "device CA trusted", "audit chain"}
    return all(ok for name, ok, _ in checks if name in critical), checks
