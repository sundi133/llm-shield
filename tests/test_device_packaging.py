"""Device DLP agent, task 6: packaging and MDM.
Spec: docs/specs/device-dlp-agent.md §8, §10.

OS commands (security, certutil, reg, icacls) are recorded, not run, so every
platform's path is tested on any machine. The packaging files are checked for
what the installers depend on: paths, ids, service arguments, MDM keys.
"""

import base64
import io
import json
import os
import plistlib
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.test_device_agent import ROOT, SK, pub  # noqa: F401  (sets sys.path)
from votal_device_agent import native_host
from votal_device_agent.platform import Paths, paths
from votal_device_agent.platform import credentials as vcred
from votal_device_agent.platform import managed, native_messaging, trust_store
from votal_device_agent.platform.ollama import OllamaSupervisor
from votal_device_agent.sync import Credentials

PKG = Path(ROOT) / "packages" / "votal-device-agent"
PACKAGING = PKG / "packaging"
SETTINGS = {"ShieldURL": "https://api.guardrails.votal.ai/", "TenantID": "acme", "Fleet": "sales",
            "PinnedPublicKey": pub(SK).upper(), "EnrollmentToken": "vde.acme." + "x" * 43,
            "ExtensionIDs": ["abcdefghijklmnopabcdefghijklmnop"]}


class Recorder:
    def __init__(self, results=None):
        self.calls, self.results = [], list(results or [])

    def __call__(self, cmd, input=None, timeout=60.0):
        self.calls.append((list(cmd), input))
        return self.results.pop(0) if self.results else (0, b"", b"")


def tmp_paths(tmp_path) -> Paths:
    return Paths(tmp_path / "install", tmp_path / "state", tmp_path / "state" / "agent.json",
                 tmp_path / "logs", tmp_path / "ollama")


# ── MDM settings ─────────────────────────────────────────────────────


def test_mac_settings_come_from_the_managed_preferences_plist(tmp_path):
    plist = tmp_path / "ai.votal.device-agent.plist"
    plist.write_bytes(plistlib.dumps({**SETTINGS, "Unrelated": 1}))
    assert managed.read_mac(plist) == SETTINGS
    assert managed.read_mac(tmp_path / "missing.plist") == {}


def test_windows_settings_come_from_the_policy_key():
    seen = []

    def reader(key):
        seen.append(key)
        return {**SETTINGS, "ExtensionIDs": "abcdefghijklmnopabcdefghijklmnop, "
                                            "bbcdefghijklmnopabcdefghijklmnop",
                "Capture": "", "ModelInline": ""}           # the MSI writes unset ones empty
    m = managed.read_windows(reader)
    assert seen == [r"SOFTWARE\Policies\Votal\DeviceAgent"]
    assert m["ExtensionIDs"] == ["abcdefghijklmnopabcdefghijklmnop", "bbcdefghijklmnopabcdefghijklmnop"]
    assert "Capture" not in m and managed.validate(m)


def test_agent_json_from_settings(tmp_path):
    p = tmp_paths(tmp_path)
    path = managed.write_agent_json(SETTINGS, p)
    cfg = json.loads(path.read_text())
    assert cfg == {"shield_url": "https://api.guardrails.votal.ai", "tenant_id": "acme",
                   "fleet": "sales", "pinned_public_key": pub(SK), "state_dir": str(p.state_dir),
                   "capture": "proxy", "model_inline": "auto", "fallback_path": ""}
    assert "vde." not in path.read_text()                              # the token is not copied
    assert oct(os.stat(path).st_mode & 0o777) == "0o644"


@pytest.mark.parametrize("change, needle", [
    ({"ShieldURL": "http://shield.example.com"}, "must be https"),
    ({"PinnedPublicKey": "abc"}, "64 hex"),
    ({"Fleet": "Sales Team"}, "Fleet"),
    ({"EnrollmentToken": "sk-123"}, "vde."),
    ({"ExtensionIDs": ["not-an-id"]}, "ExtensionIDs"),
    ({"TenantID": ""}, "TenantID: required"),
    ({"Capture": "all"}, "Capture"),
])
def test_settings_validation(change, needle):
    with pytest.raises(managed.ManagedError) as e:
        managed.validate({**SETTINGS, **change})
    assert any(needle in err for err in e.value.errors)


# ── the device key ───────────────────────────────────────────────────

CREDS = Credentials("dev_0123456789abcdef", "vdk_" + "k" * 43, "acme", "sales")


def test_keychain_store_keeps_the_key_out_of_process_arguments():
    rec = Recorder()
    vcred.KeychainStore(rec).save(CREDS)
    cmd, stdin = rec.calls[0]
    assert cmd == ["security", "-i"]
    assert CREDS.api_key not in " ".join(cmd)
    assert b"add-generic-password -U -a device -s ai.votal.device-agent" in stdin
    assert b"/Library/Keychains/System.keychain" in stdin
    encoded = stdin.split(b" -w ")[1].split(b" ")[0]
    rec = Recorder([(0, encoded + b"\n", b"")])
    assert vcred.KeychainStore(rec).load() == CREDS
    assert rec.calls[0][0][:2] == ["security", "find-generic-password"]
    assert vcred.KeychainStore(Recorder([(44, b"", b"not found")])).load() is None


def test_dpapi_store_encrypts_and_locks_the_file(tmp_path):
    rec = Recorder()
    xor = lambda b: bytes(x ^ 0x5A for x in b)                        # stands in for DPAPI
    store = vcred.DpapiStore(tmp_path, rec, protect=xor, unprotect=xor)
    store.save(CREDS)
    raw = (tmp_path / "credentials.dpapi").read_bytes()
    assert CREDS.api_key.encode() not in raw and base64.b64encode(CREDS.api_key.encode()) not in raw
    assert rec.calls[0][0][:3] == ["icacls", str(tmp_path / "credentials.dpapi"), "/inheritance:r"]
    assert store.load() == CREDS
    store.clear()
    assert store.load() is None


def test_default_store_by_platform(tmp_path):
    assert isinstance(vcred.default_store(tmp_path, "windows"), vcred.DpapiStore)
    from votal_device_agent.sync import CredentialStore
    assert isinstance(vcred.default_store(tmp_path, "other"), CredentialStore)


# ── the trust store ──────────────────────────────────────────────────


@pytest.fixture
def ca_cert(tmp_path):
    from votal_device_agent import ca
    ca.ensure_ca(tmp_path / "ca", ["chatgpt.com"])
    return tmp_path / "ca" / ca.CERT_FILE


def test_windows_trusts_silently_and_replaces_the_old_ca(ca_cert):
    rec = Recorder()
    assert trust_store.trust(ca_cert, previous="aa11", os_name="windows", run=rec) == "trusted"
    assert rec.calls[0][0] == ["certutil", "-delstore", "Root", "aa11"]
    assert rec.calls[1][0] == ["certutil", "-addstore", "-f", "Root", str(ca_cert)]
    assert trust_store.trust(ca_cert, os_name="windows",
                             run=Recorder([(1, b"", b"denied")])).startswith("failed")


def test_macos_does_not_pretend(ca_cert):
    """Since Big Sur a root process cannot mark a CA trusted without a user or
    an MDM profile; the agent reports that instead of claiming success."""
    rec = Recorder([(1, b"", b"not trusted")])
    assert trust_store.trust(ca_cert, os_name="macos", run=rec) == "needs_mdm"
    assert rec.calls[0][0][:3] == ["security", "verify-cert", "-c"]
    assert not any("add-trusted-cert" in " ".join(c) for c, _ in rec.calls)
    assert trust_store.trust(ca_cert, os_name="macos", run=Recorder([(0, b"", b"")])) == "trusted"


def test_ca_rotation_hands_the_certificate_to_the_trust_store(tmp_path, ca_cert, monkeypatch):
    from votal_device_agent import installed
    p = tmp_paths(tmp_path)
    managed.write_agent_json(SETTINGS, p)
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {})
    rec = Recorder()
    agent, _token = installed.build_agent("windows", p, run=rec)
    agent.on_ca_rotated(str(ca_cert))
    assert rec.calls[-1][0][:3] == ["certutil", "-addstore", "-f"]
    agent_mac, _ = installed.build_agent("macos", p, run=Recorder([(1, b"", b"")]))
    with pytest.raises(RuntimeError, match="needs_mdm"):                # keeps ca_trust_pending
        agent_mac.on_ca_rotated(str(ca_cert))


# ── the browser host ─────────────────────────────────────────────────


def test_native_messaging_manifests(tmp_path):
    dirs = (tmp_path / "chrome", tmp_path / "edge")
    written = native_messaging.install("/opt/votal/votal-native-host",
                                       ["abcdefghijklmnopabcdefghijklmnop"], os_name="macos",
                                       mac_dirs=dirs)
    assert len(written) == 2
    m = json.loads((dirs[0] / "ai.votal.device_agent.json").read_text())
    assert m["allowed_origins"] == ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]
    assert m["path"] == "/opt/votal/votal-native-host" and m["type"] == "stdio"
    rec = Recorder()
    native_messaging.install(r"C:\Votal\votal-native-host.cmd", ["abcdefghijklmnopabcdefghijklmnop"],
                             os_name="windows", manifest_dir=tmp_path, run=rec)
    keys = [c[0][2] for c in rec.calls]
    assert keys == [r"HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\ai.votal.device_agent",
                    r"HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\ai.votal.device_agent"]
    assert native_messaging.install("x", [], os_name="macos", mac_dirs=dirs) == []
    native_messaging.uninstall(os_name="macos", mac_dirs=dirs)
    assert not (dirs[0] / "ai.votal.device_agent.json").exists()


def test_native_host_ignores_the_arguments_chrome_passes(tmp_path):
    (tmp_path / "local_secret").write_text("z" * 43)
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"state_dir": str(tmp_path)}))
    msg = json.dumps({"type": "hello"}).encode()
    out = subprocess.run(
        [sys.executable, "-m", "votal_device_agent", "--config", str(cfg), "native-host",
         "chrome-extension://abcdefghijklmnopabcdefghijklmnop/", "--parent-window=0"],
        input=len(msg).to_bytes(4, sys.byteorder) + msg, capture_output=True, timeout=30,
        env={**os.environ, "PYTHONPATH": os.pathsep.join([str(PKG), ROOT])})
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout[4:]) == {"ok": True, "port": 47823, "secret": "z" * 43}


# ── install hooks and verify ─────────────────────────────────────────


def test_install_hooks(tmp_path):
    from votal_device_agent import installed
    p = tmp_paths(tmp_path)
    dirs = (tmp_path / "chrome", tmp_path / "edge")
    out = installed.install_hooks(os_name="macos", p=p, settings=SETTINGS, mac_dirs=dirs)
    assert out["config"] == str(p.config) and len(out["native_messaging"]) == 2
    host = json.loads((dirs[0] / "ai.votal.device_agent.json").read_text())["path"]
    assert host == str(p.install_dir / "bin" / "votal-native-host")
    assert "waits" in installed.install_hooks(os_name="macos", p=p, settings={})["config"]
    rec = Recorder()
    installed.install_hooks(os_name="windows", p=p, settings=SETTINGS, run=rec)
    icacls = [c[0] for c in rec.calls if c[0][0] == "icacls"]
    assert icacls[0][:4] == ["icacls", str(p.state_dir), "/inheritance:r", "/grant:r"]
    assert "*S-1-5-32-545:RX" in icacls[0] and "*S-1-5-32-545:(OI)(CI)R" not in icacls[0]


def test_verify_reports_every_check(tmp_path, monkeypatch):
    from votal_device_agent import installed
    p = tmp_paths(tmp_path)
    managed.write_agent_json(SETTINGS, p)
    (p.state_dir / "local_secret").write_text("s" * 43)
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: SETTINGS)
    status = {"state": "ok", "trust": {"status": "verified", "bundle_version": 7},
              "model": {"state": "ok", "p95_ms": 280, "inline": True},
              "capture": {"proxy_port": 47824}, "audit": "12 records, chain intact"}
    ok, checks = installed.verify(os_name="other", p=p, run=Recorder(),
                                  local=lambda port, secret, path: (200, json.dumps(status).encode()))
    by = {n: (passed, d) for n, passed, d in checks}
    assert by["policy bundle"] == (True, "verified v7") and by["decision model"][0]
    assert by["enrolled"][0] is False and by["device CA trusted"][0] is False
    assert ok is False                                                 # not enrolled, no CA
    ok, checks = installed.verify(os_name="other", p=p, run=Recorder(),
                                  local=lambda *a: (_ for _ in ()).throw(OSError("refused")))
    assert dict((n, x) for n, x, _ in checks)["agent running"] is False


# ── the agent's own Ollama ───────────────────────────────────────────


class FakeProc:
    def __init__(self):
        self.code = None

    def poll(self):
        return self.code

    def terminate(self):
        self.code = 0

    def wait(self, timeout=None):
        return 0


def test_ollama_is_started_on_its_own_port_and_restarted(tmp_path):
    spawned = []

    def popen(cmd, env, stdout, stderr):
        spawned.append((cmd, env))
        return FakeProc()
    s = OllamaSupervisor("/opt/votal/ollama/ollama", tmp_path / "models", popen=popen,
                         restart_delay_s=0.01)
    s.start()
    cmd, env = spawned[0]
    assert cmd == ["/opt/votal/ollama/ollama", "serve"]
    assert env["OLLAMA_HOST"] == "127.0.0.1:11535" and env["OLLAMA_MODELS"] == str(tmp_path / "models")
    s.proc.code = 1                                                    # it crashed
    for _ in range(300):
        if len(spawned) > 1:
            break
        threading.Event().wait(0.01)
    s.stop()
    assert len(spawned) == 2 and s.restarts == 1


class FakeOllamaApi(BaseHTTPRequestHandler):
    models: list = []
    deleted: list = []

    def log_message(self, *a):
        pass

    def _send(self, obj):
        out = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self._send({"models": FakeOllamaApi.models} if self.path == "/api/tags" else {"version": "0.35.0"})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        FakeOllamaApi.models = [{"name": "tev1:0.8b", "digest": "ab" * 32}]
        self._send({"status": "success"})

    def do_DELETE(self):
        FakeOllamaApi.deleted.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self._send({})


def test_the_model_is_pulled_then_checked_against_the_pinned_digest():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllamaApi)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        s = OllamaSupervisor("unused", "unused", port=srv.server_port)
        FakeOllamaApi.models, FakeOllamaApi.deleted = [], []
        assert s.wait_ready(timeout=5)
        assert s.ensure_model("tev1:0.8b", "sha256:" + "ab" * 32) == "pulled"
        assert s.ensure_model("tev1:0.8b", "sha256:" + "ab" * 32) == "ok"
        assert s.ensure_model("tev1:0.8b", "sha256:" + "cd" * 32) == "model_mismatch"
        assert FakeOllamaApi.deleted == [{"model": "tev1:0.8b"}]        # never judge with it
    finally:
        srv.shutdown()


# ── the packaging files ──────────────────────────────────────────────


def test_launch_daemon_runs_the_installed_service():
    d = plistlib.loads((PACKAGING / "macos" / "ai.votal.device-agent.plist").read_bytes())
    assert d["Label"] == "ai.votal.device-agent" and d["KeepAlive"] and d["RunAtLoad"]
    assert d["ProgramArguments"] == [str(paths("macos").install_dir / "bin" / "votal-device-agent"),
                                     "service"]
    wrapper = (PACKAGING / "macos" / "votal-native-host").read_text()
    assert f'"{paths("macos").install_dir}/bin/votal-device-agent" native-host' in wrapper


def test_pkg_scripts_are_valid_and_run_the_hooks():
    for f in ("scripts/preinstall", "scripts/postinstall", "uninstall.sh", "build_pkg.sh",
              "votal-native-host"):
        path = PACKAGING / "macos" / f
        assert os.access(path, os.X_OK), f
        assert subprocess.run(["bash", "-n", str(path)]).returncode == 0, f
    post = (PACKAGING / "macos" / "scripts" / "postinstall").read_text()
    assert "install-hooks" in post and "launchctl bootstrap system" in post
    assert "uninstall-hooks" in (PACKAGING / "macos" / "uninstall.sh").read_text()


def test_mdm_profiles():
    mdm = PACKAGING / "macos" / "mdm"
    settings = plistlib.loads((mdm / "votal-device-agent-settings.mobileconfig").read_bytes())
    prefs = settings["PayloadContent"][0]
    assert prefs["PayloadType"] == "ai.votal.device-agent" == managed.MAC_PLIST.stem
    assert set(managed.KEYS) >= {k for k in prefs if not k.startswith("Payload")}
    pac = plistlib.loads((mdm / "votal-device-agent-proxy.mobileconfig").read_bytes())
    proxies = pac["PayloadContent"][0]
    assert proxies["PayloadType"] == "com.apple.SystemConfiguration"
    assert proxies["Proxies"]["ProxyAutoConfigURLString"] == "http://127.0.0.1:47823/proxy.pac"
    uuids = [p["PayloadUUID"] for f in mdm.glob("*.mobileconfig")
             for doc in [plistlib.loads(f.read_bytes())] for p in [doc, *doc["PayloadContent"]]]
    assert len(uuids) == len(set(uuids))


def test_msi_source():
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    root = ET.parse(PACKAGING / "windows" / "votal-device-agent.wxs").getroot()
    svc = root.find(".//w:ServiceInstall", ns)
    assert svc.get("Arguments") == "service" and svc.get("Account") == "LocalSystem"
    reg = root.find(".//w:RegistryKey", ns)
    assert reg.get("Key") == managed.WIN_KEY
    names = {v.get("Name") for v in reg.findall("w:RegistryValue", ns)}
    assert names <= set(managed.KEYS) and {"ShieldURL", "PinnedPublicKey", "Fleet"} <= names
    token = [p for p in root.findall(".//w:Property", ns) if p.get("Id") == "ENROLLMENTTOKEN"][0]
    assert token.get("Hidden") == "yes"                                 # not written to MSI logs
    actions = {a.get("Id"): a.get("ExeCommand") for a in root.findall(".//w:CustomAction", ns)}
    assert actions == {"InstallHooks": "install-hooks", "UninstallHooks": "uninstall-hooks"}
    cmd = (PACKAGING / "windows" / "votal-native-host.cmd").read_text()
    assert "native-host %*" in cmd


def test_ci_builds_both_installers():
    wf = (Path(ROOT) / ".github" / "workflows" / "device-agent-installers.yml").read_text()
    assert "build_pkg.sh" in wf and "build_msi.ps1" in wf and "native-host" in wf
    assert "MAC_INSTALLER_IDENTITY" not in wf and "SIGN_CERT_THUMBPRINT" not in wf  # unsigned in CI
