"""Terminal coverage in the device agent (R1, task 2).

Spec: docs/specs/device-kit-firefox-terminal.md, sections 3, 4, 5, 7, 8.
"""
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "packages" / "votal-device-agent", ROOT / "packages" / "shield-mavlink"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from votal_device_agent import installed, terminal  # noqa: E402
from votal_device_agent.platform import Paths, managed  # noqa: E402

CA_PEM = (b"-----BEGIN CERTIFICATE-----\nMIIBdevicecaAAAA\n-----END CERTIFICATE-----\n")


def _pem(i: int) -> bytes:
    return f"-----BEGIN CERTIFICATE-----\nMIIBroot{i:04d}AAAA\n-----END CERTIFICATE-----\n".encode()


def _paths(tmp_path) -> Paths:
    base = tmp_path / "DeviceAgent"
    p = Paths(base, base / "state", base / "state" / "agent.json", base / "logs", base / "models")
    (p.state_dir / "ca").mkdir(parents=True)
    (p.state_dir / "ca" / "mitmproxy-ca-cert.pem").write_bytes(CA_PEM)
    return p


def _run_roots(n: int, code: int = 0):
    calls = []

    def run(cmd, input=None, timeout=60):
        calls.append(cmd)
        return code, b"".join(_pem(i) for i in range(n)) + _pem(0), b""
    run.calls = calls
    return run


# ── trust files ───────────────────────────────────────────────────────

def test_bundle_is_os_roots_plus_device_ca(tmp_path):
    p = _paths(tmp_path)
    run = _run_roots(120)
    out = terminal.write_trust(p, "macos", run)
    assert out["roots"] == 120 and out["reason"] == ""                       # duplicate dropped
    bundle = Path(out["bundle"]).read_bytes()
    assert bundle.startswith(_pem(0)) and bundle.endswith(CA_PEM)
    assert Path(out["device_ca"]).read_bytes() == CA_PEM
    assert run.calls[0][:4] == ["/usr/bin/security", "find-certificate", "-a", "-p"]
    assert oct(os.stat(out["bundle"]).st_mode & 0o777) == "0o644"


def test_windows_exports_localmachine_root(tmp_path):
    run = _run_roots(80)
    terminal.write_trust(_paths(tmp_path), "windows", run)
    assert run.calls[0][0] == "powershell" and "LocalMachine\\Root" in run.calls[0][-1]


def test_a_tiny_export_writes_no_bundle(tmp_path):
    p = _paths(tmp_path)
    terminal.write_trust(p, "macos", _run_roots(120))
    out = terminal.write_trust(p, "macos", _run_roots(10))
    assert out["bundle"] is None and "fewer than 50" in out["reason"]
    assert not (terminal.trust_dir(p) / terminal.BUNDLE).exists()      # a stale bundle is removed
    out = terminal.write_trust(p, "macos", _run_roots(200, code=1))
    assert out["bundle"] is None


def test_no_device_ca_yet(tmp_path):
    p = _paths(tmp_path)
    (p.state_dir / "ca" / "mitmproxy-ca-cert.pem").unlink()
    assert terminal.write_trust(p, "macos", _run_roots(100))["reason"] == "no device CA yet"


def test_replacing_variables_never_point_at_the_device_ca_alone():
    """Regression guard: REQUESTS_CA_BUNDLE, SSL_CERT_FILE and CURL_CA_BUNDLE
    replace a client's roots; pointing them at the device CA breaks HTTPS to
    every other site (the gateway scripts' bug, spec follow-up)."""
    env = terminal.variables(47824, {"device_ca": "/t/device-ca.pem", "bundle": "/t/ca-bundle.pem"})
    for k in terminal.REPLACING:
        assert env[k] == "/t/ca-bundle.pem"
    assert env["NODE_EXTRA_CA_CERTS"] == "/t/device-ca.pem"              # additive: the CA alone is right
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:47824" and "127.0.0.1" in env["NO_PROXY"]
    no_bundle = terminal.variables(47824, {"device_ca": "/t/device-ca.pem", "bundle": None})
    assert not set(terminal.REPLACING) & set(no_bundle)
    assert "/t/device-ca.pem" not in [no_bundle.get(k) for k in terminal.REPLACING]


# ── macOS shell block ─────────────────────────────────────────────────

def _block(port=47824):
    return terminal.shell_block(port, terminal.variables(port, {"device_ca": "/t/ca.pem",
                                                               "bundle": "/t/bundle.pem"}))


def test_block_is_idempotent_and_foreign_lines_are_untouched(tmp_path):
    f = tmp_path / "zshenv"
    foreign = "# admin's own line\nexport EDITOR=vim\n"
    f.write_text(foreign)
    os.chmod(f, 0o640)
    assert terminal.apply_block(f, _block()) == "written"
    assert terminal.apply_block(f, _block()) == "unchanged"
    text = f.read_text()
    assert text.startswith(foreign) and text.count(terminal.MARK_BEGIN) == 1
    assert oct(f.stat().st_mode & 0o777) == "0o640"
    f.write_text(f.read_text() + "alias ll='ls -l'\n")              # the admin adds a line after us
    assert terminal.apply_block(f, None) == "removed"
    assert f.read_text() == foreign + "alias ll='ls -l'\n"


def test_missing_file_is_created_and_errors_are_reported(tmp_path):
    f = tmp_path / "profile"
    assert terminal.apply_block(f, _block()) == "written" and terminal.MARK_END in f.read_text()
    ro = tmp_path / "ro" / "zshenv"
    ro.parent.mkdir()
    ro.write_text("x\n")
    os.chmod(ro.parent, 0o500)
    try:
        assert terminal.apply_block(ro, _block()).startswith("error:")
    finally:
        os.chmod(ro.parent, 0o700)


def _shell(shell, script, env=None):
    return subprocess.run([shell, "-c", script], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **(env or {})}, timeout=20)


@pytest.mark.parametrize("shell", ["sh", "zsh", "bash"])
def test_block_parses(shell):
    if not shutil.which(shell):
        pytest.skip(f"{shell} not installed")
    assert subprocess.run([shell, "-n"], input=_block(), text=True).returncode == 0


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_closed_port_exports_nothing():
    out = _shell("sh", _block(_free_port()) + 'echo "[$HTTPS_PROXY][$SSL_CERT_FILE]"')
    assert out.stdout.strip() == "[][]"


@pytest.mark.skipif(sys.platform != "darwin", reason="the block probes with macOS nc -G")
def test_open_port_exports_and_respects_existing_values_and_the_off_switch():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    try:
        out = _shell("sh", _block(port) + 'echo "[$HTTPS_PROXY][$SSL_CERT_FILE]"')
        assert out.stdout.strip() == f"[http://127.0.0.1:{port}][/t/bundle.pem]"
        out = _shell("sh", _block(port) + 'echo "[$SSL_CERT_FILE]"', {"SSL_CERT_FILE": "/corp.pem"})
        assert out.stdout.strip() == "[/corp.pem]"
        out = _shell("sh", _block(port) + 'echo "[$HTTPS_PROXY]"', {"VOTAL_TERMINAL_PROXY": "off"})
        assert out.stdout.strip() == "[]"
    finally:
        srv.close()


def test_apply_and_remove_on_macos(tmp_path):
    p = _paths(tmp_path)
    files = (tmp_path / "zshenv", tmp_path / "profile")
    out = terminal.apply(p, "macos", 47824, run=_run_roots(100), mac_files=files)
    assert set(out["files"].values()) == {"written"}
    ok, detail = terminal.status(p, "macos", mac_files=files)
    assert ok and "CA bundle 101 certificates" in detail
    terminal.remove(p, "macos", mac_files=files)
    assert all(terminal.MARK_BEGIN not in f.read_text() for f in files)
    assert terminal.status(p, "macos", mac_files=files)[0] is False


def test_status_names_variables_set_by_another_tool(tmp_path):
    p = _paths(tmp_path)
    f = tmp_path / "zshenv"
    f.write_text("export SSL_CERT_FILE=/corp/bundle.pem\n")
    terminal.apply(p, "macos", 47824, run=_run_roots(100), mac_files=(f,))
    ok, detail = terminal.status(p, "macos", mac_files=(f,))
    assert "set by another tool: SSL_CERT_FILE" in detail


# ── Windows machine variables ─────────────────────────────────────────

class FakeWin(terminal.WinEnv):
    def __init__(self, env=None):
        self.env, self.broadcasts = dict(env or {}), 0

    def get(self, name):
        return self.env.get(name)

    def set(self, name, value):
        self.env[name] = value

    def delete(self, name):
        self.env.pop(name, None)

    def broadcast(self):
        self.broadcasts += 1


def test_windows_sets_then_clears_only_its_own(tmp_path):
    p = _paths(tmp_path)
    win = FakeWin({"CURL_CA_BUNDLE": "C:\\corp\\bundle.pem", "PATH": "x"})
    out = terminal.apply(p, "windows", 47824, run=_run_roots(100), win=win)
    assert out["windows"]["foreign"] == ["CURL_CA_BUNDLE"]
    assert win.env["CURL_CA_BUNDLE"] == "C:\\corp\\bundle.pem"           # left alone
    assert win.env["HTTPS_PROXY"] == "http://127.0.0.1:47824" and "https_proxy" not in win.env
    assert win.env["SSL_CERT_FILE"].endswith("ca-bundle.pem") and win.broadcasts == 1
    assert terminal.status(p, "windows", win=win)[0] is True
    win.env["NO_PROXY"] = "changed-by-admin"                             # no longer ours to remove
    removed = terminal.remove(p, "windows", win=win)["removed"]
    assert "HTTPS_PROXY" in removed and "NO_PROXY" not in removed
    assert win.env == {"CURL_CA_BUNDLE": "C:\\corp\\bundle.pem", "PATH": "x", "NO_PROXY": "changed-by-admin"}


def test_windows_drops_bundle_variables_when_the_export_fails(tmp_path):
    p = _paths(tmp_path)
    win = FakeWin()
    terminal.apply(p, "windows", 47824, run=_run_roots(100), win=win)
    assert "SSL_CERT_FILE" in win.env
    terminal.apply(p, "windows", 47824, run=_run_roots(3), win=win)
    assert not set(terminal.REPLACING) & set(win.env) and "HTTPS_PROXY" in win.env


# ── MDM setting and verify ────────────────────────────────────────────

BASE = {"ShieldURL": "https://s.example", "TenantID": "t", "Fleet": "f", "PinnedPublicKey": "a" * 64}


@pytest.mark.parametrize("raw,expected", [(True, True), (False, False), ("1", True), ("true", True),
                                          ("0", False), (1, True), (None, False)])
def test_terminal_coverage_setting(raw, expected):
    m = {**BASE} if raw is None else {**BASE, "TerminalCoverage": raw}
    assert managed.terminal_coverage(managed.validate(m)) is expected


def test_terminal_coverage_setting_rejects_junk():
    with pytest.raises(managed.ManagedError) as e:
        managed.validate({**BASE, "TerminalCoverage": "maybe"})
    assert "TerminalCoverage" in str(e.value)
    assert "TerminalCoverage" in managed.KEYS


def test_windows_reads_the_msi_property():
    m = managed.read_windows(lambda _k: {**BASE, "TerminalCoverage": "1", "ModelInline": ""})
    assert managed.terminal_coverage(m) is True


def test_firefox_check(tmp_path):
    assert installed.firefox_policy_check("macos", apps=[tmp_path / "nope.app"]) == (True, "Firefox not installed")
    app = tmp_path / "Firefox.app"
    app.mkdir()
    pol = tmp_path / "org.mozilla.firefox.plist"
    ok, detail = installed.firefox_policy_check("macos", apps=[app], mac_policy=pol)
    assert not ok and "without the Votal policy" in detail
    pol.write_bytes(b"x")
    assert installed.firefox_policy_check("macos", apps=[app], mac_policy=pol)[0]
    win_ok = lambda cmd, input=None, timeout=60: (0, b"ImportEnterpriseRoots REG_DWORD 0x1", b"")  # noqa: E731
    assert installed.firefox_policy_check("windows", run=win_ok, apps=[app])[0]


def test_service_start_applies_and_removes_by_setting(tmp_path, monkeypatch):
    p = _paths(tmp_path)
    calls = []
    monkeypatch.setattr(terminal, "apply", lambda p_, os_, port, run=None: calls.append(("apply", port))
                        or {"trust": {"reason": ""}})
    monkeypatch.setattr(terminal, "remove", lambda p_, os_: calls.append(("remove",)) or {})

    class A:
        proxy_port = 47824
    monkeypatch.setattr(managed, "read", lambda os_name: {**BASE, "TerminalCoverage": True})
    assert installed._terminal_coverage("macos", p, A()) is True
    monkeypatch.setattr(managed, "read", lambda os_name: {**BASE})
    assert installed._terminal_coverage("macos", p, A()) is False
    assert calls == [("apply", 47824), ("remove",)]


def test_msi_maps_the_property():
    wxs = (ROOT / "packages" / "votal-device-agent" / "packaging" / "windows" / "votal-device-agent.wxs").read_text()
    assert '<Property Id="TERMINALCOVERAGE"' in wxs
    assert 'Name="TerminalCoverage" Type="string" Value="[TERMINALCOVERAGE]"' in wxs
