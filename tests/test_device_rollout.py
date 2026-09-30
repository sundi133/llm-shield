"""Device DLP rollout kit.
Spec: docs/specs/device-rollout-kit.md (approved).

Task 1: what an unattended rollout needs before any kit exists. The service
waits for its MDM settings instead of restarting every 10 s; kit tokens have
their own limits; the agent's version is written in one place.
"""

import json
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_device_agent import ROOT, SK, pub  # noqa: F401  (sets sys.path)
from tests.test_device_packaging import SETTINGS, tmp_paths
from votal_device_agent import installed
from votal_device_agent.platform import managed

PKG = Path(ROOT) / "packages" / "votal-device-agent"


# ── the service waits for its settings ───────────────────────────────


def test_no_settings_waits_quietly_until_stopped(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {})
    said, stop = [], threading.Event()
    t = threading.Thread(target=lambda: said.append(
        installed.wait_for_settings("macos", p, stop, poll_s=0.01, log=said.append)))
    t.start()
    time.sleep(0.2)                                   # about 20 polls
    stop.set()
    t.join(2)
    messages = [m for m in said if isinstance(m, str)]
    assert len(messages) == 1 and "waiting for MDM settings" in messages[0]   # said once
    assert said[-1] is False


def test_it_starts_when_the_profile_arrives(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    arrived = {"m": {}}
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: arrived["m"])
    said, result = [], []
    t = threading.Thread(target=lambda: result.append(
        installed.wait_for_settings("macos", p, threading.Event(), poll_s=0.01, log=said.append)))
    t.start()
    time.sleep(0.05)
    arrived["m"] = SETTINGS
    t.join(2)
    assert result == [True] and said[-1] == "votal-device-agent: settings arrived, starting"


def test_invalid_settings_wait_with_the_reason(tmp_path, monkeypatch):
    p = tmp_paths(tmp_path)
    monkeypatch.setattr(managed, "read",
                        lambda os_name, **kw: {**SETTINGS, "PinnedPublicKey": "abc"})
    assert "64 hex" in installed.settings_problem("macos", p)


def test_a_broken_profile_later_keeps_the_last_good_settings(tmp_path, monkeypatch, capsys):
    p = tmp_paths(tmp_path)
    managed.write_agent_json(SETTINGS, p, "macos")
    good = p.config.read_text()
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {**SETTINGS, "Fleet": "Bad Fleet"})
    assert installed.settings_problem("macos", p) is None      # DLP stays on
    agent, _token = installed.build_agent("other", p)
    assert p.config.read_text() == good and agent.cfg.fleet == SETTINGS["Fleet"]
    assert "keeping the last good settings" in capsys.readouterr().out


def test_the_service_returns_cleanly_when_stopped_while_waiting(tmp_path, monkeypatch):
    monkeypatch.setattr(installed, "os_paths", lambda os_name=None: tmp_paths(tmp_path))
    monkeypatch.setattr(managed, "read", lambda os_name, **kw: {})
    stop = threading.Event()
    stop.set()
    assert installed.run_installed("macos", stop=stop) == 0


# ── kit tokens ───────────────────────────────────────────────────────


@pytest.fixture
def store():
    from core.dlp import devices as dv
    dv.reset_memory()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield dv
    dv.reset_memory()


def test_kit_tokens_have_their_own_limits(store):
    dv = store
    tid = "kt" + uuid.uuid4().hex[:8]
    kit = "kit_" + "a" * 16
    token, rec = dv.create_enrollment_token(tid, "sales", uses=100_000, expires_in_days=365,
                                            kind="kit", kit_id=kit, mdm="jamf")
    assert (rec["kind"], rec["kit_id"], rec["mdm"]) == ("kit", kit, "jamf")
    assert rec["expires_at"] - rec["created_at"] == 365 * 86400
    with pytest.raises(dv.DeviceError, match="1 to 100000"):
        dv.create_enrollment_token(tid, "sales", uses=100_001, kind="kit", kit_id=kit, mdm="jamf")
    with pytest.raises(dv.DeviceError, match="1 to 365"):
        dv.create_enrollment_token(tid, "sales", expires_in_days=366, kind="kit", kit_id=kit,
                                   mdm="jamf")
    # Hand-made tokens keep their limits.
    with pytest.raises(dv.DeviceError, match="1 to 90"):
        dv.create_enrollment_token(tid, "sales", expires_in_days=180)
    with pytest.raises(dv.DeviceError, match="1 to 10000"):
        dv.create_enrollment_token(tid, "sales", uses=20_000)
    assert dv.create_enrollment_token(tid, "sales")[1]["kind"] == "standard"
    kinds = {t["kind"] for t in dv.list_enrollment_tokens(tid)}
    assert kinds == {"kit", "standard"}


@pytest.mark.parametrize("kit_id, mdm", [("", "jamf"), ("kit_123", "jamf"),
                                         ("kit_" + "a" * 16, "workspace-one")])
def test_a_kit_token_needs_a_kit_and_a_known_mdm(store, kit_id, mdm):
    with pytest.raises(store.DeviceError, match="kit_id"):
        store.create_enrollment_token("kt1", "sales", kind="kit", kit_id=kit_id, mdm=mdm)


def test_the_portal_cannot_make_kit_tokens(store):
    """The kit API (task 3) is the only way to a 365-day token: the existing
    token endpoint ignores a kind in its body."""
    src = (Path(ROOT) / "api" / "routes_devices.py").read_text()
    create = src[src.index("async def create_enrollment_token"):src.index("async def list_enrollment_tokens")]
    assert "kind" not in create


# ── one version ──────────────────────────────────────────────────────


def _version() -> str:
    text = (PKG / "votal_device_agent" / "_version.py").read_text()
    return re.search(r'^__version__ = "(.*)"$', text, re.M).group(1)


def test_the_version_is_written_once():
    from votal_device_agent import __main__ as cli, __version__, sync
    assert cli.VERSION == sync.AGENT_VERSION == __version__ == _version()
    for f in (PKG / "votal_device_agent").rglob("*.py"):
        if f.name != "_version.py":
            assert not re.search(r'=\s*"\d+\.\d+\.\d+"', f.read_text()), f


def test_the_cli_reports_it():
    import os
    import sys
    out = subprocess.run([sys.executable, "-m", "votal_device_agent", "version"],
                         capture_output=True, text=True, timeout=30,
                         env={**os.environ, "PYTHONPATH": os.pathsep.join([str(PKG), ROOT])})
    assert out.stdout.strip() == _version()


def test_both_builds_default_to_it():
    sh = (PKG / "packaging" / "macos" / "build_pkg.sh").read_text()
    line = next(l for l in sh.splitlines() if l.startswith('VERSION="${VERSION:-'))
    out = subprocess.run(["bash", "-c", f'PKG_ROOT="{PKG}"; {line}; echo "$VERSION"'],
                         capture_output=True, text=True, timeout=10)
    assert out.stdout.strip() == _version()
    ps1 = (PKG / "packaging" / "windows" / "build_msi.ps1").read_text()
    assert '[string]$Version = ""' in ps1 and "_version.py" in ps1
    wf = (Path(ROOT) / ".github" / "workflows" / "device-agent-installers.yml").read_text()
    assert "0.1.0" not in wf and "_version.py" in wf


# ── task 2: the kit generator ────────────────────────────────────────

import dataclasses  # noqa: E402
import io as _io  # noqa: E402
import os  # noqa: E402
import plistlib  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import xml.etree.ElementTree as ET  # noqa: E402
import zipfile  # noqa: E402

from core.dlp import rollout_kit as rk  # noqa: E402

HOSTS = ["chatgpt.com", "claude.ai", "api.openai.com"]
EXT = "abcdefghijklmnopabcdefghijklmnop"
TOKEN = "vde.acme." + "T0kenSecretValue_" * 3


@pytest.fixture(scope="module")
def root_pem():
    os.environ["SHIELD_DEVICE_CA_MASTER_KEY"] = "4d" * 32
    try:
        with patch("storage.tenant_store._get_redis", return_value=None):
            from core.dlp import device_ca
            return device_ca.issue_root("acme", HOSTS)
    finally:
        os.environ.pop("SHIELD_DEVICE_CA_MASTER_KEY", None)


def kit_req(root, **over) -> rk.KitRequest:
    base = dict(tenant_id="acme", fleet="sales", mdm="jamf", kit_id="kit_" + "1" * 16,
                token=TOKEN, token_id="a" * 16, shield_url="https://api.guardrails.votal.ai",
                pinned_public_key=pub(SK), agent_version="0.1.0",
                release_base="https://github.com/sundi133/llm-shield/releases/download",
                ai_hosts=HOSTS, include_proxy=True, extension_ids=[EXT],
                root_pem=root["pem"], root_fingerprint=root["fingerprint_sha256"],
                apple_team_id="ABCDE12345", created_at=1790000000, expires_at=1805552000,
                uses=5000)
    base.update(over)
    return rk.KitRequest(**base)


EXPECTED = {
    ("jamf", ()): {"macos/Votal-Device-Agent.mobileconfig", "macos/get-installer.sh",
                   "macos/jamf-extension-attribute.sh"},
    ("kandji", ()): {"macos/Votal-Device-Agent.mobileconfig", "macos/get-installer.sh",
                     "macos/kandji-audit.sh"},
    ("intune", ("macos",)): {"macos/Votal-Device-Agent.mobileconfig", "macos/get-installer.sh",
                             "macos/intune-macos-attribute.sh"},
    ("intune", ("windows",)): {"windows/install-command.txt", "windows/get-installer.ps1",
                               "windows/detect.ps1", "windows/set-pac.ps1",
                               "windows/browser-extensions.ps1"},
}
COMMON = {"README.md", "SECURITY.txt", "kit.json"}


@pytest.mark.parametrize("mdm, platforms", list(EXPECTED))
def test_each_kit_has_exactly_its_files_and_no_placeholder(root_pem, mdm, platforms):
    files = rk.files(kit_req(root_pem, mdm=mdm, platforms=platforms))
    assert set(files) == EXPECTED[(mdm, platforms)] | COMMON
    for name, data in files.items():
        text = data.decode()
        assert "{{" not in text and "}}" not in text and "__PLACEHOLDER__" not in text, name
        if name.endswith((".md", ".txt")):
            assert "—" not in text, f"{name}: no em dashes in customer files"


def test_intune_defaults_to_both_platforms(root_pem):
    files = rk.files(kit_req(root_pem, mdm="intune"))
    assert set(files) == EXPECTED[("intune", ("macos",))] | EXPECTED[("intune", ("windows",))] | COMMON
    readme = files["README.md"].decode()
    assert "Macs, with Intune" in readme and "Windows, with Intune" in readme


def test_the_token_appears_only_where_it_must(root_pem):
    files = rk.files(kit_req(root_pem, mdm="intune"))
    carrying = {n for n, d in files.items() if TOKEN.encode() in d}
    assert carrying == set(rk.TOKEN_FILES)
    assert "token" not in json.loads(files["kit.json"])
    assert TOKEN not in files["README.md"].decode() + files["SECURITY.txt"].decode()
    assert all(f in files["SECURITY.txt"].decode() for f in rk.TOKEN_FILES)


def test_the_profile_is_everything_a_mac_needs(root_pem):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    doc = plistlib.loads(rk.files(kit_req(root_pem))["macos/Votal-Device-Agent.mobileconfig"])
    by = {p["PayloadType"]: p for p in doc["PayloadContent"]}
    assert set(by) == {"ai.votal.device-agent", "com.apple.security.root",
                       "com.apple.SystemConfiguration", "com.google.Chrome",
                       "com.microsoft.Edge", "com.apple.servicemanagement"}
    uuids = [doc["PayloadUUID"]] + [p["PayloadUUID"] for p in doc["PayloadContent"]]
    assert len(uuids) == len(set(uuids))
    assert by["com.apple.security.root"]["PayloadContent"] == x509.load_pem_x509_certificate(
        root_pem["pem"].encode()).public_bytes(serialization.Encoding.DER)
    assert by["com.apple.SystemConfiguration"]["Proxies"]["ProxyAutoConfigURLString"] == \
        "http://127.0.0.1:47823/proxy.pac"
    rule = by["com.apple.servicemanagement"]["Rules"][0]
    assert (rule["RuleType"], rule["RuleValue"], rule["TeamIdentifier"]) == \
        ("Label", "ai.votal.device-agent", "ABCDE12345")
    assert by["com.google.Chrome"]["ExtensionInstallForcelist"] == [
        f"{EXT};https://clients2.google.com/service/update2/crx"]
    # The agent itself accepts these settings, as it reads them from MDM.
    settings = {k: v for k, v in by["ai.votal.device-agent"].items() if not k.startswith("Payload")}
    assert managed.validate(settings)["EnrollmentToken"] == TOKEN
    assert settings["CAMode"] == "tenant"


def test_a_newer_kit_replaces_the_profile_not_adds_one(root_pem):
    a = plistlib.loads(rk.files(kit_req(root_pem))["macos/Votal-Device-Agent.mobileconfig"])
    b = plistlib.loads(rk.files(kit_req(root_pem, kit_id="kit_" + "2" * 16))[
        "macos/Votal-Device-Agent.mobileconfig"])
    assert a["PayloadIdentifier"] == b["PayloadIdentifier"] == "ai.votal.device-agent.acme.sales"
    assert a["PayloadUUID"] != b["PayloadUUID"]
    other = plistlib.loads(rk.files(kit_req(root_pem, fleet="finance"))[
        "macos/Votal-Device-Agent.mobileconfig"])
    assert other["PayloadIdentifier"] != a["PayloadIdentifier"]


def test_an_existing_proxy_gets_pac_lines_instead(root_pem):
    files = rk.files(kit_req(root_pem, mdm="intune", include_proxy=False))
    doc = plistlib.loads(files["macos/Votal-Device-Agent.mobileconfig"])
    assert "com.apple.SystemConfiguration" not in {p["PayloadType"] for p in doc["PayloadContent"]}
    assert "windows/set-pac.ps1" not in files
    readme = files["README.md"].decode()
    snippet = readme[readme.index("```javascript") + 13:readme.index("```", readme.index("```javascript") + 13)]
    if shutil.which("node"):                       # the lines really route AI hosts only
        js = ("function shExpMatch(s,p){return new RegExp('^'+p.replace(/\\./g,'\\\\.')"
              ".replace(/\\*/g,'.*')+'$').test(s)}\nfunction FindProxyForURL(url, host) {\n"
              + snippet + '\n  return "DIRECT";\n}\n'
              "console.log(JSON.stringify(['chatgpt.com','x.claude.ai','notclaude.ai','example.org']"
              ".map(h => FindProxyForURL('', h))))")
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=10)
        assert json.loads(out.stdout) == ["PROXY 127.0.0.1:47824; DIRECT"] * 2 + ["DIRECT"] * 2


def test_no_extension_id_leaves_the_extension_out(root_pem):
    files = rk.files(kit_req(root_pem, mdm="intune", extension_ids=[]))
    types = {p["PayloadType"] for p in plistlib.loads(
        files["macos/Votal-Device-Agent.mobileconfig"])["PayloadContent"]}
    assert not types & {"com.google.Chrome", "com.microsoft.Edge"}
    assert "windows/browser-extensions.ps1" not in files
    assert "does not install the Votal browser extension" in files["README.md"].decode()


def test_the_windows_arguments_are_the_msis_properties(root_pem):
    text = rk.files(kit_req(root_pem, mdm="intune", platforms=("windows",)))[
        "windows/install-command.txt"].decode()
    args = next(l for l in text.splitlines() if l.startswith("SHIELDURL="))
    props = dict(a.split("=", 1) for a in args.split())
    ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
    wxs = ET.parse(PKG / "packaging" / "windows" / "votal-device-agent.wxs").getroot()
    declared = {p.get("Id") for p in wxs.findall(".//w:Property", ns)}
    assert set(props) <= declared
    assert props["ENROLLMENTTOKEN"] == TOKEN and props["EXTENSIONIDS"] == EXT
    assert f"msiexec /i votal-device-agent-0.1.0.msi /qn {args}" in text


@pytest.mark.parametrize("field_, value", [
    ("tenant_id", "acme$(touch /tmp/x)"), ("fleet", "sales; rm -rf /"),
    ("shield_url", "http://shield.example.com"), ("shield_url", 'https://a.example" -x'),
    ("release_base", "https://x.example/a b"), ("agent_version", "1.0; id"),
    ("apple_team_id", "abc"), ("windows_signer", "Votal'; Remove-Item"),
    ("extension_ids", ["not-an-id"]), ("ai_hosts", ["evil host"]), ("token", "vde.acme.short"),
])
def test_values_that_could_carry_script_syntax_are_refused(root_pem, field_, value):
    with pytest.raises(rk.KitError):
        rk.files(kit_req(root_pem, **{field_: value}))


def test_platform_and_root_rules(root_pem):
    with pytest.raises(rk.KitError, match="jamf manages macos"):
        rk.files(kit_req(root_pem, mdm="jamf", platforms=("windows",)))
    with pytest.raises(rk.KitError, match="root_pem"):
        rk.files(kit_req(root_pem, root_pem=""))
    rk.files(kit_req(root_pem, mdm="intune", platforms=("windows",), root_pem=""))  # not needed


def test_scripts_parse(root_pem):
    files = rk.files(kit_req(root_pem, mdm="intune"))
    for name, data in files.items():
        if name.endswith(".sh"):
            assert subprocess.run(["bash", "-n"], input=data).returncode == 0, name
    if shutil.which("pwsh"):
        for name, data in files.items():
            if name.endswith(".ps1"):
                cmd = ("$e=$null; [System.Management.Automation.Language.Parser]::ParseInput("
                       "[Console]::In.ReadToEnd(), [ref]$null, [ref]$e) | Out-Null; exit $e.Count")
                assert subprocess.run(["pwsh", "-NoProfile", "-Command", cmd],
                                      input=data).returncode == 0, name


def _stub_bin(tmp_path, sig: str, spctl: str):
    b = tmp_path / "bin"
    b.mkdir()
    for name, body in {"curl": 'for a; do [ "$prev" = "-o" ] && echo pkg > "$a"; prev="$a"; done',
                       "pkgutil": f'printf "%s\\n" "{sig}"',
                       "spctl": f'echo "{spctl}" >&2'}.items():
        (b / name).write_text(f"#!/bin/bash\n{body}\n")
        (b / name).chmod(0o755)
    return b


@pytest.mark.parametrize("sig, spctl, args, code", [
    ("Status: no signature", "", [], 2),
    ("1. Developer ID Installer: Someone Else (ZZZZZ99999)", "accepted", [], 2),
    ("1. Developer ID Installer: Votal AI (ABCDE12345)", "rejected", [], 2),
    ("1. Developer ID Installer: Votal AI (ABCDE12345)", "accepted", [], 0),
    ("Status: no signature", "", ["--allow-unsigned"], 0),
])
def test_get_installer_refuses_what_votal_did_not_sign(root_pem, tmp_path, sig, spctl, args, code):
    script = tmp_path / "get-installer.sh"
    script.write_bytes(rk.files(kit_req(root_pem))["macos/get-installer.sh"])
    b = _stub_bin(tmp_path, sig, spctl)
    out = subprocess.run(["bash", str(script), *args], capture_output=True, text=True, timeout=20,
                         cwd=tmp_path, env={**os.environ, "PATH": f"{b}:{os.environ['PATH']}"})
    assert out.returncode == code, out.stderr
    if code == 0:
        assert out.stdout.strip().endswith("votal-device-agent-0.1.0.pkg")


def test_the_zip(root_pem):
    data = rk.build(kit_req(root_pem, mdm="intune"))
    assert data == rk.build(kit_req(root_pem, mdm="intune"))          # deterministic
    with zipfile.ZipFile(_io.BytesIO(data)) as z:
        names = z.namelist()
        assert all(n.startswith("votal-rollout-kit-sales-intune/") for n in names)
        for info in z.infolist():
            mode = info.external_attr >> 16
            assert bool(mode & stat.S_IXUSR) == info.filename.endswith(".sh"), info.filename


def test_templates_ship_in_both_images():
    """.dockerignore drops *.md: every template is *.tmpl, and every one is used."""
    tmpls = sorted(p.relative_to(rk.TEMPLATES).as_posix() for p in rk.TEMPLATES.rglob("*")
                   if p.is_file())
    assert tmpls and all(t.endswith(".tmpl") for t in tmpls)
    src = (Path(ROOT) / "core" / "dlp" / "rollout_kit.py").read_text()
    for t in tmpls:
        stem = t[:-len(".tmpl")]
        base = stem.rsplit("/", 1)[-1]
        assert stem in src or base in src or "README-{req.mdm}" in src, f"unused template {t}"
    assert "COPY core/dlp/ core/dlp/" in (Path(ROOT) / "Dockerfile.admin").read_text()
    assert "COPY core/ core/" in (Path(ROOT) / "Dockerfile").read_text()


@pytest.mark.parametrize("include_proxy, ext, says, not_says", [
    (True, [EXT], ["the AI proxy setting", "set-pac.ps1", "browser-extensions.ps1"], []),
    (False, [EXT], ["browser-extensions.ps1", "It install the browser extension"[:9]],
     ["the AI proxy setting", "set-pac.ps1"]),
    (True, [], ["set-pac.ps1"], ["the browser extension and", "browser-extensions.ps1"]),
    (False, [], ["None needed"], ["the AI proxy setting", "set-pac.ps1", "browser-extensions.ps1"]),
])
def test_the_readme_describes_this_kit_not_every_kit(root_pem, include_proxy, ext, says, not_says):
    readme = rk.files(kit_req(root_pem, mdm="intune", include_proxy=include_proxy,
                              extension_ids=ext))["README.md"].decode()
    for s in says:
        assert s in readme, s
    for s in not_says:
        assert s not in readme, s
    assert readme.count("## Your existing proxy (PAC) file") == (0 if include_proxy else 1)
