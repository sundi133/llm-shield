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


def _stub_bin(tmp_path, sig: str, spctl: str, sums_ok: bool = True):
    import hashlib
    b = tmp_path / "bin"
    b.mkdir()
    digest = hashlib.sha256(b"pkg\n").hexdigest() if sums_ok else "0" * 64
    # curl: -o FILE writes the "pkg"; without -o (the SHA256SUMS fetch) it prints the sums.
    curl = ('out=""; for a; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done\n'
            'if [ -n "$out" ]; then echo pkg > "$out"; else '
            f'echo "{digest}  votal-device-agent-0.1.0.pkg"; fi')
    for name, body in {"curl": curl,
                       "pkgutil": f'printf "%s\\n" "{sig}"',
                       "spctl": f'echo "{spctl}" >&2'}.items():
        (b / name).write_text(f"#!/bin/bash\n{body}\n")
        (b / name).chmod(0o755)
    return b


@pytest.mark.parametrize("sig, spctl, args, code", [
    ("Status: no signature", "", [], 2),
    ("1. Developer ID Installer: Votal AI (ABCDE12345)", "accepted", ["--bad-sums"], 2),
    ("Status: no signature", "", ["--allow-unsigned", "--bad-sums"], 2),
    ("1. Developer ID Installer: Someone Else (ZZZZZ99999)", "accepted", [], 2),
    ("1. Developer ID Installer: Votal AI (ABCDE12345)", "rejected", [], 2),
    ("1. Developer ID Installer: Votal AI (ABCDE12345)", "accepted", [], 0),
    ("Status: no signature", "", ["--allow-unsigned"], 0),
])
def test_get_installer_refuses_what_votal_did_not_sign(root_pem, tmp_path, sig, spctl, args, code):
    script = tmp_path / "get-installer.sh"
    script.write_bytes(rk.files(kit_req(root_pem))["macos/get-installer.sh"])
    b = _stub_bin(tmp_path, sig, spctl, sums_ok="--bad-sums" not in args)
    args = [a for a in args if a != "--bad-sums"]
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


# ── task 3: the kit API ──────────────────────────────────────────────

KITS = "/v1/tenant/me/devices/rollout-kits"


@pytest.fixture
def api(monkeypatch):
    """A tenant on Shield's data plane with signing and the device CA configured."""
    from starlette.testclient import TestClient
    from core.dlp import devices as dv
    from core.runtime_policy import bundle as rt_bundle
    from storage import tenant_store as ts
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", SK)
    monkeypatch.setenv("SHIELD_DEVICE_CA_MASTER_KEY", "4d" * 32)
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_SHIELD_URL", "https://shield.example.com")
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        app = create_app()
        tid = "rk" + uuid.uuid4().hex[:8]
        key = "sk-rk-" + uuid.uuid4().hex
        ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
        c = TestClient(app, headers={"X-API-Key": key})
        c.tenant_id, c.app_ = tid, app
        yield c
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()


def _kit(api, **body):
    r = api.post(KITS, json={"fleet": "sales", "mdm": "intune", **body})
    assert r.status_code == 200, r.text
    z = zipfile.ZipFile(_io.BytesIO(r.content))
    files = {n.split("/", 1)[1]: z.read(n) for n in z.namelist()}
    return r, files


def _token_from(files) -> str:
    return re.search(r"ENROLLMENTTOKEN=(\S+)", files["windows/install-command.txt"].decode()).group(1)


def test_a_kits_token_enrolls_a_laptop(api):
    from starlette.testclient import TestClient
    r, files = _kit(api)
    assert r.headers["content-type"] == "application/zip"
    kit_id = r.headers["X-Votal-Kit-Id"]
    token = _token_from(files)
    laptop = {"hostname": "ana-pc", "os": "windows", "os_version": "11", "agent_version": "0.1.0",
              "serial_hash": "ab" * 32}
    out = TestClient(api.app_).post("/v1/devices/enroll", json=laptop,
                                    headers={"X-Enrollment-Token": token})
    assert out.status_code == 200 and out.json()["fleet"] == "sales"
    kit = next(k for k in api.get(KITS).json()["kits"] if k["kit_id"] == kit_id)
    assert (kit["status"], kit["uses_left"], kit["uses"]) == ("active", 4999, 5000)
    # The same kit's Mac profile carries the same token, and the right Shield.
    settings = next(p for p in plistlib.loads(files["macos/Votal-Device-Agent.mobileconfig"])[
        "PayloadContent"] if p["PayloadType"] == "ai.votal.device-agent")
    assert settings["EnrollmentToken"] == token
    assert settings["ShieldURL"] == "https://shield.example.com"


def test_the_list_never_shows_a_token(api):
    _r, files = _kit(api)
    listing = json.dumps(api.get(KITS).json())
    assert _token_from(files) not in listing and "vde." not in listing


def test_revoking_a_kit_stops_its_token_only(api):
    from starlette.testclient import TestClient
    r, files = _kit(api)
    token, kit_id = _token_from(files), r.headers["X-Votal-Kit-Id"]
    laptop = {"hostname": "a", "os": "windows", "os_version": "11", "agent_version": "0.1.0"}
    enrolled = TestClient(api.app_).post("/v1/devices/enroll", json=laptop,
                                         headers={"X-Enrollment-Token": token}).json()
    assert api.delete(f"{KITS}/{kit_id}").json()["revoked"] is True
    again = TestClient(api.app_).post("/v1/devices/enroll", json=laptop,
                                      headers={"X-Enrollment-Token": token})
    assert again.status_code == 401
    device = TestClient(api.app_, headers={"X-API-Key": enrolled["api_key"]})
    assert device.post("/v1/devices/heartbeat", json={}).status_code == 204   # still works
    revoked = next(k for k in api.get(KITS).json()["kits"])
    assert (revoked["status"], revoked["uses_left"]) == ("revoked", None)
    assert api.delete(f"{KITS}/kit_{'0' * 16}").status_code == 404


def test_revoke_previous_retires_the_fleets_older_kits(api):
    first, _ = _kit(api)
    other_fleet, _ = _kit(api, fleet="finance")
    second, _ = _kit(api, revoke_previous=True)
    listing = api.get(KITS).json()["kits"]
    assert listing[0]["kit_id"] == second.headers["X-Votal-Kit-Id"]         # newest first
    by = {k["kit_id"]: k["status"] for k in listing}
    assert by[first.headers["X-Votal-Kit-Id"]] == "revoked"
    assert by[second.headers["X-Votal-Kit-Id"]] == "active"
    assert by[other_fleet.headers["X-Votal-Kit-Id"]] == "active"      # another fleet untouched


def test_a_kit_reissues_a_root_that_no_longer_covers_the_policy(api):
    old, _ = _kit(api, mdm="jamf")
    assert old.headers["X-Votal-Root-Reissued"] == "0"
    hosts = api.get("/v1/tenant/me/dlp-policy").json()["policy"]["ai_hosts"]
    api.put("/v1/tenant/me/dlp-policy", json={"ai_hosts": hosts + ["newai.example"]})
    stale = next(k for k in api.get(KITS).json()["kits"])
    assert any("newai.example" in s for s in stale["stale"])
    with patch("api.routes_devices.log_admin_action") as audit:
        new, files = _kit(api, mdm="jamf")
    assert new.headers["X-Votal-Root-Reissued"] == "1"
    actions = [c.kwargs["action"] for c in audit.call_args_list]
    assert actions == ["tenant_reissue_device_root_ca", "tenant_create_rollout_kit"]
    root = next(p for p in plistlib.loads(files["macos/Votal-Device-Agent.mobileconfig"])[
        "PayloadContent"] if p["PayloadType"] == "com.apple.security.root")
    from cryptography import x509
    nc = x509.load_der_x509_certificate(root["PayloadContent"]).extensions.get_extension_for_class(
        x509.NameConstraints).value
    assert "newai.example" in {n.value for n in nc.permitted_subtrees}
    kits_now = {k["kit_id"]: k for k in api.get(KITS).json()["kits"]}
    assert any("reissued" in s for s in kits_now[old.headers["X-Votal-Kit-Id"]]["stale"])
    assert not kits_now[new.headers["X-Votal-Kit-Id"]]["stale"]


def test_the_audit_never_carries_the_token(api):
    with patch("api.routes_devices.log_admin_action") as audit:
        _r, files = _kit(api)
    logged = json.dumps([c.kwargs for c in audit.call_args_list], default=str)
    assert _token_from(files) not in logged and "tenant_create_rollout_kit" in logged


@pytest.mark.parametrize("body, needle", [
    ({"mdm": "workspace-one"}, "mdm"), ({"fleet": "Sales Team"}, "fleet"),
    ({"mdm": "jamf", "platforms": ["windows"]}, "jamf manages macos"),
    ({"expires_in_days": 400}, "1 to 365"), ({"uses": 0}, "uses"),
    ({"extension_ids": ["bad"]}, "extension id"), ({"turbo": True}, "unknown field"),
    ({"include_proxy": "yes"}, "include_proxy"),
])
def test_a_bad_request_mints_no_token(api, body, needle):
    from core.dlp import devices as dv
    before = len(dv.list_enrollment_tokens(api.tenant_id))
    r = api.post(KITS, json={"fleet": "sales", "mdm": "intune", **body})
    assert r.status_code == 400 and needle in r.text
    assert len(dv.list_enrollment_tokens(api.tenant_id)) == before


def test_missing_keys_are_named(api, monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    monkeypatch.delenv("SHIELD_DEVICE_CA_MASTER_KEY")
    r = api.post(KITS, json={"fleet": "sales", "mdm": "jamf"})
    assert r.status_code == 503 and "SHIELD_DEVICE_CA_MASTER_KEY" in r.text
    ok, files = _kit(api, platforms=["windows"])                       # Windows needs no root
    assert "macos/Votal-Device-Agent.mobileconfig" not in files
    monkeypatch.delenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY")
    rt_bundle.reset_signer_cache_for_tests()
    r = api.post(KITS, json={"fleet": "sales", "mdm": "intune", "platforms": ["windows"]})
    assert r.status_code == 503 and "SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY" in r.text


def test_kits_follow_the_registry_write_gate(api, monkeypatch):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    rt_key = "sk-rkr-" + uuid.uuid4().hex
    ts.add_api_key(api.tenant_id, rt_key, scope="runtime")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    rt = TestClient(api.app_, headers={"X-API-Key": rt_key})
    assert rt.post(KITS, json={"fleet": "sales", "mdm": "jamf"}).status_code == 403
    assert rt.get(KITS).status_code == 200


def test_tenants_see_only_their_kits(api):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    r, _ = _kit(api)
    key = "sk-rk2-" + uuid.uuid4().hex
    ts.create_tenant("rk" + uuid.uuid4().hex[:8], {"name": "o", "plan": "enterprise"}, api_keys=[key])
    other = TestClient(api.app_, headers={"X-API-Key": key})
    assert other.get(KITS).json()["kits"] == []
    assert other.delete(f"{KITS}/{r.headers['X-Votal-Kit-Id']}").status_code == 404


def test_the_shield_url_in_a_kit(api, monkeypatch):
    """Laptops must be pointed at a data plane over https."""
    from api.routes_devices import _kit_shield_url
    from fastapi import HTTPException
    from types import SimpleNamespace
    import admin_app
    # The real apps, so this holds whatever FastAPI does with included routers.
    data_plane, admin_plane = api.app_, admin_app.app
    monkeypatch.delenv("SHIELD_DEVICE_AGENT_SHIELD_URL")
    req = lambda app, base: SimpleNamespace(app=app, base_url=base)
    assert _kit_shield_url(req(data_plane, "https://api.example.com/")) == "https://api.example.com"
    for app, base in ((admin_plane, "https://portal.example.com/"), (data_plane, "http://x.example/")):
        with pytest.raises(HTTPException) as e:
            _kit_shield_url(req(app, base))
        assert e.value.status_code == 503 and "SHIELD_DEVICE_AGENT_SHIELD_URL" in e.value.detail
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_SHIELD_URL", "https://shield.corp.example/")
    assert _kit_shield_url(req(admin_plane, "https://portal.example.com/")) == \
        "https://shield.corp.example"


def test_kits_pin_the_agents_own_version():
    from core.dlp import kits
    assert kits.DEFAULT_AGENT_VERSION == _version()


def test_the_admin_image_has_the_kit_code():
    df = (Path(ROOT) / "Dockerfile.admin").read_text()
    assert "COPY core/dlp/ core/dlp/" in df and "COPY api/routes_devices.py api/" in df


# ── task 4: the company inventory ────────────────────────────────────

INV = "/v1/tenant/me/devices/inventory"
JAMF_EXPORT = ("Computer Name,Serial Number,Model\n"
               "ana-mbp,C02XK0AAJG5H,MacBook Pro\n"
               "raj-mba,FVFZ1234ABCD,MacBook Air\n")
INTUNE_EXPORT = ('﻿"Device name","Serial number","OS"\n'
                 '"RAJ-PC","5CG1234XYZ","Windows"\n'
                 '"LEE-PC","  pf2abc12  ","Windows"\n'
                 '"BAD","not a serial!!","Windows"\n')


def _enroll_with(api, token, serial):
    from starlette.testclient import TestClient
    from votal_device_agent.agent import serial_hash
    body = {"hostname": "h-" + (serial or "none")[:8], "os": "macos", "os_version": "14",
            "agent_version": "0.1.0", "serial_hash": serial_hash(serial) if serial else ""}
    return TestClient(api.app_).post("/v1/devices/enroll", json=body,
                                     headers={"X-Enrollment-Token": token})


def _token(api):
    return api.post("/v1/tenant/me/devices/enrollment-tokens",
                    json={"fleet": "sales", "uses": 20}).json()


def test_off_until_uploaded(api):
    assert api.get(INV).json()["enforced"] is False
    assert _enroll_with(api, _token(api)["enrollment_token"], "ANYTHING1").status_code == 200


@pytest.mark.parametrize("body, ctype, count, skipped", [
    (JAMF_EXPORT, "text/csv", 2, 0),
    (INTUNE_EXPORT, "text/csv", 2, 1),
    ("C02XK0AAJG5H\nFVFZ1234ABCD\nC02XK0AAJG5H\n", "text/plain", 2, 0),
    (json.dumps({"serials": ["C02XK0AAJG5H", "x"]}), "application/json", 2, 0),
    (json.dumps(["C02XK0AAJG5H"]), "application/json", 1, 0),
])
def test_the_exports_mdms_produce(api, body, ctype, count, skipped):
    r = api.put(INV, content=body.encode(), headers={"Content-Type": ctype})
    assert r.status_code == 200, r.text
    assert (r.json()["count"], r.json()["skipped"]) == (count, skipped)
    status = api.get(INV).json()
    assert status["enforced"] and status["count"] == count and "serials" not in status


def test_only_inventory_laptops_enroll(api):
    api.put(INV, content=INTUNE_EXPORT.encode(), headers={"Content-Type": "text/csv"})
    tok = _token(api)
    assert _enroll_with(api, tok["enrollment_token"], "5CG1234XYZ").status_code == 200
    # Firmware reports case and whitespace differently from the export: still a match.
    assert _enroll_with(api, tok["enrollment_token"], "PF2ABC12").status_code == 200
    with patch("core.runtime_policy.events.ingest") as ingest:
        r = _enroll_with(api, tok["enrollment_token"], "NOTOURS999")
    assert r.status_code == 403 and "not in the company inventory" in r.text
    ev = ingest.call_args.args[1][0]
    assert (ev["severity"], ev["detail"]["why"]) == ("high", "not_in_inventory")
    assert "not in the company inventory" in __import__(
        "core.runtime_policy.events", fromlist=["summary"]).summary(ev)
    assert _enroll_with(api, tok["enrollment_token"], "").status_code == 403   # no serial read
    left = next(t for t in api.get("/v1/tenant/me/devices/enrollment-tokens").json()["tokens"]
                if t["token_id"] == tok["token_id"])["uses_left"]
    assert left == 18                                   # refusals spent no use


def test_serials_are_never_stored_as_uploaded(api):
    from storage.tenant_store import _fallback_store
    from core.dlp import devices as dv
    api.put(INV, content=JAMF_EXPORT.encode(), headers={"Content-Type": "text/csv"})
    stored = json.dumps({k: str(v) for k, v in _fallback_store.items()}) + str(dv._mem_sets)
    assert "C02XK0AAJG5H" not in stored and "FVFZ1234ABCD" not in stored
    with patch("api.routes_devices.log_admin_action") as audit:
        api.put(INV, content=JAMF_EXPORT.encode(), headers={"Content-Type": "text/csv"})
    assert "C02XK0AAJG5H" not in json.dumps([c.kwargs for c in audit.call_args_list], default=str)


def test_an_upload_replaces_and_clear_turns_it_off(api):
    api.put(INV, content=b"C02XK0AAJG5H\n", headers={"Content-Type": "text/plain"})
    api.put(INV, content=b"FVFZ1234ABCD\n", headers={"Content-Type": "text/plain"})
    tok = _token(api)["enrollment_token"]
    assert _enroll_with(api, tok, "C02XK0AAJG5H").status_code == 403            # replaced
    assert api.delete(INV).json() == {"tenant_id": api.tenant_id, "cleared": True,
                                      "enforced": False}
    assert _enroll_with(api, tok, "C02XK0AAJG5H").status_code == 200


@pytest.mark.parametrize("body, ctype, needle, status", [
    ("Name,Model\na,b\n", "text/csv", "serial", 400),
    ("{not json", "application/json", "JSON", 400),
    ("", "text/csv", "no serial numbers", 400),
])
def test_bad_uploads(api, body, ctype, needle, status):
    r = api.put(INV, content=body.encode(), headers={"Content-Type": ctype})
    assert r.status_code == status and needle in r.text
    assert api.get(INV).json()["enforced"] is False


def test_the_size_cap(api, monkeypatch):
    from core.dlp import devices as dv
    monkeypatch.setattr(dv, "INVENTORY_MAX", 3)
    r = api.put(INV, content=b"A1\nA2\nA3\nA4\n", headers={"Content-Type": "text/plain"})
    assert r.status_code == 413


def test_inventory_writes_follow_the_gate_and_stay_in_the_tenant(api, monkeypatch):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    api.put(INV, content=JAMF_EXPORT.encode(), headers={"Content-Type": "text/csv"})
    key = "sk-inv-" + uuid.uuid4().hex
    ts.create_tenant("inv" + uuid.uuid4().hex[:8], {"name": "o", "plan": "enterprise"},
                     api_keys=[key])
    assert TestClient(api.app_, headers={"X-API-Key": key}).get(INV).json()["enforced"] is False
    rt_key = "sk-invr-" + uuid.uuid4().hex
    ts.add_api_key(api.tenant_id, rt_key, scope="runtime")
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    rt = TestClient(api.app_, headers={"X-API-Key": rt_key})
    assert rt.put(INV, content=b"X1\n", headers={"Content-Type": "text/plain"}).status_code == 403
    assert rt.delete(INV).status_code == 403


def test_the_laptop_and_shield_hash_serials_the_same_way():
    from core.dlp.devices import serial_hash as server
    from votal_device_agent.agent import serial_hash as laptop
    for s in ("C02XK0AAJG5H", " c02xk0aajg5h ", "5CG1234XYZ\n"):
        assert laptop(s) == server(s) == server("C02XK0AAJG5H" if "c02" in s.lower() else s)
    assert laptop("") == ""


class FakeSetRedis:
    """The Redis set commands the inventory uses, and nothing else."""

    def __init__(self):
        self.sets, self.ops = {}, []

    def sadd(self, key, *members):
        self.ops.append(("sadd", key))
        self.sets.setdefault(key, set()).update(members)

    def rename(self, src, dst):
        self.ops.append(("rename", src, dst))
        self.sets[dst] = self.sets.pop(src)

    def delete(self, key):
        self.ops.append(("delete", key))
        self.sets.pop(key, None)

    def scard(self, key):
        return len(self.sets.get(key, ()))

    def sismember(self, key, member):
        return member in self.sets.get(key, ())


def test_the_redis_path_swaps_the_inventory_atomically(store, monkeypatch):
    dv = store
    fake = FakeSetRedis()
    monkeypatch.setattr(dv, "_redis", lambda: fake)
    tid = "rinv" + uuid.uuid4().hex[:6]
    many = [f"SER{i:06d}" for i in range(2500)]                       # more than one batch
    dv.set_inventory(tid, many)
    key = f"device_inventory:{tid}"
    adds = [op for op in fake.ops if op[0] == "sadd"]
    assert len(adds) == 3 and all(op[1] != key for op in adds)        # built aside...
    assert fake.ops[-1][0] == "rename" and fake.ops[-1][2] == key     # ...then swapped in
    assert dv.inventory_allows(tid, dv.serial_hash("ser000042")) is True
    assert dv.inventory_allows(tid, dv.serial_hash("OTHER")) is False
    dv.set_inventory(tid, ["ONLY1"])
    assert fake.scard(key) == 1 and dv.inventory_status(tid)["count"] == 1
    dv.clear_inventory(tid)
    assert dv.inventory_allows(tid, dv.serial_hash("ONLY1")) is None


def test_delete_inventory_is_not_taken_for_a_device_id(api):
    """Behavioral, not a scan of app.routes (whose shape changes across FastAPI
    versions): DELETE .../inventory must reach the inventory route."""
    r = api.delete(INV)
    assert r.status_code == 200 and r.json()["enforced"] is False and "cleared" in r.json()


# ── task 5: the release pipeline ─────────────────────────────────────

import hashlib as _hashlib  # noqa: E402
import http.server  # noqa: E402
import importlib.util  # noqa: E402
import tarfile  # noqa: E402

PACKAGING = PKG / "packaging"


def _fetch_mod():
    spec = importlib.util.spec_from_file_location("fetch_ollama", PACKAGING / "fetch_ollama.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_lock_pins_a_release_the_agent_can_use():
    lock = json.loads((PACKAGING / "ollama.lock").read_text())
    assert re.match(r"^\d+\.\d+\.\d+$", lock["version"])
    assert lock["source"].endswith(f"/v{lock['version']}")
    for plat, asset in lock["assets"].items():
        assert re.match(r"^[0-9a-f]{64}$", asset["sha256"]), plat
        assert asset["binary"] in ("ollama", "ollama.exe")
    assert "lib/ollama/cuda_v12/*" in lock["assets"]["windows"]["exclude"]
    from core.dlp.device_policy import DEFAULT_MODEL
    need = tuple(int(x) for x in DEFAULT_MODEL["min_ollama"].split("."))
    assert tuple(int(x) for x in lock["version"].split(".")) >= need     # has /v1/systemone


@pytest.fixture
def served(tmp_path):
    """A local release: archives in a folder, served over HTTP."""
    root = tmp_path / "release"
    root.mkdir()

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return _hashlib.sha256(path.read_bytes()).hexdigest()


def _tgz(path, entries):
    with tarfile.open(path, "w:gz") as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            t.addfile(info, _io.BytesIO(data))
    return _hashlib.sha256(path.read_bytes()).hexdigest()


def _lock(tmp_path, source, **assets):
    p = tmp_path / "test.lock"
    p.write_text(json.dumps({"version": "9.9.9", "source": source, "assets": assets}))
    return p


def test_fetch_verifies_then_unpacks_without_cuda(served, tmp_path):
    fo = _fetch_mod()
    root, url = served
    digest = _zip(root / "ollama-windows-amd64.zip", {
        "ollama.exe": b"exe", "lib/ollama/ggml-cpu.dll": b"cpu",
        "lib/ollama/cuda_v12/big.dll": b"x" * 1000, "lib/ollama/cuda_v13/big.dll": b"y"})
    lock = _lock(tmp_path, url, windows={"name": "ollama-windows-amd64.zip", "sha256": digest,
                                         "binary": "ollama.exe",
                                         "exclude": ["lib/ollama/cuda_v12/*",
                                                     "lib/ollama/cuda_v13/*"]})
    dest = tmp_path / "out"
    assert fo.fetch("windows", dest, lock) == dest / "ollama.exe"
    assert (dest / "lib/ollama/ggml-cpu.dll").exists()
    assert not (dest / "lib/ollama/cuda_v12").exists() and not (dest / "lib/ollama/cuda_v13").exists()
    digest = _tgz(root / "ollama-darwin.tgz", {"ollama": b"bin", "libggml-cpu.so": b"so"})
    lock = _lock(tmp_path, url, macos={"name": "ollama-darwin.tgz", "sha256": digest,
                                       "binary": "ollama", "exclude": []})
    out = fo.fetch("macos", tmp_path / "mac", lock)
    assert out.read_bytes() == b"bin" and os.access(out, os.X_OK)


def test_fetch_refuses_a_changed_archive_and_unpacks_nothing(served, tmp_path):
    fo = _fetch_mod()
    root, url = served
    _zip(root / "ollama-windows-amd64.zip", {"ollama.exe": b"tampered"})
    lock = _lock(tmp_path, url, windows={"name": "ollama-windows-amd64.zip", "sha256": "0" * 64,
                                         "binary": "ollama.exe", "exclude": []})
    with pytest.raises(fo.FetchError, match="SHA-256 mismatch"):
        fo.fetch("windows", tmp_path / "out", lock)
    assert not (tmp_path / "out").exists()
    assert fo.main(["windows", str(tmp_path / "out"), "--lock", str(lock)]) == 2


@pytest.mark.parametrize("kind, entries", [
    ("zip", {"ollama.exe": b"x", "../escape.dll": b"x"}),
    ("zip", {"ollama.exe": b"x", "/abs/escape.dll": b"x"}),
    ("tgz", {"ollama": b"x", "../escape.so": b"x"}),
])
def test_fetch_refuses_entries_outside_the_target(served, tmp_path, kind, entries):
    fo = _fetch_mod()
    root, url = served
    name = "ollama-windows-amd64.zip" if kind == "zip" else "ollama-darwin.tgz"
    digest = (_zip if kind == "zip" else _tgz)(root / name, entries)
    plat = "windows" if kind == "zip" else "macos"
    lock = _lock(tmp_path, url, **{plat: {"name": name, "sha256": digest,
                                          "binary": "ollama.exe" if kind == "zip" else "ollama",
                                          "exclude": []}})
    with pytest.raises(fo.FetchError, match="outside the target"):
        fo.fetch(plat, tmp_path / "out", lock)
    assert not (tmp_path / "escape.dll").exists() and not (tmp_path / "escape.so").exists()


def test_fetch_requires_the_binary(served, tmp_path):
    fo = _fetch_mod()
    root, url = served
    digest = _zip(root / "ollama-windows-amd64.zip", {"bin/ollama.exe": b"x"})
    lock = _lock(tmp_path, url, windows={"name": "ollama-windows-amd64.zip", "sha256": digest,
                                         "binary": "ollama.exe", "exclude": []})
    with pytest.raises(fo.FetchError, match="did not contain ollama.exe"):
        fo.fetch("windows", tmp_path / "out", lock)


def test_the_builds_use_the_verified_ollama_and_sign_only_our_files():
    sh = (PACKAGING / "macos" / "build_pkg.sh").read_text()
    assert "OLLAMA_DIR" in sh and "OLLAMA_TGZ" not in sh
    sign = sh[sh.index('if [ -n "${MAC_APP_IDENTITY:-}" ]'):]
    assert 'find "$BASE/bin"' in sign and 'find "$BASE" ' not in sign   # not Ollama's binaries
    assert "NOTARY_KEYCHAIN" in sh
    ps1 = (PACKAGING / "windows" / "build_msi.ps1").read_text()
    assert "[string]$OllamaDir" in ps1 and "OllamaZip" not in ps1
    assert 'Sign-File "$Dist\\votal-device-agent.exe"' in ps1 and "Sign-File $Msi" in ps1


def test_the_model_store_is_not_the_ollama_binary_folder():
    from votal_device_agent.platform import paths
    for os_name in ("macos", "windows", "other"):
        p = paths(os_name)
        assert p.ollama_models != p.install_dir / "ollama", os_name


def test_the_release_workflow():
    import yaml
    path = Path(ROOT) / ".github" / "workflows" / "device-agent-release.yml"
    text = path.read_text()
    wf = yaml.safe_load(text)
    on = wf.get("on") or wf.get(True)
    assert on["push"]["tags"] == ["device-agent-v*"]
    assert wf["permissions"] == {"contents": "write"}
    assert set(wf["jobs"]) == {"version", "macos", "windows", "release"}
    assert "does not match _version.py" in text                        # a wrong tag fails
    assert text.count("fetch_ollama.py") == 2                           # both platforms, pinned
    for secret in ("APPLE_APP_CERT_P12", "APPLE_INSTALLER_CERT_P12", "APPLE_CERT_PASSWORD",
                   "NOTARY_KEY_ID", "NOTARY_ISSUER", "NOTARY_KEY_P8", "WINDOWS_SIGN_CERT_PFX",
                   "WINDOWS_SIGN_PASSWORD"):
        assert f"secrets.{secret}" in text, secret
    assert "UNSIGNED PRE-RELEASE" in text and "--prerelease" in text
    assert "sha256sum -- *.pkg *.msi > SHA256SUMS" in text
    # The kits download exactly these names from exactly this tag.
    assert "device-agent-v${VERSION}" in (Path(ROOT) / "core" / "dlp" / "kit_templates" / "macos"
                                          / "get-installer.sh.tmpl").read_text()
    if shutil.which("actionlint"):
        out = subprocess.run(["actionlint", str(path)], capture_output=True, text=True)
        assert out.returncode == 0, out.stdout
