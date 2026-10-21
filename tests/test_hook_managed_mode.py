"""The hook script's managed mode (docs/specs/hooks-plugin-production.md, task 1).

A managed install puts a root-owned hook.conf at the OS path. When it exists it
wins over --config, it is refused unless root owns it and its folder and no one
else can write them, and a localhost SHIELD_URL is refused: a local stand-in
answering {} would allow everything. Shield is told the mode, version and OS.

Tests cannot create root-owned files, so each runs a copy of the script whose
managed path is under tmp_path and whose managed owner is the current user.
"""

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "core", "runtime_policy", "hook_scripts", "claude_code_hook.sh")
CALL = {"session_id": "s-1", "cwd": "/tmp", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "ls"}}

SHELLS = [s for s in ("/bin/sh", shutil.which("dash")) if s and os.path.exists(s)]
_SHELL = ["/bin/sh"]

pytestmark = pytest.mark.skipif(not shutil.which("curl") or not SHELLS or os.name == "nt",
                                reason="needs sh and curl")


@pytest.fixture(autouse=True, params=SHELLS or ["/bin/sh"])
def _each_shell(request):
    _SHELL[0] = request.param


@pytest.fixture
def shield():
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            seen.append({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.send_header("content-length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def _copy(tmp_path, uid):
    """(script copy, managed conf path): the managed path under tmp_path, the
    managed owner ``uid``. The conf is not created."""
    folder = tmp_path / "managed"
    folder.mkdir(exist_ok=True)
    os.chmod(folder, 0o755)
    conf = folder / "hook.conf"
    src = open(HOOK).read()
    for old in ('MANAGED_UID=0', 'MANAGED_CONF_DARWIN="/Library/Application Support/Votal/hook.conf"',
                'MANAGED_CONF_OTHER="/etc/votal/hook.conf"'):
        assert src.count(old) == 1, old
    src = (src.replace("MANAGED_UID=0", f"MANAGED_UID={uid}")
              .replace('"/Library/Application Support/Votal/hook.conf"', f'"{conf}"')
              .replace('"/etc/votal/hook.conf"', f'"{conf}"'))
    script = tmp_path / f"hook-{uid}.sh"
    script.write_text(src)
    return str(script), conf


@pytest.fixture
def managed(tmp_path):
    """The current user plays root."""
    return _copy(tmp_path, os.getuid())


def _write(path, text, mode=0o644):
    path.write_text(text)
    os.chmod(path, mode)
    return str(path)


def _run(script, args, home):
    env = {"PATH": os.environ["PATH"], "USER": "dev", "HOME": str(home),
           "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
    return subprocess.run([_SHELL[0], script] + args, input=json.dumps(CALL).encode(),
                          capture_output=True, env=env, timeout=30)


def test_https_managed_conf_wins_over_config(managed, tmp_path, shield):
    """The managed file is read even though --config names another. It points
    at a localhost Shield, which managed mode refuses: proof it was read."""
    script, conf = managed
    url, _ = shield
    _write(conf, f"SHIELD_URL={url}\nSHIELD_API_KEY=k\n")
    other = _write(tmp_path / "other.conf", "SHIELD_URL=https://elsewhere.example\nSHIELD_API_KEY=k\n",
                   mode=0o600)
    r = _run(script, ["--config", other], tmp_path)
    assert r.returncode == 2 and b"must be https in a managed install" in r.stderr, r.stderr


@pytest.mark.parametrize("file_mode, dir_mode", [(0o664, 0o755), (0o646, 0o755),
                                                (0o644, 0o775), (0o644, 0o757)])
def test_a_writable_managed_conf_refuses_every_call(managed, tmp_path, file_mode, dir_mode):
    script, conf = managed
    _write(conf, "SHIELD_URL=https://shield.example\nSHIELD_API_KEY=k\n", mode=file_mode)
    os.chmod(conf.parent, dir_mode)
    r = _run(script, [], tmp_path)
    assert r.returncode == 2 and b"must be owned by root and writable by no one else" in r.stderr


def test_a_managed_conf_owned_by_someone_else_refuses(tmp_path):
    """The managed owner stays root (0); the user owns the file: refused."""
    if os.getuid() == 0:
        pytest.skip("running as root: every file is root-owned")
    script, conf = _copy(tmp_path, 0)
    _write(conf, "SHIELD_URL=https://shield.example\nSHIELD_API_KEY=k\n")
    r = _run(script, [], tmp_path)
    assert r.returncode == 2 and b"must be owned by root" in r.stderr


def test_managed_mode_is_reported_with_version_and_os(managed, tmp_path, shield):
    """A --config file that passes the owner check runs managed (the device
    agent's own path), and Shield is told so."""
    script, _ = managed
    url, seen = shield
    folder = tmp_path / "agent"
    folder.mkdir()
    os.chmod(folder, 0o755)
    secret = _write(folder / "secret", "s" * 40, mode=0o644)
    conf = _write(folder / "hook.conf", f"SHIELD_URL={url}\nSHIELD_LOCAL_SECRET_FILE={secret}\n")
    r = _run(script, ["--config", conf], tmp_path)
    assert r.returncode == 0, r.stderr
    h = seen[-1]
    assert h["x-votal-hook-mode"] == "managed" and h["x-votal-hook-version"] == "1.2.0"
    assert h["x-votal-hook-os"] in ("darwin", "linux")


def test_self_install_reads_home_and_runs_as_user(tmp_path, shield):
    """No managed conf, no --config: ~/.votal/hook.conf, owned by the user, not
    root, so user mode, where a localhost Shield is allowed for testing."""
    if os.getuid() == 0:
        pytest.skip("running as root: every file is root-owned")
    script, _ = _copy(tmp_path, 0)
    url, seen = shield
    home = tmp_path / "home"
    (home / ".votal").mkdir(parents=True)
    _write(home / ".votal" / "hook.conf", f"SHIELD_URL={url}\nSHIELD_API_KEY=k\n", mode=0o600)
    os.chmod(home / ".votal", 0o700)
    r = _run(script, [], home)
    assert r.returncode == 0, r.stderr
    assert seen[-1]["x-votal-hook-mode"] == "user"


def test_self_install_with_a_group_writable_folder_is_user_mode(managed, tmp_path, shield):
    """Owned by the (patched) managed owner but in a folder others can write:
    not managed, so localhost is still allowed and the mode is user."""
    script, _ = managed
    url, seen = shield
    folder = tmp_path / "shared"
    folder.mkdir()
    os.chmod(folder, 0o777)
    conf = _write(folder / "hook.conf", f"SHIELD_URL={url}\nSHIELD_API_KEY=k\n")
    r = _run(script, ["--config", conf], tmp_path)
    assert r.returncode == 0 and seen[-1]["x-votal-hook-mode"] == "user"


def test_the_plugin_copy_and_device_agent_copy_carry_managed_mode():
    """Regenerate with packages/votal-device-agent/packaging/sync_hook_scripts.py."""
    plugin = os.path.join(ROOT, "examples", "agent-hooks", "plugin", "votal-shield-hooks",
                          "scripts", "claude_code_hook.sh")
    assert open(plugin).read() == open(HOOK).read()
    assert "managed_ok" in open(HOOK).read()


def test_one_version_for_the_scripts_and_the_plugin():
    """Shield records the version each laptop runs; it must name a release."""
    import re
    plugin_dir = os.path.join(ROOT, "examples", "agent-hooks", "plugin")
    manifest = json.load(open(os.path.join(plugin_dir, "votal-shield-hooks", ".claude-plugin",
                                           "plugin.json")))
    market = json.load(open(os.path.join(plugin_dir, ".claude-plugin", "marketplace.json")))
    sh = re.search(r"^HOOK_VERSION=(\S+)", open(HOOK).read(), re.M).group(1)
    ps1 = re.search(r"^\$HookVersion = '([^']+)'",
                    open(HOOK.replace(".sh", ".ps1"), encoding="utf-8").read(), re.M).group(1)
    assert sh == ps1 == manifest["version"] == market["plugins"][0]["version"]
