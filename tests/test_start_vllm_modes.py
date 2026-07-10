"""Integration test for scripts/start_vllm.sh guard-model modes.

Drives the REAL start_vllm.sh with a stubbed `vllm` module (records launch
argv, serves /v1/models so the readiness probe passes) and a stub handler.py
that dumps the client env the script exported. Asserts each mode
(votal | nemotron | both) serves the right model(s) on the right port(s) and
hands the client the right NEMOTRON_BACKEND_URL / NEMOTRON_MODEL_NAME.

No GPU / real weights needed. Skipped if bash or curl is unavailable.
"""

import os
import shutil
import signal
import socket
import subprocess
import textwrap
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "start_vllm.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("curl") is None,
    reason="needs bash + curl",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_harness(tmp_path: Path):
    """Create the stub vllm package + env-dumping handler.py; return (pkg_dir, run_dir)."""
    pkg = tmp_path / "fakevllm"
    api = pkg / "vllm" / "entrypoints" / "openai"
    api.mkdir(parents=True)
    for p in (pkg / "vllm", pkg / "vllm" / "entrypoints", api):
        (p / "__init__.py").write_text("")
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    (api / "api_server.py").write_text(textwrap.dedent(f"""
        import sys, json
        from http.server import BaseHTTPRequestHandler, HTTPServer
        argv = sys.argv[1:]
        def opt(n): return argv[argv.index(n)+1] if n in argv else ""
        port = int(opt("--port") or "8000")
        open(r"{launch_dir}" + "/" + str(port) + ".args", "w").write(" ".join(argv))
        model, served = opt("--model"), opt("--served-model-name")
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                b = json.dumps({{"data":[{{"id": served or model}}]}}).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)
            def log_message(self, *a): pass
        HTTPServer(("127.0.0.1", port), H).serve_forever()
    """))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "handler.py").write_text(textwrap.dedent("""
        import os, sys
        print("HANDOFF_URL=" + os.environ.get("NEMOTRON_BACKEND_URL", ""), flush=True)
        print("HANDOFF_MODEL=" + os.environ.get("NEMOTRON_MODEL_NAME", ""), flush=True)
        sys.stdout.flush()
    """))
    return pkg, launch_dir, run_dir


def _run(mode, tmp_path, votal_port, nemo_port):
    """Run start_vllm.sh in its own process group; read stdout until the app
    handoff, then kill the group (the backgrounded stub servers would otherwise
    hold the pipe open forever, since `exec handler.py` drops the cleanup trap)."""
    pkg, launch_dir, run_dir = _make_harness(tmp_path)
    env = dict(os.environ)
    env.update(
        SHIELD_GUARD_MODEL_MODE=mode,
        VOTAL_MODEL_NAME="votal-ai/vai35-4B-v2",
        NEMOTRON_MODEL="nvidia/Nemotron-3.5-Content-Safety",
        NEMOTRON_SERVED_NAME="nemotron_moderator",
        VLLM_HOST="127.0.0.1",
        VLLM_PORT=str(votal_port),
        NEMOTRON_VLLM_PORT=str(nemo_port),
        PYTHONPATH=str(pkg),
    )
    proc = subprocess.Popen(
        ["bash", str(SCRIPT)], cwd=str(run_dir), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    pgid = os.getpgid(proc.pid)
    lines, deadline = [], time.time() + 40
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            if "HANDOFF_MODEL=" in line:
                break
    finally:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    out = "".join(lines)
    launched = {int(f.stem): f.read_text() for f in launch_dir.glob("*.args")}
    return out, launched


def _handoff(out):
    """Parse the HANDOFF_URL / HANDOFF_MODEL lines into a dict."""
    d = {}
    for line in out.splitlines():
        if line.startswith("HANDOFF_URL="):
            d["url"] = line[len("HANDOFF_URL="):]
        elif line.startswith("HANDOFF_MODEL="):
            d["model"] = line[len("HANDOFF_MODEL="):]
    return d


def test_votal_mode_serves_only_votal(tmp_path):
    vp, npt = _free_port(), _free_port()
    out, launched = _run("votal", tmp_path, vp, npt)
    assert set(launched) == {vp}
    assert "--model votal-ai/vai35-4B-v2" in launched[vp]
    h = _handoff(out)
    assert h.get("url") == ""     # nemotron not served -> nothing exported
    assert h.get("model") == ""


def test_nemotron_mode_serves_nemotron_and_exports(tmp_path):
    vp, npt = _free_port(), _free_port()
    out, launched = _run("nemotron", tmp_path, vp, npt)
    assert set(launched) == {vp}
    assert "--model nvidia/Nemotron-3.5-Content-Safety" in launched[vp]
    assert "--served-model-name nemotron_moderator" in launched[vp]
    h = _handoff(out)
    assert h["url"] == f"http://127.0.0.1:{vp}"
    assert h["model"] == "nemotron_moderator"


def test_both_mode_serves_two_instances(tmp_path):
    vp, npt = _free_port(), _free_port()
    out, launched = _run("both", tmp_path, vp, npt)
    assert set(launched) == {vp, npt}
    assert "--model votal-ai/vai35-4B-v2" in launched[vp]
    assert "--model nvidia/Nemotron-3.5-Content-Safety" in launched[npt]
    assert "--served-model-name nemotron_moderator" in launched[npt]
    # Client is pointed at the SECONDARY (nemotron) instance for the merge.
    h = _handoff(out)
    assert h["url"] == f"http://127.0.0.1:{npt}"
    assert h["model"] == "nemotron_moderator"


def test_invalid_mode_exits_nonzero(tmp_path):
    pkg, _, run_dir = _make_harness(tmp_path)
    env = dict(os.environ)
    env.update(SHIELD_GUARD_MODEL_MODE="bogus", PYTHONPATH=str(pkg),
               VLLM_PORT=str(_free_port()))
    proc = subprocess.run(["bash", str(SCRIPT)], cwd=str(run_dir), env=env,
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode != 0
    assert "must be 'votal', 'nemotron', or 'both'" in proc.stdout + proc.stderr
