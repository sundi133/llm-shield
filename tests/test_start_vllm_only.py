"""scripts/start_vllm.sh VLLM_ONLY=true (docs/specs/onprem-release-bundle.md, task 2b).

The split OpenShift topology runs the model in its own GPU pod and the guard
API in CPU pods. The model pod uses the same image and script as RunPod, with
VLLM_ONLY=true: vLLM starts with exactly the flags the script always builds,
and handler.py never starts. vLLM is exec'd, so it is the container's main
process: it receives the pod's SIGTERM and its exit code is the pod's.
"""

import os
import pathlib
import stat
import subprocess

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "start_vllm.sh"

_ENV_KEYS = ("SKIP_VLLM", "VLLM_ONLY", "VLLM_DRY_RUN", "LLM_BACKEND_TYPE", "LLM_BACKEND_URL",
             "SERVED_MODEL_NAME", "VLLM_QUANTIZATION", "VLLM_KV_CACHE_DTYPE")


def _stub_python(tmp_path, exit_code=0):
    """A python3 that records its arguments and exits with ``exit_code``."""
    log = tmp_path / "python3.log"
    stub = tmp_path / "python3"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit {exit_code}\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return log


def _run(tmp_path, **env):
    base = {k: v for k, v in os.environ.items() if k not in _ENV_KEYS}
    base.update(MODEL_NAME="votal-ai/vai35-4B-v2", VLLM_HOST="0.0.0.0", VLLM_PORT="8000",
                PATH=f"{tmp_path}:{os.environ['PATH']}")
    base.update(env)
    return subprocess.run(["bash", str(SCRIPT)], env=base, capture_output=True, text=True,
                          timeout=30, cwd=tmp_path)


def _dry_run_args(tmp_path, **env):
    out = _run(tmp_path, VLLM_DRY_RUN="true", **env).stdout
    line = next(l for l in out.splitlines() if l.startswith("DRY_RUN_ARGS: "))
    return line[len("DRY_RUN_ARGS: "):]


def test_vllm_only_execs_vllm_with_the_scripts_flags_and_no_guard_api(tmp_path):
    log = _stub_python(tmp_path)
    res = _run(tmp_path, VLLM_ONLY="true", SERVED_MODEL_NAME="votal-ai/vai35-4B-v2")
    assert res.returncode == 0, res.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 1, calls                          # vLLM only, no handler.py
    assert "handler.py" not in log.read_text()
    expected = _dry_run_args(tmp_path, SERVED_MODEL_NAME="votal-ai/vai35-4B-v2")
    assert calls[0] == f"-m vllm.entrypoints.openai.api_server {expected}"
    assert "--quantization fp8" in calls[0] and "--enable-prefix-caching" in calls[0]


def test_vllm_only_respects_the_same_overrides(tmp_path):
    log = _stub_python(tmp_path)
    res = _run(tmp_path, VLLM_ONLY="true", VLLM_QUANTIZATION="none", VLLM_KV_CACHE_DTYPE="none")
    assert res.returncode == 0, res.stderr
    call = log.read_text()
    assert "--quantization" not in call and "--kv-cache-dtype" not in call


@pytest.mark.parametrize("code", [1, 137])
def test_vllm_exit_code_is_the_pods(tmp_path, code):
    _stub_python(tmp_path, exit_code=code)
    assert _run(tmp_path, VLLM_ONLY="true").returncode == code


def test_skip_vllm_and_vllm_only_together_refuse_to_start(tmp_path):
    log = _stub_python(tmp_path)
    res = _run(tmp_path, VLLM_ONLY="true", SKIP_VLLM="true")
    assert res.returncode == 1
    assert "SKIP_VLLM=true and VLLM_ONLY=true" in res.stdout
    assert not log.exists()


def test_default_still_starts_the_guard_api_after_vllm(tmp_path):
    """Unset VLLM_ONLY: vLLM in the background, then exec handler.py (RunPod)."""
    log = _stub_python(tmp_path)
    curl = tmp_path / "curl"
    curl.write_text("#!/bin/sh\nexit 0\n")                 # vLLM "ready" at once
    curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
    res = _run(tmp_path)
    assert res.returncode == 0, res.stderr
    calls = log.read_text().splitlines()
    # vLLM runs in the background, so the two lines may land in either order.
    assert sorted(c.split()[0] for c in calls) == ["-m", "handler.py"], calls
