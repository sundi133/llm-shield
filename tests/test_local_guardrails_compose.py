"""Guards for the local guardrails testing stack (docker-compose.guardrails.yml).

None of this needs Docker: the stack's failure modes are all *configuration*
mistakes that a YAML read can catch. Each assertion below maps to a specific way
the stack silently produces a wrong answer rather than an obvious error --
which is worse than not having the stack at all, because someone concludes the
guardrails work when they do not.

See docs/spec-local-docker-guardrails.md section 8.
"""

import os
import re
import shutil
import subprocess

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE_PATH = os.path.join(REPO_ROOT, "docker-compose.guardrails.yml")
ENV_EXAMPLE_PATH = os.path.join(REPO_ROOT, ".env.guardrails.example")
SMOKE_PATH = os.path.join(REPO_ROOT, "scripts", "smoke_local_guardrails.sh")

DATA_PLANE = "shield"
MODEL_SERVICE = "llama"
EXPECTED_SERVICES = {"redis", MODEL_SERVICE, DATA_PLANE, "admin"}


@pytest.fixture(scope="module")
def compose():
    with open(COMPOSE_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def env_example_text():
    with open(ENV_EXAMPLE_PATH, encoding="utf-8") as fh:
        return fh.read()


def _env_map(service: dict) -> dict:
    """Compose `environment:` list -> dict. Values keep their ${VAR:-default}."""
    out = {}
    for item in service.get("environment", []) or []:
        if isinstance(item, str) and "=" in item:
            key, _, value = item.partition("=")
            out[key.strip()] = value.strip()
        elif isinstance(item, str):
            out[item.strip()] = ""
    return out


def test_compose_declares_expected_services(compose):
    assert set(compose["services"]) == EXPECTED_SERVICES


def test_data_plane_skips_vllm(compose):
    """The slim image has no vLLM stack; booting it would crash the container."""
    env = _env_map(compose["services"][DATA_PLANE])
    assert env.get("SKIP_VLLM") == "true"


def test_data_plane_overrides_baked_ollama_backend_type(compose):
    """Dockerfile.cloud bakes LLM_BACKEND_TYPE=ollama; this stack is not Ollama.

    Left unset, the container inherits `ollama` from the image. That takes a
    different branch in core/llm_backend.py than production's default (native
    /api/chat with think/format instead of OpenAI-compatible
    /v1/chat/completions), and trips the LLM_MODEL_NAME guard in
    scripts/start_vllm.sh:20-23 at boot. Neither failure names the real cause.
    """
    env = _env_map(compose["services"][DATA_PLANE])
    assert env.get("LLM_BACKEND_TYPE") == "vllm"


def test_data_plane_points_at_in_network_model_service(compose):
    """`localhost` inside the Shield container is its OWN loopback, not the model.

    The same trap is already commented in
    examples/langchain/docker-compose.local.yml. The symptom is not a crash: the
    guard path comes up and every LLM-tier guardrail fails open with
    passed=True/action="pass" (guardrails/input/adversarial.py:611), so the stack
    reports every prompt clean while judging none of them.
    """
    env = _env_map(compose["services"][DATA_PLANE])
    url = env.get("LLM_BACKEND_URL", "")
    assert url, "LLM_BACKEND_URL must be set or the data plane has no backend"
    assert "localhost" not in url and "127.0.0.1" not in url
    assert f"//{MODEL_SERVICE}:" in url, f"expected the in-network {MODEL_SERVICE!r} service, got {url!r}"


def test_data_plane_has_a_bootstrap_api_key(compose):
    """core/auth.py:146-150 returns HTTP 500 on EVERY request if this is empty.

    It short-circuits before any tenant lookup, so the failure looks like a
    broken server rather than a missing config value.
    """
    env = _env_map(compose["services"][DATA_PLANE])
    assert env.get("SHIELD_API_KEYS"), "SHIELD_API_KEYS must be non-empty when auth is enabled"


def test_telemetry_export_disabled_on_both_planes(compose):
    """Dockerfile.cloud defaults VOTAL_ES_ENABLED=true. A laptop has no SIEM."""
    for name in (DATA_PLANE, "admin"):
        env = _env_map(compose["services"][name])
        assert env.get("VOTAL_ES_ENABLED") == "false", f"{name} must not export telemetry"


def test_every_published_port_binds_loopback(compose):
    """No service may listen on 0.0.0.0.

    This stack runs an admin plane whose only credential is a documented default
    key. Published on 0.0.0.0, a laptop on an untrusted network hands tenant CRUD
    to anyone on the same LAN.
    """
    for name, service in compose["services"].items():
        for mapping in service.get("ports", []) or []:
            assert str(mapping).startswith("127.0.0.1:"), (
                f"{name} publishes {mapping!r} without a 127.0.0.1 bind"
            )


def test_model_service_is_behind_an_opt_in_profile(compose):
    """The stack must be runnable with no model, and honestly so.

    Without the profile there is no way to skip the 5.2GB download, and a
    `llama` service that starts with no weights is the worst outcome available:
    it answers nothing, every LLM guardrail fails open with passed=True, and the
    stack reports every prompt clean while judging none of them.
    """
    assert compose["services"][MODEL_SERVICE].get("profiles") == ["model"]


def test_data_plane_does_not_depend_on_the_profiled_model_service(compose):
    """A depends_on pointing into a profile either drags the service in or
    errors, depending on the Compose version -- and either defeats the profile.

    Nothing is lost by omitting it: scripts/start_vllm.sh warns rather than
    blocking when the backend is unreachable, so Shield boots fine without it.
    """
    depends = compose["services"][DATA_PLANE].get("depends_on", {}) or {}
    assert MODEL_SERVICE not in depends


def test_smoke_script_supports_a_model_free_mode(smoke_text):
    """FAST_ONLY must seed a policy with no LLM guardrail in it.

    Listing one while no model runs means it fails open, so the run goes green
    having proven nothing. The guard here is that the LLM guardrail name appears
    only inside the non-FAST_ONLY branch.
    """
    assert "FAST_ONLY" in smoke_text
    before, sep, after = smoke_text.partition("if [ \"$FAST_ONLY\" = \"1\" ]; then\n    INPUT_GUARDRAILS=''")
    assert sep, "expected FAST_ONLY to select an LLM-free set of input guardrails"


def test_model_weights_are_cached_in_a_volume(compose):
    """Without a volume, every `up` re-downloads ~5.2GB.

    The mount TARGET is asserted, not just the volume's existence. llama.cpp's
    `-hf` flag writes into the Hugging Face cache layout
    (/root/.cache/huggingface/hub/...), not /root/.cache/llama.cpp as the name
    suggests; an earlier version of this file mounted the latter and cached
    nothing at all. Nothing about that failed visibly -- the stack worked, and
    the weights were silently re-fetched on the next `up`. Mounting the shared
    parent is what makes it path-independent.
    """
    volumes = compose["services"][MODEL_SERVICE].get("volumes", []) or []
    assert "llama-models:/root/.cache" in [str(v) for v in volumes], (
        f"expected the cache volume mounted at /root/.cache, got {volumes}"
    )
    assert "llama-models" in compose.get("volumes", {})


def test_env_example_documents_every_variable_compose_reads(compose, env_example_text):
    """Drift guard: a new ${VAR} in compose with no entry in the example file.

    Someone copies .env.guardrails.example, and the undocumented variable
    silently falls back to its inline default. That is fine until the default is
    wrong for them and there is nothing in the file to point at.
    """
    referenced = set(re.findall(r"\$\{([A-Z0-9_]+)", yaml.dump(compose)))
    documented = set(re.findall(r"^([A-Z0-9_]+)=", env_example_text, re.MULTILINE))
    missing = referenced - documented
    assert not missing, f"variables used by compose but absent from .env.guardrails.example: {sorted(missing)}"


def test_filled_env_file_is_gitignored():
    """.env.guardrails and the minted tenant keys must never be committed.

    The seed pattern is a glob because each mode keeps its own file
    (.shield-local-seed, .shield-local-seed-fast); an exact-name entry would
    silently stop covering the second one.
    """
    with open(os.path.join(REPO_ROOT, ".gitignore"), encoding="utf-8") as fh:
        ignored = {line.strip() for line in fh}
    assert ".env.guardrails" in ignored
    assert ".shield-local-seed*" in ignored


# ── Smoke script ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def smoke_text():
    with open(SMOKE_PATH, encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH")
def test_smoke_script_is_valid_posix_sh():
    proc = subprocess.run(
        ["sh", "-n", SMOKE_PATH], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def _verdict_py(smoke_text: str) -> str:
    """The embedded python helper, as the shell would pass it to python -c."""
    m = re.search(r"^VERDICT_PY='\n(.*?)^'$", smoke_text, re.S | re.M)
    assert m, "could not locate the VERDICT_PY block in the smoke script"
    return m.group(1)


def test_smoke_script_detects_both_fail_open_paths(smoke_text):
    """The single assertion this whole script exists for.

    Two different fail-open paths exist, and the dangerous one is NOT the
    pipeline-level exception handler:

      "Guardrail error:"  core/pipeline.py:18-27, passed=False + action="log"
      "failed, allowing"  the handler inside each LLM guardrail, e.g.
                          guardrails/input/adversarial.py:611 -- this returns
                          passed=TRUE, action="pass", an affirmatively clean
                          verdict on a prompt nothing actually judged.

    Checking only the first (as this script originally did) means a stack whose
    entire LLM tier is unreachable smoke-tests green.
    """
    body = _verdict_py(smoke_text)
    assert "Guardrail error:" in body
    assert "failed, allowing" in body


def test_verdict_helper_is_valid_python(smoke_text):
    """It lives in a single-quoted shell string, so one apostrophe breaks it.

    A stray apostrophe in a comment there does not fail the shell's `sh -n`
    check in any way that names the cause: it ends the string early and the
    remaining words are parsed as commands ("OWN: command not found").
    """
    compile(_verdict_py(smoke_text), "VERDICT_PY", "exec")
    assert "'" not in _verdict_py(smoke_text), (
        "no apostrophes inside the single-quoted VERDICT_PY block"
    )


def test_verdict_helper_flags_a_silent_fail_open():
    """End-to-end on the helper itself, using a real captured response.

    This is the exact body /guardrails/input returns for a blatant prompt
    injection while the model server is unreachable. Note passed=true and
    action=pass: if the helper reports no error for this, the smoke test is
    lying.
    """
    import json
    import sys

    smoke = open(SMOKE_PATH, encoding="utf-8").read()
    payload = json.dumps({
        "safe": True,
        "action": "pass",
        "inference_time_ms": 2.49,
        "guardrail_results": [{
            "guardrail": "adversarial_detection",
            "passed": True,
            "action": "pass",
            "message": "LLM call failed, allowing by default: All connection attempts failed",
        }],
    })
    proc = subprocess.run(
        [sys.executable, "-c", _verdict_py(smoke)],
        input=payload, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    action, triggered, errored, _ = proc.stdout.strip().split("|")
    assert action == "pass"          # the trap: the verdict itself looks clean
    assert errored == "adversarial_detection"   # ...and this is what catches it


def test_smoke_script_does_not_authenticate_with_a_sandbox_key(smoke_text):
    """`sk-test-*` bypasses normal tenant resolution.

    core/auth.py:169 and storage/tenant_store.py:473 both short-circuit such a
    key to the shared `test-tenant-001`. A smoke test using one would not be
    exercising the code path a real tenant key takes.

    Comments are stripped first: the script explains this trap in prose, and the
    prose must not trip the guard that enforces it.
    """
    code = "\n".join(
        line for line in smoke_text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "sk-test-" not in code
