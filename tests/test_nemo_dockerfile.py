"""Dockerfile.nemo must not drift from Dockerfile.

The two images run the SAME application; only the dependency floor and the
serving defaults differ. Nothing enforces that by construction, so a new
top-level package added to one and not the other produces an image that boots
and then fails on an import at request time.

This is the analogue of tests/test_admin_dockerfile_imports.py, which exists
because that exact class of drift has bitten this repo before.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "Dockerfile"
NEMO = ROOT / "Dockerfile.nemo"
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

_COPY_DIR = re.compile(r"^COPY\s+([\w./-]+/)\s+[\w./-]+/\s*$", re.MULTILINE)
_COPY_FILE = re.compile(r"^COPY\s+([\w.-]+\.\w+)\s+\.\s*$", re.MULTILINE)
_ENV = re.compile(r"^ENV\s+([A-Z0-9_]+)=(.*)$", re.MULTILINE)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _copied_dirs(path: Path) -> set[str]:
    return set(_COPY_DIR.findall(_text(path)))


def _copied_files(path: Path) -> set[str]:
    return set(_COPY_FILE.findall(_text(path)))


def _env(path: Path) -> dict[str, str]:
    return dict(_ENV.findall(_text(path)))


def test_both_dockerfiles_exist():
    assert DEFAULT.is_file()
    assert NEMO.is_file()


def test_the_same_source_directories_are_copied():
    """The drift guard. Add a top-level package to one, add it to both."""
    assert _copied_dirs(NEMO) == _copied_dirs(DEFAULT)


def test_the_same_application_files_are_copied():
    """requirements-nemo.txt is the one deliberate extra."""
    extra = _copied_files(NEMO) - _copied_files(DEFAULT)
    assert extra == {"requirements-nemo.txt"}
    assert not _copied_files(DEFAULT) - _copied_files(NEMO)


def test_the_same_entrypoint_script_is_installed():
    for path in (DEFAULT, NEMO):
        assert "cp /runpod/scripts/start_vllm.sh /start-services.sh" in _text(path)
        assert 'CMD ["/start-services.sh"]' in _text(path)


# ── the five env vars the image exists to guarantee ─────────────────────


def test_nemo_image_pins_every_serving_flag_that_must_not_be_forgotten():
    """A missed VLLM_NOTHINK_SUFFIX=false injects Qwen thinking tokens into
    every Nemotron prompt. That is the whole reason this image exists."""
    env = _env(NEMO)
    assert env["MODEL_NAME"] == "nvidia/Nemotron-3.5-Content-Safety"
    assert env["VLLM_QUANTIZATION"] == "none"
    assert env["VLLM_KV_CACHE_DTYPE"] == "none"
    assert env["VLLM_PERFORMANCE_MODE"] == "none"
    assert env["VLLM_NOTHINK_SUFFIX"] == "false"


def test_the_default_image_still_serves_the_votal_model():
    """Guard against a copy-paste that repoints the default image."""
    assert _env(DEFAULT)["MODEL_NAME"] == "votal-ai/vai35-4B-v2"
    assert "VLLM_NOTHINK_SUFFIX" not in _env(DEFAULT)


def test_the_nemo_image_runs_the_nemo_family():
    """The family selects the verdict parser, so it is not optional here.
    Nemotron under the vai family fails every parse and passes everything."""
    assert _env(NEMO)["SHIELD_GUARDRAIL_FAMILY"] == "nemo"


def test_the_default_image_does_not_set_a_family():
    """Unset resolves to vai in active_family(); pinning it would make the
    default image's behaviour depend on a var nobody sets today."""
    assert "SHIELD_GUARDRAIL_FAMILY" not in _env(DEFAULT)


def test_startup_refuses_a_family_model_mismatch():
    """Boot-time failure beats a silent hole: a mismatch does not error at
    request time, it passes everything behind clean 200s."""
    script = (ROOT / "scripts" / "start_vllm.sh").read_text(encoding="utf-8")
    assert "SHIELD_ALLOW_FAMILY_MISMATCH" in script
    assert script.count("exit 1") >= 3   # ollama x2, plus the family guard


def test_the_vllm_base_is_pinned_inside_the_documented_window():
    """Nemotron documents vllm>=0.11.0,<=0.20.2. Tracking :latest would let a
    base-image bump silently move the moderator outside its supported range."""
    m = re.search(r"^ARG VLLM_BASE_IMAGE=(.+)$", _text(NEMO), re.MULTILINE)
    assert m, "Dockerfile.nemo must declare ARG VLLM_BASE_IMAGE"
    assert m.group(1).strip() != "vllm/vllm-openai:latest"
    assert "vllm/vllm-openai:v" in m.group(1)


def test_requirements_nemo_states_the_model_card_window():
    text = (ROOT / "requirements-nemo.txt").read_text(encoding="utf-8")
    assert "transformers>=4.57.1,<=4.57.6" in text
    assert "torch==2.8.0" in text


# ── CI parity ───────────────────────────────────────────────────────────


def _matrix() -> list[dict]:
    wf = yaml.safe_load(_text(BUILD_WORKFLOW))
    return wf["jobs"]["build"]["strategy"]["matrix"]["include"]


def test_the_nemo_image_is_in_the_build_matrix():
    """A Dockerfile nothing builds rots. Every other image here is published."""
    entry = next((e for e in _matrix() if e["name"] == "nemo"), None)
    assert entry is not None, "add nemo to .github/workflows/build.yml"
    assert entry["dockerfile"] == "Dockerfile.nemo"
    assert entry["image"] == "llm-shield-nemo"


def test_every_matrix_dockerfile_exists():
    for entry in _matrix():
        assert (ROOT / entry["dockerfile"]).is_file(), entry["dockerfile"]


def test_the_vllm_based_builds_free_disk_and_use_min_cache():
    """The vLLM base is ~10 GB. Without the free-disk step the runner dies on
    "No space left on device"; with mode=max the cache blows GHA's 10 GB
    per-scope limit and is evicted every run."""
    text = _text(BUILD_WORKFLOW)
    free_disk = re.search(r"if:\s*(matrix\.name.*)", text)
    assert free_disk and "nemo" in free_disk.group(1)
    cache = re.search(r"^\s*cache-to:.*$", text, re.MULTILINE)
    assert cache and "nemo" in cache.group(0)


@pytest.mark.parametrize("name", ["vllm", "nemo", "admin", "litellm", "cloud"])
def test_matrix_images_have_distinct_names(name):
    entries = [e for e in _matrix() if e["name"] == name]
    assert len(entries) == 1
    images = [e["image"] for e in _matrix()]
    assert len(images) == len(set(images))
