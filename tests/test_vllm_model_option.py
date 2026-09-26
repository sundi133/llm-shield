"""Serving an alternate guardrail model (e.g. nvidia/Nemotron-3.5-Content-Safety)
as an env-only option, with the votal-ai/vai35 defaults byte-identical.

Covers the two switch points:
- core.llm_backend: VLLM_NOTHINK_SUFFIX gates the Qwen-only
  "/no_think /set nothink" system-message suffix on the vLLM path.
- scripts/start_vllm.sh: model-dependent flags (fp8 quantization, kv-cache
  dtype, language-model-only, performance-mode, served-model-name) are
  env-overridable; VLLM_DRY_RUN=true prints the resolved args and exits.
"""

import os
import pathlib
import subprocess

import pytest

from core import llm_backend

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "start_vllm.sh"

SCHEMA = {"type": "object", "properties": {"violates_policy": {"type": "boolean"}}}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in (
        "LLM_BACKEND_TYPE",
        "ENABLE_LITELLM",
        "LLM_BACKEND_URL",
        "LLM_MODEL_NAME",
        "VLLM_NOTHINK_SUFFIX",
        "OLLAMA_THINK",
    ):
        monkeypatch.delenv(k, raising=False)


def _messages():
    return [
        {"role": "system", "content": "You are a guardrail classifier."},
        {"role": "user", "content": "evaluate this"},
    ]


# --- VLLM_NOTHINK_SUFFIX (payload path) --------------------------------------


def test_default_vllm_payload_keeps_qwen_suffix():
    p = llm_backend._build_payload(_messages(), 10, 0, None)
    assert "/no_think" in p["messages"][0]["content"]
    assert "/set nothink" in p["messages"][0]["content"]
    assert p["chat_template_kwargs"] == {"enable_thinking": False}


def test_nothink_suffix_disabled_leaves_prompts_untouched(monkeypatch):
    monkeypatch.setenv("VLLM_NOTHINK_SUFFIX", "false")
    msgs = _messages()
    p = llm_backend._build_payload(msgs, 10, 0, None)
    assert p["messages"][0]["content"] == "You are a guardrail classifier."
    assert "/no_think" not in p["messages"][0]["content"]
    # Everything else on the vLLM path is unchanged by the flag.
    assert p["chat_template_kwargs"] == {"enable_thinking": False}
    assert "model" not in p


def test_nothink_suffix_disabled_keeps_response_format(monkeypatch):
    monkeypatch.setenv("VLLM_NOTHINK_SUFFIX", "false")
    p = llm_backend._build_payload(_messages(), 10, 0, SCHEMA)
    assert p["response_format"]["type"] == "json_schema"
    assert p["response_format"]["json_schema"]["schema"] == SCHEMA


@pytest.mark.parametrize("value", ["true", "1", "yes", "", "bogus"])
def test_nothink_suffix_stays_on_unless_explicitly_false(monkeypatch, value):
    monkeypatch.setenv("VLLM_NOTHINK_SUFFIX", value)
    p = llm_backend._build_payload(_messages(), 10, 0, None)
    assert "/no_think" in p["messages"][0]["content"]


def test_ollama_path_ignores_nothink_flag(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")
    monkeypatch.setenv("VLLM_NOTHINK_SUFFIX", "false")
    p = llm_backend._build_payload(_messages(), 10, 0, None)
    # Native Ollama payload: never had the suffix, still doesn't.
    assert p["model"] == "gemma4:31b"
    assert "/no_think" not in p["messages"][0]["content"]
    assert "chat_template_kwargs" not in p


# --- start_vllm.sh flag resolution (VLLM_DRY_RUN) -----------------------------


def _resolved_args(extra_env):
    env = os.environ.copy()
    for k in (
        "SKIP_VLLM",
        "VLLM_QUANTIZATION",
        "VLLM_KV_CACHE_DTYPE",
        "VLLM_LANGUAGE_MODEL_ONLY",
        "VLLM_PERFORMANCE_MODE",
        "VLLM_DTYPE",
        "SERVED_MODEL_NAME",
        "SHIELD_GUARDRAIL_FAMILY",
        "SHIELD_ALLOW_FAMILY_MISMATCH",
    ):
        env.pop(k, None)
    env.update(
        {
            "VLLM_DRY_RUN": "true",
            "MODEL_NAME": "votal-ai/vai35-4B-v2",
            "VLLM_HOST": "0.0.0.0",
            "VLLM_PORT": "8000",
        }
    )
    env.update(extra_env)
    out = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    lines = [l for l in out.stdout.splitlines() if l.startswith("DRY_RUN_ARGS: ")]
    assert len(lines) == 1, out.stdout
    return lines[0].removeprefix("DRY_RUN_ARGS: ")


def test_default_launch_args_match_historical_votal_flags():
    args = _resolved_args({})
    assert "--model votal-ai/vai35-4B-v2" in args
    assert "--dtype bfloat16" in args
    assert "--quantization fp8" in args
    assert "--kv-cache-dtype fp8" in args
    assert "--language-model-only" in args
    assert "--performance-mode throughput" in args
    assert "--enable-prefix-caching" in args
    assert "--served-model-name" not in args


def test_nemotron_env_overrides_omit_qwen_era_flags():
    args = _resolved_args(
        {
            "MODEL_NAME": "nvidia/Nemotron-3.5-Content-Safety",
            # Serving Nemotron under the vai family is refused at boot — the
            # family selects the verdict parser, and the wrong one passes
            # everything. See the guard in scripts/start_vllm.sh.
            "SHIELD_GUARDRAIL_FAMILY": "nemo",
            "VLLM_QUANTIZATION": "none",
            "VLLM_KV_CACHE_DTYPE": "none",
            "VLLM_PERFORMANCE_MODE": "none",
        }
    )
    assert "--model nvidia/Nemotron-3.5-Content-Safety" in args
    assert "--quantization" not in args
    assert "--kv-cache-dtype" not in args
    assert "--performance-mode" not in args
    # Text-only serving stays on by default (skips the vision tower).
    assert "--language-model-only" in args


def test_language_model_only_can_be_disabled():
    args = _resolved_args({"VLLM_LANGUAGE_MODEL_ONLY": "false"})
    assert "--language-model-only" not in args


def test_served_model_name_is_optional_alias():
    args = _resolved_args({"SERVED_MODEL_NAME": "nemotron_moderator"})
    assert "--served-model-name nemotron_moderator" in args
