"""Backend-URL scheme validation (Pepper CWE-918, SSRF via LLM server_url).

Backend URLs are operator-set (env / config), not user input, so this is not
a user-driven SSRF sink -- validating the scheme is defence-in-depth so a typo
or a stray file://, gopher://, etc. can't become an unexpected request target.
Host is intentionally NOT restricted: a self-hosted vLLM backend legitimately
lives on localhost / a private address.
"""

import pytest

from core import llm_backend


def test_env_backend_url_accepts_http_and_https(monkeypatch):
    for url in ("http://127.0.0.1:8000", "https://vllm.example.com/v1"):
        monkeypatch.setenv("LLM_BACKEND_URL", url)
        assert llm_backend._get_env_backend_url() is not None


def test_env_backend_url_rejects_non_http_scheme(monkeypatch):
    for bad in ("file:///etc/passwd", "gopher://x/", "ftp://host/f"):
        monkeypatch.setenv("LLM_BACKEND_URL", bad)
        with pytest.raises(RuntimeError, match="http"):
            llm_backend._get_env_backend_url()


def test_env_backend_url_unset_is_none(monkeypatch):
    monkeypatch.delenv("LLM_BACKEND_URL", raising=False)
    assert llm_backend._get_env_backend_url() is None


def test_localhost_backend_allowed(monkeypatch):
    """Host is NOT restricted -- only the scheme is enforced."""
    monkeypatch.setenv("LLM_BACKEND_URL", "http://localhost:8000")
    assert llm_backend._get_env_backend_url() == "http://localhost:8000"


def test_assert_http_url_helper():
    assert llm_backend._assert_http_url("https://x.io", "src") == "https://x.io"
    with pytest.raises(RuntimeError, match="src"):
        llm_backend._assert_http_url("file:///x", "src")


def test_validate_config_rejects_bad_votal_url(monkeypatch):
    """A bad LLM_BACKEND_URL scheme fails at boot (validate_guard_model_config),
    not per-request on the guard path."""
    monkeypatch.delenv("SHIELD_GUARD_MODEL_MODE", raising=False)
    monkeypatch.setenv("LLM_BACKEND_URL", "file:///etc/passwd")
    with pytest.raises(RuntimeError, match="http"):
        llm_backend.validate_guard_model_config()
