import subprocess
import requests
import time
from typing import Optional

import httpx

import config.schema as _config_module

_DEFAULT_LLAMA_URL = "http://127.0.0.1:8000"
_DEFAULT_MEDIUM_URL = "http://127.0.0.1:8001"
_DEFAULT_MODEL_PATH = "/models/Qwen3-8B-Q4_K_M.gguf"
_DEFAULT_MEDIUM_MODEL_PATH = "/models/Qwen3-1.7B-Q4_K_M.gguf"
_DEFAULT_DRAFT_MODEL_PATH = "/models/Qwen3-0.6B-Q4_K_M.gguf"


def _get_llama_url() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("url", _DEFAULT_LLAMA_URL)
    return _DEFAULT_LLAMA_URL


def _get_medium_url() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("medium_url", _DEFAULT_MEDIUM_URL)
    return _DEFAULT_MEDIUM_URL


def _get_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("model_path", _DEFAULT_MODEL_PATH)
    return _DEFAULT_MODEL_PATH


def _get_medium_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get(
            "medium_model_path", _DEFAULT_MEDIUM_MODEL_PATH
        )
    return _DEFAULT_MEDIUM_MODEL_PATH


def _get_draft_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get(
            "draft_model_path", _DEFAULT_DRAFT_MODEL_PATH
        )
    return _DEFAULT_DRAFT_MODEL_PATH


def _wait_for_server(url: str, label: str, max_attempts: int = 60):
    """Wait for a llama-server to become healthy."""
    for i in range(max_attempts):
        try:
            r = requests.get(f"{url}/health", timeout=2)
            if r.json().get("status") == "ok":
                print(f"{label} ready!")
                return
        except Exception:
            pass
        time.sleep(2)
        print(f"Waiting for {label}... {i + 1}/{max_attempts}")
    raise RuntimeError(f"{label} failed to start")


def start_server():
    """Start both llama-server instances and wait for them to become healthy.

    - Port 8000: Qwen3-8B (slow tier — adversarial detection)
    - Port 8001: Qwen3-1.7B (medium tier — topic, safety, toxicity)
    """
    llama_url = _get_llama_url()
    medium_url = _get_medium_url()
    model_path = _get_model_path()
    medium_model_path = _get_medium_model_path()
    draft_model_path = _get_draft_model_path()

    # Start 8B server (slow tier) — port 8000
    subprocess.Popen(
        [
            "/app/llama-server",
            "-m",
            model_path,
            "-md",
            draft_model_path,
            "-ngl",
            "99",
            "-ngld",
            "99",
            "-c",
            "16384",
            "--flash-attn",
            "auto",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "-np",
            "4",
            "--draft-max",
            "32",
            "--cache-type-k",
            "q4_0",
            "--cache-type-v",
            "q4_0",
            "--log-disable",
        ]
    )

    # Start 1.7B server (medium tier) — port 8001
    subprocess.Popen(
        [
            "/app/llama-server",
            "-m",
            medium_model_path,
            "-ngl",
            "99",
            "-c",
            "16384",
            "--flash-attn",
            "auto",
            "--host",
            "0.0.0.0",
            "--port",
            "8001",
            "-np",
            "8",
            "--cache-type-k",
            "q4_0",
            "--cache-type-v",
            "q4_0",
            "--log-disable",
        ]
    )

    # Wait for both servers
    _wait_for_server(llama_url, "llama-server-8B")
    _wait_for_server(medium_url, "llama-server-1.7B")


def _ensure_no_think(messages: list) -> list:
    """Append /no_think to the system message to disable Qwen3 thinking mode.

    This prevents thinking tokens from corrupting structured JSON output.
    """
    messages = [dict(m) for m in messages]  # shallow copy
    for m in messages:
        if m.get("role") == "system" and "/no_think" not in m.get("content", ""):
            m["content"] = m["content"].rstrip() + " /no_think"
            break
    return messages


def _build_payload(
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Build the request payload for llama-server."""
    messages = _ensure_no_think(messages)
    payload = {
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if response_format:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "response",
                "strict": True,
                "schema": response_format,
            },
        }
    return payload


def llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
) -> dict:
    """Synchronous LLM call to the 8B llama-server."""
    llama_url = _get_llama_url()
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    res = requests.post(
        f"{llama_url}/v1/chat/completions",
        json=payload,
        timeout=300,
    )
    return res.json()


async def async_llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
) -> dict:
    """Async LLM call to the 8B llama-server (slow tier)."""
    llama_url = _get_llama_url()
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    async with httpx.AsyncClient(timeout=300) as client:
        res = await client.post(
            f"{llama_url}/v1/chat/completions",
            json=payload,
        )
        return res.json()


async def async_llm_call_medium(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
) -> dict:
    """Async LLM call to the 1.7B llama-server (medium tier)."""
    medium_url = _get_medium_url()
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    async with httpx.AsyncClient(timeout=300) as client:
        res = await client.post(
            f"{medium_url}/v1/chat/completions",
            json=payload,
        )
        return res.json()
