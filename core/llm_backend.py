import subprocess
import requests
import time
from typing import Optional

import httpx

import config.schema as _config_module

_DEFAULT_LLAMA_URL = "http://127.0.0.1:8000"
_DEFAULT_MODEL_PATH = "/models/Qwen3-8B-Q4_K_M.gguf"
_DEFAULT_DRAFT_MODEL_PATH = "/models/Qwen3-0.6B-Q4_K_M.gguf"


def _get_llama_url() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("url", _DEFAULT_LLAMA_URL)
    return _DEFAULT_LLAMA_URL


def _get_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("model_path", _DEFAULT_MODEL_PATH)
    return _DEFAULT_MODEL_PATH


def _get_draft_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("draft_model_path", _DEFAULT_DRAFT_MODEL_PATH)
    return _DEFAULT_DRAFT_MODEL_PATH


def start_server():
    """Start the llama-server subprocess and wait for it to become healthy."""
    llama_url = _get_llama_url()
    model_path = _get_model_path()
    draft_model_path = _get_draft_model_path()

    subprocess.Popen([
        "/app/llama-server",
        "-m", model_path,
        "-md", draft_model_path,
        "-ngl", "99",
        "-ngld", "99",
        "-c", "8192",
        "--flash-attn", "auto",
        "--host", "0.0.0.0",
        "--port", "8000",
        "-np", "8",
        "--draft-max", "16",
        "--cache-type-k", "q8_0",
        "--cache-type-v", "q8_0",
        "--log-disable",
    ])
    for i in range(60):
        try:
            r = requests.get(f"{llama_url}/health", timeout=2)
            if r.json().get("status") == "ok":
                print("llama-server ready!")
                return
        except Exception:
            pass
        time.sleep(2)
        print(f"Waiting... {i+1}/60")
    raise RuntimeError("Server failed to start")


def llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
) -> dict:
    """Synchronous LLM call to the llama-server."""
    llama_url = _get_llama_url()
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
    """Async LLM call to the llama-server using httpx."""
    llama_url = _get_llama_url()
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
    async with httpx.AsyncClient(timeout=300) as client:
        res = await client.post(
            f"{llama_url}/v1/chat/completions",
            json=payload,
        )
        return res.json()
