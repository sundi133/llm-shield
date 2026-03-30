import os
import subprocess
import requests
import time
from typing import Optional

import httpx

import config.schema as _config_module

_DEFAULT_MODEL_PATH = "/models/Qwen3.5-4B-Q4_K_M.gguf"
_DEFAULT_DRAFT_MODEL_PATH = "/models/Qwen3.5-0.8B-Q4_K_M.gguf"

# Guardrail name → server URL routing map (built at startup)
_guardrail_server_map: dict[str, str] = {}
_default_server_url: str = "http://127.0.0.1:8000"


def _get_servers_config() -> list[dict]:
    """Get server configs from yaml. Falls back to single-server default."""
    if _config_module.config and _config_module.config.llm_backend:
        servers = _config_module.config.llm_backend.get("servers")
        if servers:
            return servers
        # Legacy single-server config
        url = _config_module.config.llm_backend.get("url", "http://127.0.0.1:8000")
        return [{"url": url, "gpu": 0, "guardrails": ["all"]}]
    return [{"url": "http://127.0.0.1:8000", "gpu": 0, "guardrails": ["all"]}]


def _get_model_path() -> str:
    if _config_module.config and _config_module.config.llm_backend:
        return _config_module.config.llm_backend.get("model_path", _DEFAULT_MODEL_PATH)
    return _DEFAULT_MODEL_PATH


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


def _build_server_args(port: int, model_path: str, draft_model_path: str) -> list[str]:
    """Build llama-server command args for a single instance."""
    args = [
        "/app/llama-server",
        "-m",
        model_path,
    ]
    # Add draft model for speculative decoding if it exists
    if draft_model_path and os.path.exists(draft_model_path):
        args.extend(["-md", draft_model_path, "-ngld", "99", "--draft-max", "32"])
    args.extend(
        [
            "-ngl",
            "99",
            "-c",
            "32768",
            "--flash-attn",
            "auto",
            "--host",
            "0.0.0.0",
            "--port",
            str(port),
            "-np",
            "8",
            "--cache-type-k",
            "q4_0",
            "--cache-type-v",
            "q4_0",
            "--log-disable",
        ]
    )
    return args


def start_server():
    """Start llama-server instance(s) based on config.

    Single GPU (default):
      servers:
        - url: "http://127.0.0.1:8000"
          gpu: 0
          guardrails: ["all"]

    Multi-GPU:
      servers:
        - url: "http://127.0.0.1:8000"
          gpu: 0
          guardrails: ["adversarial_detection"]
        - url: "http://127.0.0.1:8001"
          gpu: 1
          guardrails: ["topic_restriction", "topic_enforcement"]
        - url: "http://127.0.0.1:8002"
          gpu: 2
          guardrails: ["safety_check", "toxicity"]
    """
    global _guardrail_server_map, _default_server_url

    servers = _get_servers_config()
    model_path = _get_model_path()
    draft_model_path = _get_draft_model_path()

    # Clear any RunPod-set GPU restriction so all GPUs are visible
    parent_cuda = os.environ.get("CUDA_VISIBLE_DEVICES", "not set")
    print(f"Parent CUDA_VISIBLE_DEVICES: {parent_cuda}")
    print(f"Launching {len(servers)} server(s)...")

    for server_cfg in servers:
        url = server_cfg["url"]
        gpu = server_cfg.get("gpu", 0)
        guardrail_names = server_cfg.get("guardrails", ["all"])

        # Extract port from URL
        port = int(url.rsplit(":", 1)[-1])

        # Build routing map
        if "all" in guardrail_names:
            _default_server_url = url
        else:
            for name in guardrail_names:
                _guardrail_server_map[name] = url

        # Start llama-server pinned to this GPU
        # Override CUDA_VISIBLE_DEVICES for this specific process
        env = os.environ.copy()
        env["CUDA_VISIBLE_DEVICES"] = str(gpu)

        args = _build_server_args(port, model_path, draft_model_path)
        subprocess.Popen(args, env=env)
        print(f"Started llama-server on port {port} (CUDA_VISIBLE_DEVICES={gpu}) for {guardrail_names}")

    # Wait for all servers
    for server_cfg in servers:
        url = server_cfg["url"]
        gpu = server_cfg.get("gpu", 0)
        _wait_for_server(url, f"llama-server (GPU {gpu})")

    # Log routing summary
    print("\n" + "=" * 60)
    print("LLM BACKEND — SERVER ROUTING")
    print("=" * 60)
    print(f"  Servers started: {len(servers)}")
    print(f"  Model: {model_path}")
    print(f"  Draft: {draft_model_path}")
    print()
    for server_cfg in servers:
        url = server_cfg["url"]
        gpu = server_cfg.get("gpu", 0)
        names = server_cfg.get("guardrails", ["all"])
        print(f"  GPU {gpu} → {url}")
        print(f"    Guardrails: {', '.join(names)}")
    print()
    if _guardrail_server_map:
        print("  Routing map:")
        for name, url in sorted(_guardrail_server_map.items()):
            print(f"    {name} → {url}")
    else:
        print(f"  All guardrails → {_default_server_url}")
    print("=" * 60 + "\n")


def get_server_url(guardrail_name: Optional[str] = None) -> str:
    """Get the server URL for a specific guardrail.

    If the guardrail has a dedicated server, returns that URL.
    Otherwise returns the default server URL.
    """
    if guardrail_name and guardrail_name in _guardrail_server_map:
        return _guardrail_server_map[guardrail_name]
    return _default_server_url


def _ensure_no_think(messages: list) -> list:
    """Append /no_think to the system message to disable Qwen3 thinking mode."""
    messages = [dict(m) for m in messages]
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
    guardrail_name: Optional[str] = None,
) -> dict:
    """Synchronous LLM call routed to the correct server."""
    url = get_server_url(guardrail_name)
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    res = requests.post(
        f"{url}/v1/chat/completions",
        json=payload,
        timeout=300,
    )
    return res.json()


async def async_llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
    guardrail_name: Optional[str] = None,
) -> dict:
    """Async LLM call routed to the correct server based on guardrail name."""
    import logging

    url = get_server_url(guardrail_name)
    logging.getLogger("llm_backend").debug(
        f"[{guardrail_name or 'unknown'}] → {url}"
    )
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    async with httpx.AsyncClient(timeout=300) as client:
        res = await client.post(
            f"{url}/v1/chat/completions",
            json=payload,
        )
        return res.json()
