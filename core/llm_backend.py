import json
import os
import re
import subprocess
import requests
import time
from typing import Optional


def parse_llm_json(raw: str) -> dict:
    """Parse JSON from LLM, fixing common model quirks like extra spaces in keys.

    Models sometimes generate keys like 'is_  adversarial' instead of 'is_adversarial'.
    This function cleans up such malformed keys before parsing.
    """
    cleaned = re.sub(
        r'"([^"]*?)\s{2,}([^"]*?)"(\s*:)',
        lambda m: f'"{m.group(1)}{m.group(2)}"{m.group(3)}',
        raw,
    )
    return json.loads(cleaned)


def parse_csv_response(raw: str, fields: list[str]) -> dict:
    """Parse a CSV line from LLM into a dict keyed by field names.

    Handles common quirks: extra whitespace, quoted values, header echo.
    Fields are cast to bool/float where possible.
    """
    line = raw.strip()
    # If the model echoed the header, take the second line
    if "\n" in line:
        line = line.split("\n")[-1].strip()
    # Strip surrounding quotes if model wrapped the whole line
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]

    parts = [p.strip().strip('"').strip("'") for p in line.split(",")]

    result: dict = {}
    for i, name in enumerate(fields):
        val = parts[i].strip() if i < len(parts) else ""
        # Cast booleans
        if val.lower() in ("true", "yes"):
            result[name] = True
        elif val.lower() in ("false", "no"):
            result[name] = False
        else:
            # Try float
            try:
                result[name] = float(val)
            except (ValueError, TypeError):
                result[name] = val
    return result

import httpx

import config.schema as _config_module

# Shared clients for connection pooling and reuse
_shared_client: Optional[httpx.AsyncClient] = None
_shared_session: Optional[requests.Session] = None


def _get_shared_client() -> httpx.AsyncClient:
    """Get or create the shared AsyncClient for connection reuse."""
    global _shared_client
    if _shared_client is None:
        # Try to enable HTTP/2 if available, fallback to HTTP/1.1
        try:
            _shared_client = httpx.AsyncClient(
                timeout=300,
                limits=httpx.Limits(
                    max_keepalive_connections=50,   # 50 warm connections
                    max_connections=200,            # 200 total for 100 req/sec + bursts
                    keepalive_expiry=60.0,          # 60 second keepalive
                ),
                http2=True,  # Enable HTTP/2 for better performance
            )
        except ImportError:
            # Fallback to HTTP/1.1 if h2 package not available
            _shared_client = httpx.AsyncClient(
                timeout=300,
                limits=httpx.Limits(
                    max_keepalive_connections=50,
                    max_connections=200,
                    keepalive_expiry=60.0,
                ),
            )
    return _shared_client


def _get_shared_session() -> requests.Session:
    """Get or create the shared requests Session for connection reuse."""
    global _shared_session
    if _shared_session is None:
        _shared_session = requests.Session()
        # Configure connection pooling for high volume (100 req/sec)
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,            # 20 connection pools per host
            pool_maxsize=150,               # 150 connections per pool
            max_retries=0,                  # No auto-retry (guardrails handle failures)
            pool_block=False,               # Don't block when pool is full
        )
        _shared_session.mount("http://", adapter)
        _shared_session.mount("https://", adapter)
    return _shared_session


async def _close_shared_clients():
    """Close both shared clients on shutdown."""
    global _shared_client, _shared_session

    if _shared_client is not None:
        await _shared_client.aclose()
        _shared_client = None

    if _shared_session is not None:
        _shared_session.close()
        _shared_session = None

_DEFAULT_MODEL_PATH = "/models/Qwen3.5-9B-guardrailed-Q4_K_M.gguf"
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
            "16384",
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
          guardrails: ["toxicity"]
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
    print(f"    Repo: votal-ai/Qwen3.5-9B-guardrailed-v3-GGUF")
    print(f"  Draft: {draft_model_path}")
    print(f"    Repo: votal-ai/Qwen3.5-0.8B-GGUF")
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
    """Append thinking suppression to the system message.

    Supports both Qwen3 (/no_think) and Qwen3.5 (/set nothink) formats.
    """
    messages = [dict(m) for m in messages]
    for m in messages:
        if m.get("role") == "system":
            content = m.get("content", "")
            if "/no_think" not in content and "/set nothink" not in content:
                m["content"] = content.rstrip() + " /no_think /set nothink"
            break
    return messages


def _build_payload(
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Build the request payload for llama-server or LiteLLM."""
    messages = _ensure_no_think(messages)
    payload = {
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    # Add model field for LiteLLM mode
    if os.getenv("ENABLE_LITELLM") == "true":
        # Use the model name from LiteLLM config - default to first available model
        model_name = os.getenv("LLM_MODEL_NAME", "gpt_4o_mini")
        payload["model"] = model_name
    else:
        # vLLM mode - add chat template kwargs
        payload["chat_template_kwargs"] = {"enable_thinking": False}

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
    session = _get_shared_session()
    res = session.post(
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
    url = get_server_url(guardrail_name)
    prep_start = time.perf_counter()
    payload = _build_payload(messages, max_tokens, temperature, response_format)
    prep_ms = (time.perf_counter() - prep_start) * 1000

    llm_start = time.perf_counter()
    client = _get_shared_client()
    res = await client.post(
        f"{url}/v1/chat/completions",
        json=payload,
    )
    result = res.json()
    llm_ms = (time.perf_counter() - llm_start) * 1000

    post_start = time.perf_counter()
    # Inject timing metadata into the response
    if isinstance(result, dict):
        result["_timing"] = {
            "prep_ms": round(prep_ms, 2),
            "llm_call_ms": round(llm_ms, 2),
            "guardrail_name": guardrail_name,
            "server_url": url,
        }
    post_ms = (time.perf_counter() - post_start) * 1000
    if isinstance(result, dict) and "_timing" in result:
        result["_timing"]["post_ms"] = round(post_ms, 2)

    return result
