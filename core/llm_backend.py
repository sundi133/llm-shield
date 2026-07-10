import asyncio
import json
import logging
import os
import re
import subprocess
import requests
import time
import urllib.parse
from typing import Optional

logger = logging.getLogger("votal.llm_backend")

LLM_DEBUG = os.environ.get("LLM_DEBUG", "false").lower() in ("true", "1", "yes")


def parse_llm_json(raw: str) -> dict:
    """Parse JSON from LLM, fixing common model quirks.

    Handles:
    - markdown code fences: some models (e.g. gemma4 on ollama.com) wrap
      their JSON in ```json ... ``` even when a schema is requested, which
      makes json.loads fail with "Expecting value: line 1 column 1 (char 0)"
    - extra spaces in keys: 'is_  adversarial' instead of 'is_adversarial'
    """
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    cleaned = re.sub(
        r'"([^"]*?)\s{2,}([^"]*?)"(\s*:)',
        lambda m: f'"{m.group(1)}{m.group(2)}"{m.group(3)}',
        cleaned,
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


def _normalize_server_url(url: str) -> str:
    """Normalize server base URLs before appending endpoint paths."""
    return url.strip().rstrip("/")


def _assert_http_url(url: str, source: str) -> str:
    """Reject anything that isn't a plain http(s) URL before it becomes an
    outbound request target (CWE-918 defence-in-depth).

    Backend URLs are operator-set (env / config), not user input, so this is
    not a user-driven SSRF sink -- but validating the scheme means a typo or a
    stray file://, gopher://, etc. can't turn into an unexpected request. Host
    is intentionally NOT restricted: a self-hosted vLLM backend legitimately
    lives on localhost / a private address.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(
            f"{source} must be an http(s) URL (got scheme {parsed.scheme!r}); "
            "refusing to use it as an LLM backend."
        )
    return url


def _get_env_backend_url() -> Optional[str]:
    """Return an explicit backend URL override from the environment."""
    url = _normalize_server_url(os.getenv("LLM_BACKEND_URL", ""))
    if not url:
        return None
    return _assert_http_url(url, "LLM_BACKEND_URL")


def _get_backend_type() -> str:
    """Backend type: 'vllm' (default), 'litellm', or 'ollama'."""
    return os.getenv("LLM_BACKEND_TYPE", "vllm").strip().lower()


def _get_backend_api_key() -> Optional[str]:
    """API key for authenticated backends (e.g. ollama.com cloud)."""
    return os.getenv("OLLAMA_API_KEY") or os.getenv("LLM_BACKEND_API_KEY") or None


def _is_ollama_mode() -> bool:
    """True when the backend is Ollama (LiteLLM mode takes precedence)."""
    return os.getenv("ENABLE_LITELLM") != "true" and _get_backend_type() == "ollama"


def _auth_headers() -> dict:
    """Authorization headers for the LLM backend, if configured.

    Only attached in ollama mode (ollama.com cloud needs a Bearer key;
    local `ollama serve` needs none). Never log the key itself.
    """
    if _get_backend_type() == "ollama":
        key = _get_backend_api_key()
        if key:
            return {"Authorization": f"Bearer {key}"}
    return {}


def _get_servers_config() -> list[dict]:
    """Get server configs from yaml. Falls back to single-server default."""
    env_url = _get_env_backend_url()
    if env_url:
        return [{"url": env_url, "gpu": 0, "guardrails": ["all"]}]

    if _config_module.config and _config_module.config.llm_backend:
        servers = _config_module.config.llm_backend.get("servers")
        if servers:
            normalized_servers = []
            for server in servers:
                normalized_server = dict(server)
                if "url" in normalized_server:
                    normalized_server["url"] = _assert_http_url(
                        _normalize_server_url(normalized_server["url"]),
                        "llm_backend.servers[].url",
                    )
                normalized_servers.append(normalized_server)
            return normalized_servers
        # Legacy single-server config
        url = _assert_http_url(
            _normalize_server_url(
                _config_module.config.llm_backend.get("url", "http://127.0.0.1:8000")
            ),
            "llm_backend.url",
        )
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
                logger.info("%s ready!", label)
                return
        except Exception:
            pass
        time.sleep(2)
        logger.info("Waiting for %s... %d/%d", label, i + 1, max_attempts)
    raise RuntimeError(f"{label} failed to start")


def _assert_safe_model_path(path: str, source: str) -> str:
    """Reject model paths that contain shell metacharacters or control chars
    before they're passed to subprocess (CWE-78 defence-in-depth).

    start_server launches llama-server with subprocess.Popen(args) in LIST
    form and never shell=True, so there is no shell to inject into today. This
    guard is belt-and-suspenders against a poisoned config file and a future
    refactor that might introduce a shell: a legitimate model path is a plain
    filesystem path, so anything with shell metacharacters, whitespace tricks,
    or NUL/newline bytes is refused rather than executed.
    """
    if path and (
        any(ch in path for ch in ";|&$`><\n\r\t\0")
        or path.strip() != path
    ):
        raise RuntimeError(
            f"{source} contains unsafe characters and will not be used to "
            f"launch a subprocess: {path!r}"
        )
    return path


def _build_server_args(port: int, model_path: str, draft_model_path: str) -> list[str]:
    """Build llama-server command args for a single instance."""
    _assert_safe_model_path(model_path, "model_path")
    _assert_safe_model_path(draft_model_path, "draft_model_path")
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
    logger.info("Parent CUDA_VISIBLE_DEVICES: %s", parent_cuda)
    logger.info("Launching %d server(s)...", len(servers))

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
        logger.info("Started llama-server on port %d (CUDA_VISIBLE_DEVICES=%s) for %s", port, gpu, guardrail_names)

    # Wait for all servers
    for server_cfg in servers:
        url = server_cfg["url"]
        gpu = server_cfg.get("gpu", 0)
        _wait_for_server(url, f"llama-server (GPU {gpu})")

    # Log routing summary
    logger.info("LLM BACKEND — SERVER ROUTING")
    logger.info("  Servers started: %d", len(servers))
    logger.info("  Model: %s (votal-ai/Qwen3.5-9B-guardrailed-v3-GGUF)", model_path)
    logger.info("  Draft: %s (votal-ai/Qwen3.5-0.8B-GGUF)", draft_model_path)
    for server_cfg in servers:
        url = server_cfg["url"]
        gpu = server_cfg.get("gpu", 0)
        names = server_cfg.get("guardrails", ["all"])
        logger.info("  GPU %s → %s | Guardrails: %s", gpu, url, ", ".join(names))
    if _guardrail_server_map:
        for name, url in sorted(_guardrail_server_map.items()):
            logger.info("  Routing: %s → %s", name, url)
    else:
        logger.info("  All guardrails → %s", _default_server_url)


def get_server_url(guardrail_name: Optional[str] = None) -> str:
    """Get the server URL for a specific guardrail.

    If the guardrail has a dedicated server, returns that URL.
    Otherwise returns the default server URL.
    """
    env_url = _get_env_backend_url()
    if env_url:
        return env_url
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


def _build_ollama_payload(
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Build a native Ollama /api/chat payload.

    Native API instead of OpenAI-compat because:
    - `think: false` actually disables thinking (compat endpoint ignores it,
      and thinking models then return empty content under low max_tokens);
    - `format` enforces a JSON schema server-side for response_format
      guardrails (custom_policy, role_based_policy).
    No /no_think prompt hack needed — `think` is first-class here.
    """
    payload = {
        "model": os.getenv("LLM_MODEL_NAME", ""),
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    # OLLAMA_THINK: false (default) | true | auto ("auto" omits the field for
    # models that reject the parameter).
    think = os.getenv("OLLAMA_THINK", "false").strip().lower()
    if think in ("true", "false"):
        payload["think"] = think == "true"
    if response_format:
        payload["format"] = response_format
    return payload


def _adapt_ollama_response(data: dict) -> dict:
    """Adapt a native Ollama /api/chat response to the OpenAI shape callers expect.

    Error responses ({"error": ...}) pass through unchanged — callers treat a
    missing choices key as an LLM failure, same as an OpenAI-style error.
    """
    if not isinstance(data, dict) or "message" not in data:
        return data
    msg = data.get("message") or {}
    return {
        "model": data.get("model"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": msg.get("role", "assistant"),
                    "content": msg.get("content", ""),
                },
                "finish_reason": data.get("done_reason", "stop"),
            }
        ],
    }


def _build_payload(
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Build the request payload for llama-server, LiteLLM, or Ollama."""
    if _is_ollama_mode():
        return _build_ollama_payload(messages, max_tokens, temperature, response_format)

    messages = _ensure_no_think(messages)
    payload = {
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    # Add model field for LiteLLM mode
    if os.getenv("ENABLE_LITELLM") == "true":
        # Use the model name from LiteLLM config; "default" is the alias
        # set in router_settings.model_group_alias by the config generator,
        # and works regardless of which provider was selected.
        model_name = os.getenv("LLM_MODEL_NAME", "default")
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


def _print_llm_request(endpoint_url: str, payload: dict):
    """Print the exact LLM endpoint and request payload for debugging."""
    if not LLM_DEBUG:
        return
    logger.debug("LLM REQUEST | URL: %s | PAYLOAD: %s", endpoint_url, json.dumps(payload, ensure_ascii=False))


def _print_llm_response(endpoint_url: str, status_code: int, body: str):
    """Print upstream LLM response details when debugging failures."""
    if not LLM_DEBUG:
        return
    logger.debug("LLM RESPONSE | URL: %s | STATUS: %d | BODY: %s", endpoint_url, status_code, body)


def _chat_completions_url(server_url: str) -> str:
    return f"{_normalize_server_url(server_url)}/v1/chat/completions"


def _endpoint_url(server_url: str) -> str:
    """Endpoint for the configured backend.

    Ollama mode uses the native /api/chat endpoint, NOT the OpenAI-compat
    /v1/chat/completions: the compat endpoint ignores the `think` parameter,
    so thinking models burn the whole token budget on reasoning and return
    empty content (breaks response_format guardrails like custom_policy).
    """
    if _is_ollama_mode():
        return f"{_normalize_server_url(server_url)}/api/chat"
    return _chat_completions_url(server_url)


# ---------------------------------------------------------------------------
# Guard model mode — SHIELD_GUARD_MODEL_MODE=votal (default) | nemotron | both
#
# "votal" is the unmodified, current-production code path (see llm_call /
# async_llm_call below) -- this section only adds NEW behavior for the
# nemotron/both modes, gated by an opt-in env var. Nothing here changes
# behavior when the env var is unset.
#
# SCOPE: the mode applies ONLY to guard-classification calls -- those that
# pass a guardrail_name. Calls without one (the gateway's proxied user chat
# completions in routes_gateway.py, codegen enhancement) always use the
# original votal path: routing user chat traffic to a content-safety
# classifier would break the product, and duplicating it to a second backend
# in 'both' mode would leak user conversations to an endpoint the tenant
# never opted into.
# ---------------------------------------------------------------------------


def _get_guard_model_mode() -> str:
    """Which guard model backend(s) to call: 'votal' (default) | 'nemotron' | 'both'."""
    return os.getenv("SHIELD_GUARD_MODEL_MODE", "votal").strip().lower()


def _get_guard_model_primary() -> str:
    """In 'both' mode, which model's verdict is authoritative on a tie/no-flag."""
    return os.getenv("SHIELD_GUARD_MODEL_PRIMARY", "votal").strip().lower()


def _resolve_targets(mode: str) -> list[str]:
    """Ordered list of backend targets to call for this guard-path request."""
    if mode == "votal":
        return ["votal"]
    if mode == "nemotron":
        return ["nemotron"]
    if mode == "both":
        primary = _get_guard_model_primary()
        if primary not in ("votal", "nemotron"):
            raise RuntimeError(
                f"Unknown SHIELD_GUARD_MODEL_PRIMARY={primary!r} (expected 'votal' or 'nemotron')"
            )
        secondary = "nemotron" if primary == "votal" else "votal"
        return [primary, secondary]
    raise RuntimeError(
        f"Unknown SHIELD_GUARD_MODEL_MODE={mode!r} (expected 'votal', 'nemotron', or 'both')"
    )


def _get_nemotron_server_url() -> str:
    """Nemotron backend URL. Required whenever a request targets 'nemotron'.

    Fails fast rather than silently falling back to Votal -- a misconfigured
    nemotron/both deployment should be loud, not quietly serve Votal traffic
    under a different name.

    The URL is operator-set (an env var), not user input, so this is not a
    user-driven SSRF sink. As defence-in-depth for a new egress path, we
    still reject anything that isn't a plain http/https URL -- so a typo or a
    stray file://, gopher://, etc. can't turn into an unexpected request
    scheme. Host is intentionally NOT restricted: a self-hosted vLLM backend
    legitimately lives on localhost / a private address.
    """
    url = _normalize_server_url(os.getenv("NEMOTRON_BACKEND_URL", ""))
    if not url:
        raise RuntimeError(
            "NEMOTRON_BACKEND_URL must be set when SHIELD_GUARD_MODEL_MODE is "
            "'nemotron' or 'both'."
        )
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(
            f"NEMOTRON_BACKEND_URL must be an http(s) URL (got scheme "
            f"{parsed.scheme!r}); refusing to use it as a guard backend."
        )
    return url


def _nemotron_model_name() -> str:
    return os.getenv("NEMOTRON_MODEL_NAME", "")


def _nemotron_auth_headers() -> dict:
    """Bearer auth for NIM-hosted endpoints; empty for a self-hosted server."""
    key = os.getenv("NEMOTRON_BACKEND_API_KEY")
    return {"Authorization": f"Bearer {key}"} if key else {}


def _build_nemotron_payload(
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Minimal standard OpenAI chat-completions payload for the Nemotron backend.

    Deliberately skips the vLLM-specific extras _build_payload adds for Votal
    (chat_template_kwargs, /no_think injection): the exact Nemotron hosting
    (self-hosted vLLM vs an NVIDIA NIM endpoint) isn't resolved yet (see
    docs/investigation/open-questions.md #1/#2), so this targets the lowest
    common denominator of the OpenAI-compatible contract both platforms support.
    """
    payload = {
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    model_name = _nemotron_model_name()
    if model_name:
        payload["model"] = model_name
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


# Per-guardrail verdict readers for 'both'-mode merging. Merging two models'
# outputs requires knowing each guardrail's verdict POLARITY -- several
# guardrails use true=SAFE semantics (tone_enforcement 'compliant',
# topic_restriction 'related', topic_enforcement 'overall_allowed',
# factual_grounding 'grounded'), so a naive "true means flagged" OR-merge
# would let a permissive secondary verdict MASK a primary violation. Only
# guardrails registered here are merged; anything else (unknown names,
# multi-line shapes like hallucinated_links, free-text shapes like
# language_detection) is shadow-logged: the secondary's raw output is
# attached for comparison but never changes the decision.
#   kind "csv":  verdict is the first field of a single CSV line
#   kind "json": verdict is the named boolean field of a JSON object
#   unsafe_when: the field value that means "flag/block"
_GUARD_VERDICT_REGISTRY: dict[str, dict] = {
    "adversarial_detection": {"kind": "csv", "unsafe_when": True},
    "toxicity": {"kind": "csv", "unsafe_when": True},
    "pii_detection": {"kind": "csv", "unsafe_when": True},
    "bias_detection": {"kind": "csv", "unsafe_when": True},
    "topic_restriction": {"kind": "csv", "unsafe_when": False},
    "topic_enforcement": {"kind": "csv", "unsafe_when": False},
    "tone_enforcement": {"kind": "csv", "unsafe_when": False},
    "factual_grounding": {"kind": "csv", "unsafe_when": False},
    "custom_policy_input": {"kind": "json", "field": "violates_policy", "unsafe_when": True},
    "custom_policy_output": {"kind": "json", "field": "violates_policy", "unsafe_when": True},
    "role_based_input_policy": {"kind": "json", "field": "violates_policy", "unsafe_when": True},
    "role_based_policy": {"kind": "json", "field": "violates_policy", "unsafe_when": True},
}


def _first_csv_bool(content: str) -> Optional[bool]:
    """True/False if content is a single CSV line whose first field is an
    unambiguous boolean token (e.g. 'true,jailbreak,0.97'). None if the shape
    doesn't match -- e.g. multi-line outputs like hallucinated_links.py's
    per-URL CSV rows, where a generic merge would corrupt the content.
    """
    text = (content or "").strip()
    if not text or "\n" in text:
        return None
    first = text.split(",", 1)[0].strip().strip('"').strip("'").lower()
    if first in ("true", "yes"):
        return True
    if first in ("false", "no"):
        return False
    return None


def _json_bool_field(content: str, field: str) -> Optional[bool]:
    """The named boolean field from a JSON completion, or None if the content
    doesn't parse as JSON with that field as a bool."""
    try:
        data = parse_llm_json(content)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    value = data.get(field)
    return value if isinstance(value, bool) else None


def _verdict_unsafe(guardrail_name: Optional[str], content: str) -> Optional[bool]:
    """Whether this completion means 'flag/block' for the given guardrail.

    None when the guardrail isn't registered or the content doesn't match its
    registered shape -- callers must treat None as 'do not merge'.
    """
    spec = _GUARD_VERDICT_REGISTRY.get(guardrail_name or "")
    if spec is None:
        return None
    if spec["kind"] == "csv":
        value = _first_csv_bool(content)
    else:
        value = _json_bool_field(content, spec["field"])
    if value is None:
        return None
    return value == spec["unsafe_when"]


def _combine_both(
    primary_result: dict,
    secondary_result: Optional[dict],
    guardrail_name: Optional[str],
) -> tuple[dict, dict]:
    """OR-combine primary/secondary verdicts for SHIELD_GUARD_MODEL_MODE=both.

    Decision: block if EITHER model flags content unsafe -- the conservative
    choice for a security guardrail -- applied only for guardrails whose
    verdict shape AND polarity are registered in _GUARD_VERDICT_REGISTRY.
    Everything else is shadow-logged (secondary attached to _secondary_model
    for comparison/benchmarking, decision unchanged): merging without knowing
    polarity risks a permissive secondary verdict masking a primary violation.

    Returns (response_to_use, secondary_metadata).
    """
    secondary_meta: dict = {"raw": None, "merged": False, "error": None}

    if secondary_result is None:
        return primary_result, secondary_meta

    try:
        primary_content = primary_result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return primary_result, secondary_meta

    try:
        secondary_content = secondary_result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        secondary_meta["error"] = "secondary response missing choices"
        return primary_result, secondary_meta

    secondary_meta["raw"] = secondary_content

    primary_unsafe = _verdict_unsafe(guardrail_name, primary_content)
    secondary_unsafe = _verdict_unsafe(guardrail_name, secondary_content)

    if primary_unsafe is None or secondary_unsafe is None:
        # Unregistered guardrail or unexpected shape -- shadow-log only.
        return primary_result, secondary_meta

    secondary_meta["merged"] = True
    if secondary_unsafe and not primary_unsafe:
        # Secondary flagged something primary missed. Return secondary's own
        # response (not a synthetic patch) so its type/confidence/reasoning
        # stay self-consistent for the calling guardrail's existing parser.
        return secondary_result, secondary_meta

    return primary_result, secondary_meta


def validate_guard_model_config() -> None:
    """Fail fast on a malformed guard-model configuration.

    Call at data-plane startup (create_app). Without this, a typo'd
    SHIELD_GUARD_MODEL_MODE or a missing NEMOTRON_BACKEND_URL only raises at
    call time -- and every LLM guardrail catches call failures and allows by
    default, so the misconfiguration would silently disable ALL LLM
    guardrails instead of being loud.
    """
    targets = _resolve_targets(_get_guard_model_mode())
    if "nemotron" in targets:
        _get_nemotron_server_url()
    # Also validate the Votal backend URL sources (env + config) so a bad
    # scheme fails at boot rather than per-request on the guard path.
    _get_env_backend_url()
    _get_servers_config()


def _dispatch_sync(
    target: str,
    guardrail_name: Optional[str],
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Single synchronous backend call for the given target ('votal' | 'nemotron')."""
    if target == "nemotron":
        url = _get_nemotron_server_url()
        payload = _build_nemotron_payload(messages, max_tokens, temperature, response_format)
        endpoint_url = _chat_completions_url(url)
        headers = _nemotron_auth_headers() or None
    else:
        url = get_server_url(guardrail_name)
        payload = _build_payload(messages, max_tokens, temperature, response_format)
        endpoint_url = _endpoint_url(url)
        headers = _auth_headers() or None

    _print_llm_request(endpoint_url, payload)
    session = _get_shared_session()
    res = session.post(endpoint_url, json=payload, headers=headers, timeout=300)
    if res.status_code >= 400:
        _print_llm_response(endpoint_url, res.status_code, res.text)
    result = res.json()
    if target == "votal" and _is_ollama_mode():
        result = _adapt_ollama_response(result)
    return {"result": result, "server_url": url}


async def _dispatch_async(
    target: str,
    guardrail_name: Optional[str],
    messages: list,
    max_tokens: int,
    temperature: float,
    response_format: Optional[dict],
) -> dict:
    """Single async backend call for the given target ('votal' | 'nemotron')."""
    if target == "nemotron":
        url = _get_nemotron_server_url()
        payload = _build_nemotron_payload(messages, max_tokens, temperature, response_format)
        endpoint_url = _chat_completions_url(url)
        headers = _nemotron_auth_headers() or None
    else:
        url = get_server_url(guardrail_name)
        payload = _build_payload(messages, max_tokens, temperature, response_format)
        endpoint_url = _endpoint_url(url)
        headers = _auth_headers() or None

    _print_llm_request(endpoint_url, payload)
    client = _get_shared_client()
    res = await client.post(endpoint_url, json=payload, headers=headers)
    if res.status_code >= 400:
        _print_llm_response(endpoint_url, res.status_code, res.text)
    result = res.json()
    if target == "votal" and _is_ollama_mode():
        result = _adapt_ollama_response(result)
    return {"result": result, "server_url": url}


def llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
    guardrail_name: Optional[str] = None,
) -> dict:
    """Synchronous LLM call routed per SHIELD_GUARD_MODEL_MODE.

    The mode only applies to guard-classification calls (guardrail_name set);
    calls without one always use the original votal path (see the guard-model
    section comment above for why).

    mode=votal (default, unset): identical to the original single-backend
    behavior below -- no change for existing deployments.
    mode=nemotron: same call shape, routed to the Nemotron backend.
    mode=both: calls both sequentially and OR-combines verdicts (see
    _combine_both); the secondary's failure never blocks the primary result.
    """
    mode = _get_guard_model_mode()
    targets = _resolve_targets(mode) if guardrail_name else ["votal"]

    if len(targets) == 1:
        target = targets[0]
        if target == "votal":
            # Unmodified original code path.
            url = get_server_url(guardrail_name)
            payload = _build_payload(messages, max_tokens, temperature, response_format)
            endpoint_url = _endpoint_url(url)
            _print_llm_request(endpoint_url, payload)
            session = _get_shared_session()
            res = session.post(
                endpoint_url,
                json=payload,
                headers=_auth_headers() or None,
                timeout=300,
            )
            if res.status_code >= 400:
                _print_llm_response(endpoint_url, res.status_code, res.text)
            result = res.json()
            if _is_ollama_mode():
                result = _adapt_ollama_response(result)
            return result
        return _dispatch_sync(
            target, guardrail_name, messages, max_tokens, temperature, response_format
        )["result"]

    primary_target, secondary_target = targets
    primary_dispatched = _dispatch_sync(
        primary_target, guardrail_name, messages, max_tokens, temperature, response_format
    )

    secondary_result = None
    secondary_url = None
    secondary_error = None
    try:
        secondary_dispatched = _dispatch_sync(
            secondary_target, guardrail_name, messages, max_tokens, temperature, response_format
        )
        secondary_result = secondary_dispatched["result"]
        secondary_url = secondary_dispatched["server_url"]
    except Exception as e:
        secondary_error = str(e)

    merged_result, secondary_meta = _combine_both(
        primary_dispatched["result"], secondary_result, guardrail_name
    )
    secondary_meta.update({"target": secondary_target, "server_url": secondary_url})
    if secondary_error:
        secondary_meta["error"] = secondary_error
    if isinstance(merged_result, dict):
        merged_result["_secondary_model"] = secondary_meta
    return merged_result


async def async_llm_call(
    messages: list,
    max_tokens: int = 10,
    temperature: float = 0,
    response_format: Optional[dict] = None,
    guardrail_name: Optional[str] = None,
) -> dict:
    """Async LLM call routed per SHIELD_GUARD_MODEL_MODE.

    The mode only applies to guard-classification calls (guardrail_name set);
    calls without one always use the original votal path (see the guard-model
    section comment above for why).

    mode=votal (default, unset): identical to the original single-backend
    behavior below -- no change for existing deployments.
    mode=nemotron: same call shape, routed to the Nemotron backend.
    mode=both: calls both concurrently (asyncio.gather -- wall-clock is
    governed by the slower of the two, not their sum) and OR-combines
    verdicts (see _combine_both); the secondary's failure never blocks the
    primary result.
    """
    mode = _get_guard_model_mode()
    targets = _resolve_targets(mode) if guardrail_name else ["votal"]

    if len(targets) == 1 and targets[0] == "votal":
        # Unmodified original code path.
        url = get_server_url(guardrail_name)
        prep_start = time.perf_counter()
        payload = _build_payload(messages, max_tokens, temperature, response_format)
        prep_ms = (time.perf_counter() - prep_start) * 1000

        llm_start = time.perf_counter()
        client = _get_shared_client()
        endpoint_url = _endpoint_url(url)
        _print_llm_request(endpoint_url, payload)
        res = await client.post(
            endpoint_url,
            json=payload,
            headers=_auth_headers() or None,
        )
        if res.status_code >= 400:
            _print_llm_response(endpoint_url, res.status_code, res.text)
        result = res.json()
        if _is_ollama_mode():
            result = _adapt_ollama_response(result)
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

    if len(targets) == 1:
        # mode=nemotron
        llm_start = time.perf_counter()
        dispatched = await _dispatch_async(
            targets[0], guardrail_name, messages, max_tokens, temperature, response_format
        )
        llm_ms = (time.perf_counter() - llm_start) * 1000
        result = dispatched["result"]
        if isinstance(result, dict):
            result["_timing"] = {
                "prep_ms": 0.0,
                "llm_call_ms": round(llm_ms, 2),
                "guardrail_name": guardrail_name,
                "server_url": dispatched["server_url"],
                "guard_model_mode": mode,
            }
        return result

    # mode=both
    primary_target, secondary_target = targets
    llm_start = time.perf_counter()
    primary_dispatched, secondary_dispatched = await asyncio.gather(
        _dispatch_async(
            primary_target, guardrail_name, messages, max_tokens, temperature, response_format
        ),
        _dispatch_async(
            secondary_target, guardrail_name, messages, max_tokens, temperature, response_format
        ),
        return_exceptions=True,
    )
    llm_ms = (time.perf_counter() - llm_start) * 1000

    if isinstance(primary_dispatched, Exception):
        raise primary_dispatched

    secondary_result = None
    secondary_url = None
    secondary_error = None
    if isinstance(secondary_dispatched, Exception):
        secondary_error = str(secondary_dispatched)
    else:
        secondary_result = secondary_dispatched["result"]
        secondary_url = secondary_dispatched["server_url"]

    merged_result, secondary_meta = _combine_both(
        primary_dispatched["result"], secondary_result, guardrail_name
    )
    secondary_meta.update({"target": secondary_target, "server_url": secondary_url})
    if secondary_error:
        secondary_meta["error"] = secondary_error

    if isinstance(merged_result, dict):
        merged_result["_secondary_model"] = secondary_meta
        merged_result["_timing"] = {
            "prep_ms": 0.0,
            "llm_call_ms": round(llm_ms, 2),
            "guardrail_name": guardrail_name,
            "server_url": primary_dispatched["server_url"],
            "guard_model_mode": mode,
            "primary_target": primary_target,
        }
    return merged_result
