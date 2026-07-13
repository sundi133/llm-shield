"""LLM providers for the agentic deep-scan (``--deep``).

Two backends behind one `complete(system, user, schema) -> dict` surface:
- **openai**: OpenAI-compatible ``/chat/completions`` via the ``httpx`` already in
  the package (works with OpenAI, Ollama, vLLM, Together). No SDK.
- **anthropic**: the official ``anthropic`` SDK (optional extra
  ``pip install shield-mcp[deep]``), model default ``claude-opus-4-8``,
  structured output via ``output_config.format``.

All of this is imported only under ``--deep``; the default scan never touches it.
"""

from __future__ import annotations

import json
import os
from typing import Optional


class DeepConfigError(Exception):
    """--deep has no resolvable backend / bad provider (maps to usage exit 4)."""


def _first(*vals):
    for v in vals:
        if v:
            return v
    return None


# ── openai-compatible (raw httpx) ──────────────────────────────────────
class OpenAIClient:
    def __init__(self, *, base_url: str, model: str, api_key: str = "",
                 timeout: float = 60.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self._transport = transport  # test seam (httpx.MockTransport)

    async def complete(self, system: str, user: str, schema: dict) -> dict:
        import httpx

        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Best-effort structured output; the JSON parse below is the real guard
            # (some OpenAI-compatible servers ignore response_format).
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "deep_scan", "schema": schema, "strict": True},
            },
        }
        async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
            resp = await client.post(self.base_url + "/chat/completions",
                                     json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)


# ── anthropic (official SDK) ───────────────────────────────────────────
class AnthropicClient:
    def __init__(self, *, model: str, api_key: str, timeout: float = 60.0):
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    async def complete(self, system: str, user: str, schema: dict) -> dict:
        try:
            from anthropic import AsyncAnthropic
        except Exception as e:  # optional extra not installed
            raise DeepConfigError(
                "--deep-provider anthropic needs the anthropic SDK: "
                "pip install shield-mcp[deep]"
            ) from e

        client = AsyncAnthropic(api_key=self.api_key, timeout=self.timeout)
        msg = await client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        text = next((b.text for b in msg.content if getattr(b, "type", None) == "text"), "")
        return json.loads(text)


# ── resolution (with the hard error when unconfigured) ─────────────────
def resolve_client(provider: Optional[str], *, url=None, model=None, api_key=None,
                   timeout: float = 60.0) -> object:
    """Build the LLM client for --deep, or raise DeepConfigError (exit 4)."""
    provider = (provider or "openai").lower()

    if provider == "openai":
        base = _first(url, os.environ.get("SHIELD_DEEP_URL"))
        mdl = _first(model, os.environ.get("SHIELD_DEEP_MODEL"))
        key = _first(api_key, os.environ.get("SHIELD_DEEP_API_KEY"),
                     os.environ.get("OPENAI_API_KEY"))
        missing = [n for n, v in (("--deep-url", base), ("--deep-model", mdl)) if not v]
        if missing:
            raise DeepConfigError(
                "--deep (openai) needs " + " and ".join(missing) +
                " (or $SHIELD_DEEP_URL / $SHIELD_DEEP_MODEL)"
            )
        return OpenAIClient(base_url=base, model=mdl, api_key=key or "", timeout=timeout)

    if provider == "anthropic":
        mdl = _first(model, os.environ.get("SHIELD_DEEP_MODEL"), "claude-opus-4-8")
        key = _first(api_key, os.environ.get("SHIELD_DEEP_API_KEY"),
                     os.environ.get("ANTHROPIC_API_KEY"))
        if not key:
            raise DeepConfigError(
                "--deep (anthropic) needs --deep-api-key (or $ANTHROPIC_API_KEY)"
            )
        return AnthropicClient(model=mdl, api_key=key, timeout=timeout)

    raise DeepConfigError(f"unknown --deep-provider {provider!r} (use openai|anthropic)")
