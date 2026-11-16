"""One interface to any model that can drive the lab's browser agents.

Pick the provider with environment variables (nothing is hard-coded):

    AGENT_LLM_PROVIDER   anthropic (default) | openai | azure
    AGENT_LLM_MODEL      model or deployment name
                         (default for anthropic: claude-opus-5-5)
    AGENT_LLM_EFFORT     anthropic only: low (default) | medium | high

    anthropic  ANTHROPIC_API_KEY. Uses the official Anthropic SDK.
    openai     AGENT_LLM_BASE_URL (for example https://openrouter.ai/api/v1,
               http://localhost:8000/v1 for vLLM, http://localhost:11434/v1
               for Ollama) and AGENT_LLM_API_KEY. Any OpenAI-compatible
               /chat/completions endpoint.
    azure      AGENT_LLM_BASE_URL (https://<resource>.openai.azure.com),
               AGENT_LLM_MODEL (the deployment name), AGENT_LLM_API_KEY,
               AGENT_LLM_AZURE_API_VERSION (default 2024-10-21).

Keys are never passed on the command line or printed. If a key isn't in the
environment, it is read from AGENT_LLM_ENV_FILE (default
~/.config/shield-lab/llm.env): KEY=VALUE lines, mode 600.

Every call returns the decoded JSON object the schema describes, plus token
usage, so the lab can report cost per run.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

import httpx

DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
ENV_FILE = Path(os.environ.get("AGENT_LLM_ENV_FILE", Path.home() / ".config/shield-lab/llm.env"))


def _load_env_file() -> None:
    """Fill missing variables from the private env file, without printing them."""
    if not ENV_FILE.exists():
        return
    mode = ENV_FILE.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit(f"{ENV_FILE} is readable by other users; run: chmod 600 {ENV_FILE}")
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        os.environ.setdefault(key, value.strip().strip('"').strip("'"))


@dataclass
class Usage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.calls += other.calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens


@dataclass
class LLM:
    provider: str
    model: str
    effort: str = "low"
    usage: Usage = field(default_factory=Usage)

    @classmethod
    def from_env(cls) -> "LLM":
        _load_env_file()
        provider = os.environ.get("AGENT_LLM_PROVIDER", "anthropic").strip().lower()
        if provider not in ("anthropic", "openai", "azure", "scripted"):
            raise SystemExit(f"AGENT_LLM_PROVIDER must be anthropic, openai or azure, not {provider!r}")
        if provider == "scripted":
            return cls(provider="scripted", model="fixed-plan")
        model = os.environ.get("AGENT_LLM_MODEL") or (DEFAULT_ANTHROPIC_MODEL if provider == "anthropic" else "")
        if not model:
            raise SystemExit("Set AGENT_LLM_MODEL for the openai and azure providers.")
        llm = cls(provider=provider, model=model, effort=os.environ.get("AGENT_LLM_EFFORT", "low"))
        llm._check_credentials()
        return llm

    def _check_credentials(self) -> None:
        if self.provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
            raise SystemExit(f"No ANTHROPIC_API_KEY in the environment or {ENV_FILE}.")
        if self.provider in ("openai", "azure"):
            if not os.environ.get("AGENT_LLM_BASE_URL"):
                raise SystemExit("Set AGENT_LLM_BASE_URL.")
            if not os.environ.get("AGENT_LLM_API_KEY") and self.provider == "azure":
                raise SystemExit("Set AGENT_LLM_API_KEY.")

    def describe(self) -> str:
        return f"{self.provider}:{self.model}"

    # ── one structured call ─────────────────────────────────────────────

    async def json_call(self, system: str, user: str, schema: dict, *, max_tokens: int = 4000) -> dict:
        if self.provider == "scripted":
            self.usage.add(Usage(1, 0, 0, 0))
            return _scripted_step(user)
        if self.provider == "anthropic":
            return await self._anthropic(system, user, schema, max_tokens)
        return await self._openai_compatible(system, user, schema, max_tokens)

    async def _anthropic(self, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        import anthropic

        client = _anthropic_client()
        # Claude Opus 5.5 always thinks; effort sets how much. The system
        # prompt is stable across every step, so it carries the cache marker.
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
        output_config = {"effort": self.effort, "format": {"type": "json_schema", "schema": schema}}
        try:
            resp = await client.messages.create(**kwargs, output_config=output_config)
        except TypeError:
            # Older SDKs don't know output_config by name; send it in the body.
            resp = await client.messages.create(**kwargs, extra_body={"output_config": output_config})
        except anthropic.APIStatusError:
            raise
        if resp.stop_reason == "refusal":
            raise RuntimeError("model refused the step")
        u = resp.usage
        self.usage.add(Usage(1, u.input_tokens + (getattr(u, "cache_creation_input_tokens", 0) or 0),
                             u.output_tokens, getattr(u, "cache_read_input_tokens", 0) or 0))
        text = next((b.text for b in resp.content if b.type == "text"), "")
        return json.loads(text)

    async def _openai_compatible(self, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        base = os.environ["AGENT_LLM_BASE_URL"].rstrip("/")
        key = os.environ.get("AGENT_LLM_API_KEY", "")
        if self.provider == "azure":
            version = os.environ.get("AGENT_LLM_AZURE_API_VERSION", "2024-10-21")
            url = f"{base}/openai/deployments/{self.model}/chat/completions?api-version={version}"
            headers = {"api-key": key}
        else:
            url = f"{base}/chat/completions"
            headers = {"Authorization": f"Bearer {key}"} if key else {}
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "agent_step", "strict": True, "schema": schema}},
        }
        async with httpx.AsyncClient(timeout=120) as http:
            r = await http.post(url, json=body, headers=headers)
            if r.status_code == 400:
                # Some servers only support JSON mode, not a schema.
                body["response_format"] = {"type": "json_object"}
                body["messages"][0]["content"] += "\nReply with one JSON object only."
                r = await http.post(url, json=body, headers=headers)
            r.raise_for_status()
            data = r.json()
        u = data.get("usage") or {}
        cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        self.usage.add(Usage(1, u.get("prompt_tokens", 0), u.get("completion_tokens", 0), cached))
        text = data["choices"][0]["message"]["content"] or ""
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end + 1] if start >= 0 else text)


_CLIENT = None


def _anthropic_client():
    global _CLIENT
    if _CLIENT is None:
        import anthropic
        _CLIENT = anthropic.AsyncAnthropic(max_retries=4)
    return _CLIENT


# ── plumbing test only ────────────────────────────────────────────────────
# A fixed rule-based plan (no model) that walks sign-up, promo and checkout,
# so the shop, logs and analysis can be tested before a model key is set.
# Its sessions are NOT agent data and are never used for detection results.

def _scripted_step(user: str) -> dict:
    import re

    url = re.search(r"^URL: (.*)$", user, re.M).group(1).strip()
    persona = json.loads(re.search(r"^Persona: (.*)$", user, re.M).group(1))
    last = re.search(r"^Last action result: (.*)$", user, re.M).group(1)
    elements = dict(re.findall(r"^\[(\d+)\] (.*)$", user.split("Elements:", 1)[1], re.M))
    signed_in = "Signed in as" in user

    def find(pattern: str) -> int:
        for idx, desc in elements.items():
            if re.search(pattern, desc, re.I):
                return int(idx)
        return -1

    def step(action, index=-1, text="", url_=""):
        return {"thought": "fixed plan", "action": action, "index": index, "text": text, "url": url_}

    def next_empty(fields):
        for label, value in fields:
            i = find(f'label="{re.escape(label)}')
            if i >= 0 and "text=" not in elements[str(i)]:
                return step("type", i, value)
        return None

    if "Order #" in user:
        return step("done", text="order placed")
    if url == "/" and not signed_in:
        return step("goto", url_="/signup")
    if url == "/signup":
        s = next_empty([("Full name", persona["name"]), ("Email", persona["email"]),
                        ("Password", "Trailhead2026x")])
        if s:
            return s
        if not last.startswith("selected"):
            return step("select", find(r"^select"), "United States")
        return step("click", find('text="Create account'))
    if url == "/account":
        return step("goto", url_="/promo")
    if url == "/promo":
        if "Code applied" in user or "already used" in user:
            return step("goto", url_="/product/6")
        s = next_empty([("Promo code", "WELCOME50")])
        return s or step("click", find('text="Redeem'))
    if url.startswith("/product/"):
        return step("click", find('text="Add to cart'))
    if url == "/cart":
        return step("click", find("href=/checkout"))
    if url == "/checkout":
        s = next_empty([("Street address", persona["address"]), ("City", persona["city"]),
                        ("Postal code", persona["zip"])])
        return s or step("click", find('text="Place order'))
    return step("goto", url_="/")
