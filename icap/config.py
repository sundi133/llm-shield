"""Configuration for the ICAP adapter, read once from the environment.

Env flags are the operator's only interface (§6 of the spec). Nothing here
touches Shield; PR 1 is protocol-only.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

# Destinations we inspect. Suffix-matched, so "openai.com" covers
# api.openai.com and chat.openai.com. Deliberately a list of AI providers
# rather than "everything": traffic we never see is traffic we can never leak,
# and this list is the sentence a works council reads.
DEFAULT_AI_HOSTS: tuple[str, ...] = (
    "openai.com",
    "anthropic.com",
    "claude.ai",
    "perplexity.ai",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
    "githubcopilot.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.groq.com",
    "api.x.ai",
    "openrouter.ai",
)

# Bodies above this are not screened (spec §7: "do not block what we did not
# read"). Bodies above HARD_BODY_CAP are not even drained -- the connection is
# closed, because a client streaming gigabytes at an inspection service is
# either broken or hostile.
DEFAULT_MAX_BODY = 1 * 1024 * 1024
HARD_BODY_CAP = 64 * 1024 * 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _read_secret(name: str) -> str:
    """Read a credential from `<NAME>_FILE` if present, else `<NAME>`.

    The file form is what a Docker or Kubernetes secret mount gives you, and it
    keeps the tenant key out of `docker inspect` and the process environment.
    """
    path = os.environ.get(name + "_FILE")
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    return os.environ.get(name, "").strip()


def _parse_cidrs(raw: str) -> tuple:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return tuple(nets)


@dataclass
class IcapConfig:
    """Adapter settings. Construct with `IcapConfig.from_env()` in production."""

    mode: str = "monitor"                 # monitor | enforce
    preview: int = 4096
    max_body: int = DEFAULT_MAX_BODY
    hard_body_cap: int = HARD_BODY_CAP
    options_ttl: int = 300
    ai_hosts: tuple[str, ...] = DEFAULT_AI_HOSTS
    allowed_clients: tuple = field(default_factory=lambda: _parse_cidrs("0.0.0.0/0,::/0"))
    # Payload of the ISTag header. Becomes the policy bundle version in PR 3;
    # until then it identifies the build, which is still what ISTag is for:
    # telling the SWG its cached verdicts are stale.
    version: str = "pr1"

    # Shield data plane. Tier 1 pulls its rule bundle from here; Tier 2 (PR 4)
    # screens against it.
    api_base: str = "https://api.guardrails.votal.ai"
    api_key: str = ""
    proxy_token: str = ""          # bearer for a fronting proxy (RunPod topology)
    bundle_poll_s: int = 300
    bundle_timeout_s: float = 10.0
    # v1 cannot rewrite request bodies (spec §5), so a `redact` rule resolves to
    # one of these. Default `pass`: a redact rule was not written to block, and
    # silently upgrading it to a block would surprise the operator.
    redact_fallback: str = "pass"
    # Ceiling on local rule evaluation. A tenant regex that cannot finish inside
    # this on an already-capped body is a broken pattern, not a verdict.
    scan_timeout_ms: int = 250

    @classmethod
    def from_env(cls) -> "IcapConfig":
        hosts_raw = os.environ.get("SHIELD_ICAP_AI_HOSTS", "")
        hosts = tuple(h.strip().lower() for h in hosts_raw.split(",") if h.strip()) or DEFAULT_AI_HOSTS
        return cls(
            mode="enforce" if os.environ.get("SHIELD_ICAP_MODE", "monitor").strip().lower() == "enforce" else "monitor",
            preview=_env_int("SHIELD_ICAP_PREVIEW", 4096),
            max_body=_env_int("SHIELD_ICAP_MAX_BODY", DEFAULT_MAX_BODY),
            options_ttl=_env_int("SHIELD_ICAP_OPTIONS_TTL", 300),
            ai_hosts=hosts,
            allowed_clients=_parse_cidrs(os.environ.get("SHIELD_ICAP_ALLOWED_CLIENTS", "0.0.0.0/0,::/0")),
            version=os.environ.get("SHIELD_ICAP_VERSION", "pr1"),
            api_base=os.environ.get("SHIELD_API_BASE", "https://api.guardrails.votal.ai").strip(),
            api_key=_read_secret("SHIELD_API_KEY"),
            proxy_token=_read_secret("SHIELD_PROXY_TOKEN"),
            bundle_poll_s=_env_int("SHIELD_ICAP_BUNDLE_POLL_S", 300),
            redact_fallback=(
                "block"
                if os.environ.get("SHIELD_ICAP_REDACT_FALLBACK", "pass").strip().lower() == "block"
                else "pass"
            ),
            scan_timeout_ms=_env_int("SHIELD_ICAP_SCAN_TIMEOUT_MS", 250),
        )

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def client_allowed(self, ip: str | None) -> bool:
        """Defense in depth for §5: port 1344 must only be reachable by the SWG.

        An unknown peer (no address on the transport) is refused rather than
        allowed -- the allowlist is a security control, so it fails closed.
        """
        if not self.allowed_clients:
            return True
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowed_clients)

    def is_ai_host(self, host: str | None) -> bool:
        """Suffix match on the inspected Host header, port stripped."""
        if not host:
            return False
        h = host.strip().lower()
        # Strip a port, taking care not to mangle a bracketed IPv6 literal.
        if h.startswith("["):
            h = h[1:].split("]", 1)[0]
        elif h.count(":") == 1:
            h = h.split(":", 1)[0]
        return any(h == entry or h.endswith("." + entry) for entry in self.ai_hosts)
