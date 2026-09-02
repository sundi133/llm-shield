"""Configuration for the ICAP adapter, read once from the environment.

Env flags are the operator's only interface (§6 of the spec).
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
    # Web apps. These are where employees actually paste things, and several
    # do not share a domain with the vendor's API: chatgpt.com is not
    # openai.com, and missing it means missing most ChatGPT usage.
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "grok.com",
    "deepseek.com",
    "meta.ai",
    "poe.com",
    # APIs.
    "openai.com",
    "anthropic.com",
    "generativelanguage.googleapis.com",
    "githubcopilot.com",
    "api.cohere.ai",
    "mistral.ai",
    "api.groq.com",
    "api.x.ai",
    "openrouter.ai",
)

# Never inspected, and never even routed to the proxy. Categories where
# decryption is a legal problem rather than a technical one, plus the client
# certificate endpoints that break outright under interception. Operators
# extend this list; they should not have to think of it first.
DEFAULT_BYPASS_HOSTS: tuple[str, ...] = (
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "paypal.com",
    "workday.com",
    "adp.com",
    "okta.com",
    "onelogin.com",
    "duosecurity.com",
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


def _host_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    parsed = tuple(h.strip().lower() for h in raw.split(",") if h.strip())
    return parsed or default


def _api_base(raw: str) -> str:
    """Normalise the data plane URL, upgrading plaintext to TLS.

    `http://api.guardrails.votal.ai` answers 301 to https. Following that
    redirect would mean putting the tenant key on the wire in plaintext first,
    and httpx does not follow redirects by default anyway, so the bundle fetch
    would fail with a confusing parse error. Upgrade it here and say so.
    """
    base = (raw or "").strip().rstrip("/")
    if base.startswith("http://"):
        upgraded = "https://" + base[len("http://"):]
        import logging

        logging.getLogger("shield.icap").warning(
            "SHIELD_API_BASE was http://; using %s instead. The tenant key must "
            "never traverse plaintext.", upgraded,
        )
        return upgraded
    return base


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
    # Fallback payload for the ISTag header, used until a policy bundle
    # loads. Once one has, PolicyCache.version supplies the bundle version.
    version: str = "pr1"

    # Shield data plane. Tier 1 pulls its rule bundle from here; Tier 2
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

    # Tier 2. Off the request path by default: a cloud screen measures 14-20s,
    # which no ICAP transaction can absorb.
    sync_screen: bool = False
    screen_timeout_s: float = 30.0
    telemetry_queue: int = 1000
    telemetry_workers: int = 4
    # Only has teeth in sync mode, where the operator has deliberately put
    # Shield on the request path. In the default async mode, Shield being
    # unreachable degrades Tier 2 to nothing and never blocks browsing.
    fail_open: bool = False

    # PAC generation (mode A, bundled Squid). `pac_proxy` is Squid's address as
    # the BROWSER sees it, not the ICAP port.
    pac_proxy: str = "127.0.0.1:3128"
    bypass_hosts: tuple[str, ...] = DEFAULT_BYPASS_HOSTS

    @classmethod
    def from_env(cls) -> "IcapConfig":
        return cls(
            mode="enforce" if os.environ.get("SHIELD_ICAP_MODE", "monitor").strip().lower() == "enforce" else "monitor",
            preview=_env_int("SHIELD_ICAP_PREVIEW", 4096),
            max_body=_env_int("SHIELD_ICAP_MAX_BODY", DEFAULT_MAX_BODY),
            options_ttl=_env_int("SHIELD_ICAP_OPTIONS_TTL", 300),
            ai_hosts=_host_list("SHIELD_ICAP_AI_HOSTS", DEFAULT_AI_HOSTS),
            allowed_clients=_parse_cidrs(os.environ.get("SHIELD_ICAP_ALLOWED_CLIENTS", "0.0.0.0/0,::/0")),
            version=os.environ.get("SHIELD_ICAP_VERSION", "pr1"),
            api_base=_api_base(os.environ.get("SHIELD_API_BASE", "https://api.guardrails.votal.ai")),
            api_key=_read_secret("SHIELD_API_KEY"),
            proxy_token=_read_secret("SHIELD_PROXY_TOKEN"),
            bundle_poll_s=_env_int("SHIELD_ICAP_BUNDLE_POLL_S", 300),
            redact_fallback=(
                "block"
                if os.environ.get("SHIELD_ICAP_REDACT_FALLBACK", "pass").strip().lower() == "block"
                else "pass"
            ),
            scan_timeout_ms=_env_int("SHIELD_ICAP_SCAN_TIMEOUT_MS", 250),
            sync_screen=_env_bool("SHIELD_ICAP_SYNC_SCREEN", False),
            screen_timeout_s=float(_env_int("SHIELD_ICAP_SCREEN_TIMEOUT_S", 30)),
            telemetry_queue=_env_int("SHIELD_ICAP_TELEMETRY_QUEUE", 1000),
            telemetry_workers=max(1, _env_int("SHIELD_ICAP_TELEMETRY_WORKERS", 4)),
            fail_open=_env_bool("SHIELD_ICAP_FAIL_OPEN", False),
            pac_proxy=os.environ.get("SHIELD_ICAP_PAC_PROXY", "127.0.0.1:3128").strip(),
            bypass_hosts=_host_list("SHIELD_ICAP_BYPASS_HOSTS", DEFAULT_BYPASS_HOSTS),
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
