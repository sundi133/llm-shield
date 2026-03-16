import asyncio
import json
import logging
import re
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from guardrails.base import BaseGuardrail
from core.models import GuardrailResult
from core.llm_backend import async_llm_call

logger = logging.getLogger(__name__)

_URL_PATTERN = re.compile(
    r'https?://[^\s<>\"\'\)\]\},;]+',
    re.IGNORECASE,
)

# Well-known domains — skip HTTP check entirely
_TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "wikipedia.org", "en.wikipedia.org",
    "youtube.com", "www.youtube.com",
    "microsoft.com", "www.microsoft.com", "learn.microsoft.com", "docs.microsoft.com",
    "apple.com", "www.apple.com", "developer.apple.com",
    "amazon.com", "www.amazon.com", "aws.amazon.com", "docs.aws.amazon.com",
    "twitter.com", "www.twitter.com", "x.com",
    "facebook.com", "www.facebook.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
    "medium.com",
    "npmjs.com", "www.npmjs.com",
    "pypi.org",
    "docs.python.org",
    "developer.mozilla.org", "mdn.io",
    "w3.org", "www.w3.org",
    "mozilla.org",
    "cloudflare.com",
    "gitlab.com",
    "bitbucket.org",
    "huggingface.co",
    "arxiv.org",
    "openai.com", "platform.openai.com",
    "anthropic.com", "docs.anthropic.com",
    "slack.com",
    "notion.so",
    "figma.com",
    "vercel.com",
    "netlify.com",
    "heroku.com",
    "digitalocean.com",
    "docker.com", "hub.docker.com",
}

_SYSTEM_PROMPT = (
    "You are a URL verification specialist. Given a list of URLs found in an AI-generated response, "
    "determine whether each URL is likely real (points to a well-known, existing domain and plausible path) "
    "or likely hallucinated/fabricated. Consider domain reputation, path structure, and common patterns "
    "of hallucinated URLs. Some URLs have already been checked via HTTP and returned errors — factor "
    "that into your assessment."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "urls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "likely_real": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["url", "likely_real", "reason"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["urls"],
    "additionalProperties": False,
}

_HEAD_TIMEOUT = 3.0  # seconds per URL
_MAX_CONCURRENT_CHECKS = 10
_MAX_URLS_FOR_LLM = 15


async def _http_head_check(url: str, client: httpx.AsyncClient) -> dict:
    """Perform an HTTP HEAD request to check if URL exists.

    Returns dict with url, status, reachable, and error fields.
    """
    try:
        resp = await client.head(url, follow_redirects=True, timeout=_HEAD_TIMEOUT)
        return {
            "url": url,
            "status": resp.status_code,
            "reachable": resp.status_code < 400,
            "error": None,
        }
    except httpx.TimeoutException:
        return {"url": url, "status": None, "reachable": False, "error": "timeout"}
    except httpx.ConnectError:
        return {"url": url, "status": None, "reachable": False, "error": "connection_failed"}
    except Exception as e:
        return {"url": url, "status": None, "reachable": False, "error": str(e)}


async def _batch_http_check(urls: list[str]) -> list[dict]:
    """Check multiple URLs concurrently with HTTP HEAD requests."""
    sem = asyncio.Semaphore(_MAX_CONCURRENT_CHECKS)

    async def _check(url: str, client: httpx.AsyncClient) -> dict:
        async with sem:
            return await _http_head_check(url, client)

    async with httpx.AsyncClient(
        headers={"User-Agent": "LLMShield-LinkChecker/1.0"},
        verify=False,  # some hallucinated domains have bad certs
    ) as client:
        tasks = [_check(url, client) for url in urls]
        return await asyncio.gather(*tasks)


def _is_trusted(url: str, trusted_domains: set[str]) -> bool:
    """Check if a URL belongs to a trusted domain."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in trusted_domains:
            return True
        for domain in trusted_domains:
            if hostname.endswith("." + domain):
                return True
        return False
    except Exception:
        return False


class HallucinatedLinksGuardrail(BaseGuardrail):
    """Detect potentially hallucinated or fabricated URLs in LLM output.

    Three-tier verification:
      1. Trusted domain allowlist — instant pass, no network call
      2. HTTP HEAD request — catches 404s, dead domains, connection failures
      3. LLM fallback — only for URLs that are reachable but still look suspicious
    """

    name = "hallucinated_links"
    tier = "slow"
    stage = "output"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        start = time.perf_counter()
        threshold = self.settings.get("threshold", 0.75)
        extra_trusted = set(self.settings.get("trusted_domains", []))
        trusted = _TRUSTED_DOMAINS | extra_trusted
        verify_http = self.settings.get("verify_http", True)

        # ── Step 1: extract URLs ──
        urls = _URL_PATTERN.findall(content)
        if not urls:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message="No URLs found in output",
                latency_ms=elapsed,
            )

        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        # ── Step 2: trusted domain filter ──
        trusted_urls = []
        non_trusted_urls = []
        for url in unique_urls:
            if _is_trusted(url, trusted):
                trusted_urls.append(url)
            else:
                non_trusted_urls.append(url)

        if not non_trusted_urls:
            elapsed = (time.perf_counter() - start) * 1000
            return GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name=self.name,
                message=f"All {len(unique_urls)} URLs are from trusted domains",
                details={
                    "total_urls": len(unique_urls),
                    "trusted": len(trusted_urls),
                    "http_checked": 0,
                    "sent_to_llm": 0,
                },
                latency_ms=elapsed,
            )

        # ── Step 3: HTTP HEAD check ──
        http_results = []
        dead_urls = []       # 404, connection failed, timeout
        reachable_urls = []  # 2xx/3xx — might still be hallucinated paths on real domains
        uncertain_urls = []  # couldn't determine

        if verify_http:
            http_results = await _batch_http_check(non_trusted_urls)
            for hr in http_results:
                if hr["reachable"]:
                    reachable_urls.append(hr)
                elif hr["error"] == "timeout":
                    # Timeout is ambiguous — could be slow server
                    uncertain_urls.append(hr)
                else:
                    dead_urls.append(hr)
        else:
            # Skip HTTP check, send all to LLM
            uncertain_urls = [{"url": u} for u in non_trusted_urls]

        # ── Step 4: LLM verification for uncertain URLs ──
        # Dead URLs are already flagged. Reachable URLs pass.
        # Only send uncertain ones (timeouts + if configured, reachable ones too) to LLM.
        needs_llm = [u["url"] for u in uncertain_urls]

        llm_hallucinated = []
        llm_results_raw = None

        if needs_llm:
            urls_for_llm = needs_llm[:_MAX_URLS_FOR_LLM]
            url_list = "\n".join(f"- {url}" for url in urls_for_llm)
            user_msg = f"Please verify the following URLs found in an AI response:\n\n{url_list}"

            messages = [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]

            try:
                response = await async_llm_call(
                    messages=messages,
                    max_tokens=512,
                    temperature=0,
                    response_format=_RESPONSE_SCHEMA,
                )
                raw = response["choices"][0]["message"]["content"]
                llm_results_raw = json.loads(raw)
                llm_hallucinated = [
                    u for u in llm_results_raw.get("urls", [])
                    if not u.get("likely_real", True)
                ]
            except Exception as e:
                logger.warning("LLM call failed for URL verification: %s", e)

        # ── Build final result ──
        elapsed = (time.perf_counter() - start) * 1000

        all_hallucinated = []

        # Dead URLs (HTTP 404, connection failed, DNS error)
        for hr in dead_urls:
            status_info = f"HTTP {hr['status']}" if hr["status"] else hr["error"]
            all_hallucinated.append({
                "url": hr["url"],
                "likely_real": False,
                "reason": f"URL unreachable ({status_info})",
                "source": "http_check",
            })

        # LLM-flagged URLs
        for lu in llm_hallucinated:
            all_hallucinated.append({
                "url": lu["url"],
                "likely_real": False,
                "reason": lu.get("reason", "Flagged by LLM verification"),
                "source": "llm",
            })

        details = {
            "total_urls": len(unique_urls),
            "trusted": len(trusted_urls),
            "http_checked": len(http_results),
            "dead_urls": len(dead_urls),
            "reachable_urls": len(reachable_urls),
            "sent_to_llm": len(needs_llm),
            "hallucinated": all_hallucinated,
        }
        if llm_results_raw:
            details["llm_results"] = llm_results_raw

        if all_hallucinated:
            hallucinated_list = ", ".join(h["url"] for h in all_hallucinated)
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"Hallucinated/dead URLs detected ({len(all_hallucinated)}): {hallucinated_list}",
                details=details,
                latency_ms=elapsed,
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message=f"All {len(unique_urls)} URLs verified ({len(trusted_urls)} trusted, {len(reachable_urls)} reachable, {len(needs_llm)} LLM-checked)",
            details=details,
            latency_ms=elapsed,
        )
