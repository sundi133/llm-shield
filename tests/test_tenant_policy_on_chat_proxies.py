"""A tenant's configured policies must be enforced on the chat proxies too.

Regression for a silent no-enforcement bug: ``/guardrails/input`` applied a
tenant's custom policies, but ``/v1/chat/completions`` and
``/v1/shield/chat/completions`` did not. Customers routing through the proxy got
only the default guardrails, so policies they configured in the portal were
never applied — with a 200 and a normal model reply as the only evidence.

The mechanism behind the bug: policy-driven guardrails read their settings from
the ``_request_configs`` contextvar. The proxies ran the pipeline without ever
setting it, so those guardrails executed against empty settings and passed.

These tests drive the *real* middleware (tenant resolved from ``X-API-Key``) and
the *real* guardrails — deterministic, non-LLM ones — so they fail if the
tenant-config wiring is removed from either proxy.
"""

from unittest.mock import patch

import pytest

from config.schema import AuthConfig, ShieldConfig
from core.models import GuardrailResult, PipelineResult

# Both guarded chat proxies. Every enforcement test runs against both, because
# the bug was independently present in each.
PROXIES = ["/v1/chat/completions", "/v1/shield/chat/completions"]

TENANT_ID = "bank-co"
API_KEY = "sk-bank-co-test"

# Deterministic, settings-driven guardrails: keyword_blocklist (fast/input) and
# competitor_mention (fast/output). Both read settings + action off the
# contextvar, which is exactly the wiring under test — and neither calls an LLM.
BLOCKED_KEYWORD = "supplier cost"
BLOCKED_COMPETITOR = "Globex"


def _tenant_config(**overrides) -> dict:
    cfg = {
        "input_guardrails": {
            "keyword_blocklist": {
                "enabled": True,
                "action": "block",
                "settings": {"keywords": [BLOCKED_KEYWORD], "case_insensitive": True},
            }
        },
        "output_guardrails": {
            "competitor_mention": {
                "enabled": True,
                "action": "block",
                "settings": {"competitors": [BLOCKED_COMPETITOR]},
            }
        },
    }
    cfg.update(overrides)
    return cfg


def _make_app(cfg=None):
    import config.schema as cs

    cfg = cfg or ShieldConfig(auth=AuthConfig(enabled=False))
    original = cs.config
    cs.config = cfg
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app

        app = create_app()
    return app, original


async def _noop_audit(*args, **kwargs):
    return None


def _fake_llm(content="here is the answer"):
    async def _call(*args, **kwargs):
        return {
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }

    return _call


class _Ctx:
    """Drives a proxy request with a tenant resolved by the real middleware."""

    def __init__(self, tenant_config, llm_reply="here is the answer"):
        self.tenant_config = tenant_config
        self.llm_reply = llm_reply

    def __enter__(self):
        from starlette.testclient import TestClient

        self.app, self.original = _make_app()
        self._patches = [
            # The real middleware path: X-API-Key -> (tenant_id, tenant_config).
            patch(
                "core.middleware._get_cached_tenant",
                return_value=(TENANT_ID, self.tenant_config),
            ),
            patch("api.routes_openai_compat._get_upstream_url", return_value=None),
            patch("api.routes_gateway._get_upstream_url", return_value=None),
            patch(
                "api.routes_openai_compat.async_llm_call",
                side_effect=_fake_llm(self.llm_reply),
            ),
            patch(
                "api.routes_gateway.async_llm_call",
                side_effect=_fake_llm(self.llm_reply),
            ),
            patch("api.routes_openai_compat.audit_logger.log", side_effect=_noop_audit),
            patch("api.routes_gateway.audit_logger.log", side_effect=_noop_audit),
        ]
        for p in self._patches:
            p.start()
        return TestClient(self.app)

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        import config.schema as cs

        cs.config = self.original
        # The tenant cache is keyed by api key and lives across tests.
        import core.middleware as mw

        mw._tenant_cache.clear()
        return False


def _post(client, path, message):
    return client.post(
        path,
        json={"model": "gpt-x", "messages": [{"role": "user", "content": message}]},
        headers={"X-API-Key": API_KEY},
    )


def _blocked(path, resp) -> bool:
    """Both proxies signal a block, but in their own response shapes.

    The OpenAI-compat endpoint must stay a valid OpenAI object, so it renders a
    block as a 200 ``content_filter`` refusal; the legacy gateway returns 403.
    """
    if path == "/v1/chat/completions":
        if resp.status_code != 200:
            return False
        data = resp.json()
        return (
            resp.headers.get("x-shield-blocked") == "true"
            or data.get("x_shield", {}).get("blocked") is True
            or data["choices"][0].get("finish_reason") == "content_filter"
        )
    return resp.status_code == 403 and resp.json().get("blocked") is True


# ── the reported bug ──────────────────────────────────────────────────────

@pytest.mark.parametrize("path", PROXIES)
def test_tenant_input_policy_blocks_on_proxy(path):
    """The repro: a tenant input policy blocked on /guardrails/input but not here."""
    with _Ctx(_tenant_config()) as client:
        resp = _post(client, path, f"our margin is 62% and {BLOCKED_KEYWORD} is 400 AED")
    assert _blocked(path, resp), f"{path} did not enforce the tenant input policy"


@pytest.mark.parametrize("path", PROXIES)
def test_tenant_output_policy_blocks_on_proxy(path):
    """Same gap on the output stage — the model's reply violates the policy."""
    with _Ctx(_tenant_config(), llm_reply=f"You should try {BLOCKED_COMPETITOR}.") as client:
        resp = _post(client, path, "who else offers this?")
    assert _blocked(path, resp), f"{path} did not enforce the tenant output policy"


@pytest.mark.parametrize("path", PROXIES)
def test_benign_message_still_passes(path):
    """The fix must not turn a configured tenant into a blanket block."""
    with _Ctx(_tenant_config()) as client:
        resp = _post(client, path, "what are your opening hours?")
    assert not _blocked(path, resp)


# ── parity: the drift guard ───────────────────────────────────────────────

@pytest.mark.parametrize("path", PROXIES)
def test_proxy_matches_guardrails_input_decision(path):
    """Same tenant + same message must decide the same on /guardrails/input.

    This is the regression that keeps the paths from drifting apart again.
    """
    message = f"our margin is 62% and {BLOCKED_KEYWORD} is 400 AED"
    with _Ctx(_tenant_config()) as client:
        direct = client.post(
            "/guardrails/input",
            json={"message": message},
            headers={"X-API-Key": API_KEY},
        )
        proxied = _post(client, path, message)

    assert direct.status_code == 200
    assert direct.json()["action"] == "block", "precondition: /guardrails/input blocks"
    assert _blocked(path, proxied), f"{path} disagreed with /guardrails/input"


# ── edge cases ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", PROXIES)
def test_no_tenant_falls_back_to_defaults(path):
    """No API key -> no tenant -> defaults only, exactly as before the fix."""
    with _Ctx(None) as client:
        resp = client.post(
            path,
            json={"model": "gpt-x", "messages": [{"role": "user", "content": f"{BLOCKED_KEYWORD} is 400 AED"}]},
        )
    assert not _blocked(path, resp)


@pytest.mark.parametrize("path", PROXIES)
def test_empty_stage_config_falls_back_to_defaults(path):
    """A tenant with no input_guardrails key must not break the proxy."""
    with _Ctx({"output_guardrails": {}}) as client:
        resp = _post(client, path, f"{BLOCKED_KEYWORD} is 400 AED")
    assert not _blocked(path, resp)


@pytest.mark.parametrize("path", PROXIES)
def test_tenant_disabled_guardrail_is_not_resurrected(path):
    """enabled=false must win.

    Specific to UNION mode: the guardrail is also in the stage defaults, and a
    guardrail absent from the request config falls through to the *global*
    config. Skipping it instead of recording enabled=false would silently turn
    back on something the tenant switched off.
    """
    cfg = _tenant_config()
    cfg["input_guardrails"]["keyword_blocklist"]["enabled"] = False
    with _Ctx(cfg) as client:
        resp = _post(client, path, f"{BLOCKED_KEYWORD} is 400 AED")
    assert not _blocked(path, resp)


@pytest.mark.parametrize("path", PROXIES)
def test_unknown_guardrail_name_is_skipped(path):
    """An unregistered name in the config must not 500 the request."""
    cfg = _tenant_config()
    cfg["input_guardrails"]["no_such_guardrail"] = {"enabled": True, "action": "block", "settings": {}}
    with _Ctx(cfg) as client:
        resp = _post(client, path, f"{BLOCKED_KEYWORD} is 400 AED")
    # Still enforces the *known* policy alongside it.
    assert _blocked(path, resp)


@pytest.mark.parametrize("path", PROXIES)
def test_monitor_mode_does_not_block(path):
    """Dry-run: findings are recorded, traffic is not stopped.

    Without this, shipping tenant-policy enforcement here would hard-block every
    tenant that was deliberately running a new policy in monitor mode.
    """
    with _Ctx(_tenant_config(policy_mode="monitor")) as client:
        resp = _post(client, path, f"{BLOCKED_KEYWORD} is 400 AED")
    assert not _blocked(path, resp), "monitor mode must not enforce"


@pytest.mark.parametrize("path", PROXIES)
def test_kill_switch_restores_previous_behavior(path, monkeypatch):
    """Escape hatch for an operator whose traffic breaks."""
    monkeypatch.setenv("SHIELD_DISABLE_TENANT_POLICY_ON_PROXY", "1")
    with _Ctx(_tenant_config()) as client:
        resp = _post(client, path, f"{BLOCKED_KEYWORD} is 400 AED")
    assert not _blocked(path, resp)


# ── the agentic chat endpoint had the identical gap ───────────────────────

AGENT_PATH = "/v1/shield/chat/agent"


def test_tenant_input_policy_blocks_on_agent_chat():
    """/v1/shield/chat/agent read tenant_config for tool RBAC only.

    Same bug as the two chat proxies, found while wiring them: it resolved the
    tenant config for the tool allowlist, then ran the input pipeline without
    it, so tenant input/output policies never applied here either.
    """
    with _Ctx(_tenant_config()) as client:
        with patch("api.routes_agent_chat._call_llm", side_effect=_fake_agent_llm()):
            resp = client.post(
                AGENT_PATH,
                json={"messages": [{"role": "user", "content": f"{BLOCKED_KEYWORD} is 400 AED"}]},
                headers={"X-API-Key": API_KEY},
            )
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True


def test_agent_chat_benign_message_passes():
    with _Ctx(_tenant_config()) as client:
        with patch("api.routes_agent_chat._call_llm", side_effect=_fake_agent_llm()):
            resp = client.post(
                AGENT_PATH,
                json={"messages": [{"role": "user", "content": "what are your hours?"}]},
                headers={"X-API-Key": API_KEY},
            )
    assert resp.status_code == 200


def _fake_agent_llm(content="here is the answer"):
    async def _call(*args, **kwargs):
        return {"choices": [{"message": {"content": content}}], "usage": {}}

    return _call


# ── streaming ─────────────────────────────────────────────────────────────

class _FakeStreamResponse:
    status_code = 200
    headers = {"content-type": "text/event-stream"}

    async def aiter_lines(self):
        for line in [
            'data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"try "},"finish_reason":null}]}',
            "",
            f'data: {{"id":"c1","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"{BLOCKED_COMPETITOR} instead"}},"finish_reason":null}}]}}',
            "",
            "data: [DONE]",
            "",
        ]:
            yield line

    async def aread(self):
        return b""


class _FakeStreamContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *exc):
        return False


class _FakeStreamClient:
    def __init__(self, *args, **kwargs):
        pass

    def stream(self, method, url, json):
        return _FakeStreamContext(_FakeStreamResponse())

    async def aclose(self):
        return None


@pytest.mark.parametrize("path", PROXIES)
def test_tenant_output_policy_applies_to_streaming(path):
    """Streaming must enforce the tenant's output policy too.

    The SSE generator runs after the request handler returns, so the tenant
    config has to be installed on the contextvar *inside* the generator — a
    detail easy to get wrong, and invisible in the non-streaming tests.
    """
    with _Ctx(_tenant_config()) as client:
        with (
            patch("api.routes_gateway._get_upstream_url", return_value="https://upstream.test"),
            patch("api.routes_gateway.httpx.AsyncClient", _FakeStreamClient),
            patch("api.routes_gateway._STREAM_FAST_CHECK_EVERY_CHARS", 1),
        ):
            with client.stream(
                "POST",
                path,
                json={
                    "model": "gpt-x",
                    "messages": [{"role": "user", "content": "who else?"}],
                    "stream": True,
                },
                headers={"X-API-Key": API_KEY},
            ) as resp:
                body = "".join(resp.iter_text())

    assert "content_filter" in body, "tenant output policy not enforced mid-stream"
    assert f'"content":"{BLOCKED_COMPETITOR} instead"' not in body


# ── the helper itself ─────────────────────────────────────────────────────

def test_union_keeps_defaults_replace_does_not():
    """UNION is a superset of REPLACE — the reason the proxies do not use REPLACE.

    A tenant naming a single guardrail must not thereby drop the stage's other
    guards on proxied traffic.
    """
    from core.tenant_pipeline import REPLACE, UNION, resolve_tenant_guardrails
    from guardrails.registry import get_by_stage

    tenant = {"keyword_blocklist": {"enabled": True, "action": "block", "settings": {}}}

    _, replaced = resolve_tenant_guardrails("input", tenant, {}, REPLACE)
    _, unioned = resolve_tenant_guardrails("input", tenant, {}, UNION)

    assert [g.name for g in replaced] == ["keyword_blocklist"]

    default_names = {g.name for g in get_by_stage("input")}
    union_names = {g.name for g in unioned}
    assert default_names.issubset(union_names)
    assert "keyword_blocklist" in union_names


def test_union_runs_a_shared_guardrail_only_once():
    """A guardrail in both the defaults and the tenant config must not double-run."""
    from core.tenant_pipeline import UNION, resolve_tenant_guardrails

    tenant = {"keyword_blocklist": {"enabled": True, "action": "block", "settings": {}}}
    _, guardrails = resolve_tenant_guardrails("input", tenant, {}, UNION)

    names = [g.name for g in guardrails]
    assert names.count("keyword_blocklist") == 1
    assert len(names) == len(set(names))


def test_tenant_settings_win_over_global_for_named_guardrail():
    """The tenant's settings/action are what land in the request config."""
    from core.tenant_pipeline import UNION, resolve_tenant_guardrails

    tenant = {
        "keyword_blocklist": {
            "enabled": True,
            "action": "warn",
            "settings": {"keywords": ["zzz"]},
        }
    }
    configs, _ = resolve_tenant_guardrails("input", tenant, {}, UNION)

    assert configs["keyword_blocklist"]["action"] == "warn"
    assert configs["keyword_blocklist"]["settings"]["keywords"] == ["zzz"]


def test_contextvar_is_reset_after_the_pipeline_runs():
    """No config may leak into a later request on the same worker."""
    import asyncio

    from core.tenant_pipeline import UNION, run_tenant_pipeline
    from guardrails.base import _request_configs

    tenant = {"keyword_blocklist": {"enabled": True, "action": "block", "settings": {"keywords": ["zzz"]}}}

    assert _request_configs.get() is None
    asyncio.run(run_tenant_pipeline("input", "hello", {}, tenant, mode=UNION))
    assert _request_configs.get() is None


def test_monitor_mode_marks_findings_unenforced():
    """A suppressed block is still visible as a would-be block."""
    from core.policy_mode import ENFORCE, MONITOR
    from core.tenant_pipeline import apply_mode_to_pipeline_result

    def _result():
        return PipelineResult(
            allowed=False,
            results=[
                GuardrailResult(
                    passed=False, action="block",
                    guardrail_name="keyword_blocklist", message="nope",
                )
            ],
        )

    enforced = apply_mode_to_pipeline_result(_result(), ENFORCE)
    assert enforced.allowed is False

    monitored = apply_mode_to_pipeline_result(_result(), MONITOR)
    assert monitored.allowed is True
    assert monitored.results[0].details["enforced"] is False
    assert monitored.results[0].details["would_block"] is True


def test_administrative_blocks_enforce_even_in_monitor_mode():
    """An operator kill action is not a policy finding — it still stops."""
    from core.policy_mode import MONITOR
    from core.tenant_pipeline import apply_mode_to_pipeline_result

    result = PipelineResult(
        allowed=False,
        results=[
            GuardrailResult(
                passed=False, action="block", guardrail_name="tool_killswitch",
                message="agent disabled", details={"administrative": True},
            )
        ],
    )
    assert apply_mode_to_pipeline_result(result, MONITOR).allowed is False
