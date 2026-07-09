"""SHIELD_GUARD_MODEL_MODE=votal (default) | nemotron | both for core/llm_backend.py.

Covers: default mode is byte-identical to the pre-existing single-backend
behavior, the mode only applies to guard-classification calls (guardrail_name
set) so the gateway's proxied user chat traffic is never rerouted or
duplicated, nemotron mode routes to NEMOTRON_BACKEND_URL with a minimal
OpenAI-compatible payload, both mode calls both backends concurrently and
OR-combines verdicts only for guardrails with a registered verdict polarity
(true=SAFE guardrails like tone_enforcement must not be naively OR-merged),
fail-fast startup validation of malformed config, and fail-open when only the
secondary backend errors. No network -- transports are stubbed.
"""

import pytest

from core import llm_backend


def _messages():
    return [
        {"role": "system", "content": "You are a guardrail."},
        {"role": "user", "content": "hello"},
    ]


# adversarial_detection: registered CSV verdict, true=UNSAFE polarity.
_GUARD = "adversarial_detection"


def _clear_guard_mode_env(monkeypatch):
    for var in (
        "SHIELD_GUARD_MODEL_MODE",
        "SHIELD_GUARD_MODEL_PRIMARY",
        "NEMOTRON_BACKEND_URL",
        "NEMOTRON_MODEL_NAME",
        "NEMOTRON_BACKEND_API_KEY",
        "LLM_BACKEND_TYPE",
        "LLM_BACKEND_URL",
        "LLM_MODEL_NAME",
        "ENABLE_LITELLM",
    ):
        monkeypatch.delenv(var, raising=False)


class _Resp:
    status_code = 200
    text = "{}"

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _StubSession:
    """Routes by URL so primary/secondary calls in 'both' mode get distinct bodies."""

    def __init__(self, body_by_url=None, default_body=None, raise_for=None):
        self.calls = []
        self._body_by_url = body_by_url or {}
        self._default_body = default_body
        self._raise_for = raise_for or set()

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url in self._raise_for:
            raise ConnectionError(f"unreachable: {url}")
        return _Resp(self._body_by_url.get(url, self._default_body))


class _StubAsyncClient:
    def __init__(self, body_by_url=None, default_body=None, raise_for=None):
        self.calls = []
        self._body_by_url = body_by_url or {}
        self._default_body = default_body
        self._raise_for = raise_for or set()

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url in self._raise_for:
            raise ConnectionError(f"unreachable: {url}")
        return _Resp(self._body_by_url.get(url, self._default_body))


_VOTAL_URL = "http://127.0.0.1:8000/v1/chat/completions"
_NEMOTRON_URL = "https://nemotron.example.com/v1/chat/completions"

_VOTAL_SAFE = {"choices": [{"message": {"content": "false,none,0.95"}}]}
_VOTAL_UNSAFE = {"choices": [{"message": {"content": "true,jailbreak,0.98"}}]}
_NEMOTRON_SAFE = {"choices": [{"message": {"content": "false,none,0.90"}}]}
_NEMOTRON_UNSAFE = {"choices": [{"message": {"content": "true,jailbreak,0.93"}}]}


def _set_both(monkeypatch):
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "both")
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("NEMOTRON_BACKEND_URL", "https://nemotron.example.com")


# ---------------------------------------------------------------------------
# Default mode (unset / "votal") is byte-identical to the original behavior
# ---------------------------------------------------------------------------


def test_default_mode_is_votal(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    assert llm_backend._get_guard_model_mode() == "votal"
    assert llm_backend._resolve_targets("votal") == ["votal"]


def test_llm_call_unset_mode_unchanged(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")

    session = _StubSession(default_body={"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages(), guardrail_name=_GUARD)

    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == _VOTAL_URL
    assert "_secondary_model" not in result


@pytest.mark.asyncio
async def test_async_llm_call_unset_mode_unchanged(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")

    client = _StubAsyncClient(default_body=dict(_VOTAL_SAFE))
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    assert len(client.calls) == 1
    assert result["_timing"]["server_url"] == "http://127.0.0.1:8000"
    assert "guard_model_mode" not in result["_timing"]
    assert "_secondary_model" not in result


# ---------------------------------------------------------------------------
# Scope: calls WITHOUT a guardrail_name (gateway user completions, codegen)
# always stay on the votal path, whatever the mode -- user chat traffic must
# never be rerouted to a safety classifier or duplicated to a second backend.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_guardrail_name_ignores_nemotron_mode(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotron")
    monkeypatch.setenv("NEMOTRON_BACKEND_URL", "https://nemotron.example.com")
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")

    client = _StubAsyncClient(default_body={"choices": [{"message": {"content": "hi"}}]})
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages())  # no guardrail_name

    assert len(client.calls) == 1
    assert client.calls[0][0] == _VOTAL_URL
    assert "_secondary_model" not in result


@pytest.mark.asyncio
async def test_no_guardrail_name_ignores_both_mode(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(default_body={"choices": [{"message": {"content": "hi"}}]})
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages())  # no guardrail_name

    called_urls = [c[0] for c in client.calls]
    assert called_urls == [_VOTAL_URL]  # never duplicated to the secondary
    assert "_secondary_model" not in result


def test_sync_no_guardrail_name_ignores_mode(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    session = _StubSession(default_body={"choices": [{"message": {"content": "hi"}}]})
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages())  # no guardrail_name

    assert [c[0] for c in session.calls] == [_VOTAL_URL]
    assert "_secondary_model" not in result


# ---------------------------------------------------------------------------
# mode=nemotron -- single-model swap
# ---------------------------------------------------------------------------


def test_nemotron_mode_requires_backend_url(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotron")

    with pytest.raises(RuntimeError, match="NEMOTRON_BACKEND_URL"):
        llm_backend.llm_call(_messages(), guardrail_name=_GUARD)


def test_nemotron_mode_routes_to_nemotron_backend(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotron")
    monkeypatch.setenv("NEMOTRON_BACKEND_URL", "https://nemotron.example.com")
    monkeypatch.setenv("NEMOTRON_MODEL_NAME", "nemotron-content-safety-4b")
    monkeypatch.setenv("NEMOTRON_BACKEND_API_KEY", "sk-nim")

    session = _StubSession(default_body=dict(_NEMOTRON_SAFE))
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages(), guardrail_name=_GUARD)

    url, kwargs = session.calls[0]
    assert url == _NEMOTRON_URL
    assert kwargs["json"]["model"] == "nemotron-content-safety-4b"
    assert kwargs["headers"] == {"Authorization": "Bearer sk-nim"}
    # No vLLM-specific extras -- hosting platform isn't resolved yet.
    assert "chat_template_kwargs" not in kwargs["json"]
    assert result["choices"][0]["message"]["content"] == "false,none,0.90"


@pytest.mark.asyncio
async def test_async_nemotron_mode_routes_to_nemotron_backend(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotron")
    monkeypatch.setenv("NEMOTRON_BACKEND_URL", "https://nemotron.example.com")

    client = _StubAsyncClient(default_body=dict(_NEMOTRON_SAFE))
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    url, _ = client.calls[0]
    assert url == _NEMOTRON_URL
    assert result["_timing"]["guard_model_mode"] == "nemotron"


def test_nemotron_payload_has_no_vllm_extras(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    payload = llm_backend._build_nemotron_payload(_messages(), 20, 0, None)
    assert "chat_template_kwargs" not in payload
    assert "/no_think" not in payload["messages"][0]["content"]
    assert payload["max_tokens"] == 20


# ---------------------------------------------------------------------------
# mode=both -- concurrent dual call + polarity-aware OR-combine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_both_mode_calls_both_backends_concurrently(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE), _NEMOTRON_URL: dict(_NEMOTRON_SAFE)}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    called_urls = {c[0] for c in client.calls}
    assert called_urls == {_VOTAL_URL, _NEMOTRON_URL}
    assert result["_timing"]["guard_model_mode"] == "both"
    assert result["_timing"]["primary_target"] == "votal"
    assert result["_secondary_model"]["target"] == "nemotron"
    assert result["_secondary_model"]["merged"] is True


@pytest.mark.asyncio
async def test_both_mode_or_logic_secondary_flags_unsafe(monkeypatch):
    """Primary (votal) says safe, secondary (nemotron) flags unsafe -- OR logic blocks."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE), _NEMOTRON_URL: dict(_NEMOTRON_UNSAFE)}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    # Downstream guardrail parsing sees the flagging model's own verdict.
    assert result["choices"][0]["message"]["content"] == "true,jailbreak,0.93"


@pytest.mark.asyncio
async def test_both_mode_both_flag_prefers_primary(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_UNSAFE), _NEMOTRON_URL: dict(_NEMOTRON_UNSAFE)}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    assert result["choices"][0]["message"]["content"] == "true,jailbreak,0.98"  # votal's own


@pytest.mark.asyncio
async def test_both_mode_neither_flags_returns_primary(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE), _NEMOTRON_URL: dict(_NEMOTRON_SAFE)}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    assert result["choices"][0]["message"]["content"] == "false,none,0.95"  # votal's own


@pytest.mark.asyncio
async def test_both_mode_primary_override(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_PRIMARY", "nemotron")

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE), _NEMOTRON_URL: dict(_NEMOTRON_SAFE)}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    assert result["_timing"]["primary_target"] == "nemotron"
    assert result["_secondary_model"]["target"] == "votal"


@pytest.mark.asyncio
async def test_both_mode_secondary_failure_fails_open(monkeypatch):
    """Secondary backend errors -- primary result still returned, no exception."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE)},
        raise_for={_NEMOTRON_URL},
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)

    assert result["choices"][0]["message"]["content"] == "false,none,0.95"
    assert result["_secondary_model"]["error"] is not None
    assert result["_secondary_model"]["merged"] is False


@pytest.mark.asyncio
async def test_both_mode_primary_failure_propagates(monkeypatch):
    """Primary backend errors -- existing per-guardrail fail-open (in the
    guardrail's own try/except) still applies; this call must raise, not
    silently substitute the secondary as if nothing happened."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    client = _StubAsyncClient(
        body_by_url={_NEMOTRON_URL: dict(_NEMOTRON_SAFE)},
        raise_for={_VOTAL_URL},
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    with pytest.raises(ConnectionError):
        await llm_backend.async_llm_call(_messages(), guardrail_name=_GUARD)


def test_both_mode_sync_secondary_failure_fails_open(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    session = _StubSession(
        body_by_url={_VOTAL_URL: dict(_VOTAL_SAFE)},
        raise_for={_NEMOTRON_URL},
    )
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages(), guardrail_name=_GUARD)

    assert result["choices"][0]["message"]["content"] == "false,none,0.95"
    assert result["_secondary_model"]["error"] is not None


# ---------------------------------------------------------------------------
# Malformed configuration: call-time raise (for guard calls) + fail-fast
# startup validation, so a config typo can't silently disable guardrails.
# ---------------------------------------------------------------------------


def test_invalid_mode_raises(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "bogus")
    with pytest.raises(RuntimeError, match="SHIELD_GUARD_MODEL_MODE"):
        llm_backend.llm_call(_messages(), guardrail_name=_GUARD)


def test_invalid_primary_raises(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "both")
    monkeypatch.setenv("SHIELD_GUARD_MODEL_PRIMARY", "bogus")
    with pytest.raises(RuntimeError, match="SHIELD_GUARD_MODEL_PRIMARY"):
        llm_backend.llm_call(_messages(), guardrail_name=_GUARD)


def test_validate_config_ok_by_default(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    llm_backend.validate_guard_model_config()  # must not raise


def test_validate_config_rejects_bad_mode(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "bogus")
    with pytest.raises(RuntimeError, match="SHIELD_GUARD_MODEL_MODE"):
        llm_backend.validate_guard_model_config()


def test_validate_config_rejects_missing_nemotron_url(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotron")
    with pytest.raises(RuntimeError, match="NEMOTRON_BACKEND_URL"):
        llm_backend.validate_guard_model_config()


def test_validate_config_rejects_both_without_url(monkeypatch):
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "both")
    with pytest.raises(RuntimeError, match="NEMOTRON_BACKEND_URL"):
        llm_backend.validate_guard_model_config()


def test_app_boot_fails_fast_on_bad_mode(monkeypatch):
    """create_app must crash loudly on a typo'd mode, not boot with all LLM
    guardrails silently failing open at call time."""
    _clear_guard_mode_env(monkeypatch)
    monkeypatch.setenv("SHIELD_GUARD_MODEL_MODE", "nemotorn")  # typo
    # create_app() -> load_config() mutates the config.schema.config
    # singleton before validation raises; restore it after.
    import config.schema as cs
    original = cs.config
    try:
        from core.app import create_app
        with pytest.raises(RuntimeError, match="SHIELD_GUARD_MODEL_MODE"):
            create_app()
    finally:
        cs.config = original


# ---------------------------------------------------------------------------
# Verdict registry: polarity-aware reads; unknown guardrails never merge.
# ---------------------------------------------------------------------------


def test_verdict_unsafe_true_means_unsafe_polarity():
    assert llm_backend._verdict_unsafe("adversarial_detection", "true,jailbreak,0.9") is True
    assert llm_backend._verdict_unsafe("adversarial_detection", "false,none,0.9") is False
    assert llm_backend._verdict_unsafe("toxicity", "true,0.9,hate,high") is True


def test_verdict_unsafe_true_means_safe_polarity():
    # tone_enforcement: 'compliant,detected_tone,severity' -- true = SAFE.
    assert llm_backend._verdict_unsafe("tone_enforcement", "true,professional,none") is False
    assert llm_backend._verdict_unsafe("tone_enforcement", "false,sarcastic,high") is True
    # topic_restriction: 'related,topic1,...' -- true = SAFE.
    assert llm_backend._verdict_unsafe("topic_restriction", "true,insurance,claims") is False
    assert llm_backend._verdict_unsafe("topic_restriction", "false,poetry") is True
    # topic_enforcement / factual_grounding: same inverted polarity.
    assert llm_backend._verdict_unsafe("topic_enforcement", "false,poetry:false:0.95") is True
    assert llm_backend._verdict_unsafe("factual_grounding", "true,0.9,") is False


def test_verdict_unsafe_json_violates_policy():
    assert llm_backend._verdict_unsafe("custom_policy_input", '{"violates_policy": true}') is True
    assert llm_backend._verdict_unsafe("custom_policy_input", '{"violates_policy": false}') is False
    assert llm_backend._verdict_unsafe("role_based_policy", '{"violates_policy": true, "confidence": 0.9}') is True


def test_verdict_unsafe_none_for_unregistered_guardrail():
    # hallucinated_links (multi-line per-URL rows) and language_detection
    # (bare ISO code) are deliberately NOT registered -- never merged.
    assert llm_backend._verdict_unsafe("hallucinated_links", "true,real,ok") is None
    assert llm_backend._verdict_unsafe("language_detection", "en") is None
    assert llm_backend._verdict_unsafe(None, "true,x,0.9") is None


def test_verdict_unsafe_none_for_shape_mismatch():
    multiline = "http://a.com,true,reachable\nhttp://b.com,false,dead link"
    assert llm_backend._verdict_unsafe("adversarial_detection", multiline) is None
    assert llm_backend._verdict_unsafe("custom_policy_input", "not json at all") is None


@pytest.mark.asyncio
async def test_both_mode_inverted_polarity_blocks_correctly(monkeypatch):
    """tone_enforcement: primary says compliant=false (violation), secondary
    says compliant=true. The old naive OR-merge would have returned the
    secondary's 'true' as the flagged verdict -- masking the violation. The
    polarity-aware merge must keep the primary's violation."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    primary_violation = {"choices": [{"message": {"content": "false,sarcastic,high"}}]}
    secondary_compliant = {"choices": [{"message": {"content": "true,professional,none"}}]}
    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: primary_violation, _NEMOTRON_URL: secondary_compliant}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name="tone_enforcement")

    assert result["choices"][0]["message"]["content"] == "false,sarcastic,high"
    assert result["_secondary_model"]["merged"] is True


@pytest.mark.asyncio
async def test_both_mode_inverted_polarity_secondary_catches_violation(monkeypatch):
    """tone_enforcement: primary compliant, secondary flags a violation
    (compliant=false) -- OR logic must surface the secondary's violation."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    primary_compliant = {"choices": [{"message": {"content": "true,professional,none"}}]}
    secondary_violation = {"choices": [{"message": {"content": "false,aggressive,high"}}]}
    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: primary_compliant, _NEMOTRON_URL: secondary_violation}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name="tone_enforcement")

    assert result["choices"][0]["message"]["content"] == "false,aggressive,high"


@pytest.mark.asyncio
async def test_both_mode_unregistered_guardrail_shadow_logs_only(monkeypatch):
    """hallucinated_links isn't in the verdict registry -- both models are
    called, but the primary's decision is returned untouched."""
    _clear_guard_mode_env(monkeypatch)
    _set_both(monkeypatch)

    primary_body = {
        "choices": [{"message": {"content": "http://a.com,true,reachable\nhttp://b.com,false,dead"}}]
    }
    secondary_body = {
        "choices": [{"message": {"content": "http://a.com,false,dead\nhttp://b.com,true,reachable"}}]
    }
    client = _StubAsyncClient(
        body_by_url={_VOTAL_URL: primary_body, _NEMOTRON_URL: secondary_body}
    )
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages(), guardrail_name="hallucinated_links")

    assert result["choices"][0]["message"]["content"] == primary_body["choices"][0]["message"]["content"]
    assert result["_secondary_model"]["merged"] is False
    assert result["_secondary_model"]["raw"] == secondary_body["choices"][0]["message"]["content"]


def test_registry_covers_only_known_guardrail_names():
    """Every registry key must correspond to a real guardrail name -- a stale
    entry would silently never merge (shadow-only), hiding a coverage gap."""
    from guardrails.registry import list_guardrails
    known = {g.name for g in list_guardrails()}
    for name in llm_backend._GUARD_VERDICT_REGISTRY:
        assert name in known, f"registry entry {name!r} is not a discovered guardrail"
