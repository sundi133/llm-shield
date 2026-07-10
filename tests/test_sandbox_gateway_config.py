"""Sandbox egress gateway config (examples/sandbox/gateway/) — the L2 layer
from docs/spec-sandbox-guardrails.md (task 4).

What must hold (spec §5):
  * the shipped config registers VotalGuardrail on BOTH hooks (pre_call and
    post_call) with default_on: true, so the vanilla OpenAI client inside a
    sandbox is screened without knowing the guard exists;
  * the config ships fail-CLOSED (block_on_failure: true) and VotalGuardrail
    actually honors that key — LiteLLM guardrails default fail-open upstream;
  * a blocked tool call assembled at stream end FAILS the request by default
    (streaming_tool_rbac: enforce) instead of being merely logged;
  * VotalGuardrail refuses to boot without a configured Shield endpoint
    (no hardcoded fallback host);
  * the residual-risk statement ships verbatim in the README.

litellm is faked in sys.modules so votal_guardrail.py imports without the
proxy extra (same pattern as the faked modal SDK in test_sandbox_broker.py).
"""

from __future__ import annotations

import asyncio
import importlib
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
GATEWAY_DIR = REPO / "examples" / "sandbox" / "gateway"
CONFIG = GATEWAY_DIR / "config.yaml"
README = GATEWAY_DIR / "README.md"

# Spec §5: "must ship verbatim in the README".
RESIDUAL_RISK = (
    "On providers without guaranteed egress lockdown (E2B, Daytona today), "
    "untrusted code may make ungoverned read-only calls to third parties. "
    "It still cannot perform Shield-mediated side effects or obtain "
    "credentials. Close the gap with provider egress allowlisting: Modal "
    "(`block_network`/`cidr_allowlist`) and K8s Agent Sandbox (NetworkPolicy "
    "deny-by-default egress + allowlist to the gateway, CNI-dependent) both "
    "support the strong posture, so the L2 non-bypassability claim holds on "
    "either."
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


@pytest.fixture
def cfg() -> dict:
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


class TestConfig:
    def test_guard_registered_on_both_hooks_default_on(self, cfg):
        guards = {
            g["litellm_params"]["mode"]: g["litellm_params"]
            for g in cfg["guardrails"]
        }
        assert set(guards) == {"pre_call", "post_call"}
        for mode, params in guards.items():
            assert params["guardrail"] == "votal_guardrail.VotalGuardrail", mode
            assert params["default_on"] is True, mode

    def test_ships_fail_closed(self, cfg):
        assert cfg["votal_guardrail"]["block_on_failure"] is True
        assert cfg["votal_guardrail"]["streaming_tool_rbac"] == "enforce"

    def test_points_at_a_shield_data_plane(self, cfg):
        assert cfg["votal_guardrail"]["api_base"]


class TestReadme:
    def test_residual_risk_statement_verbatim(self):
        assert _norm(RESIDUAL_RISK) in _norm(README.read_text(encoding="utf-8"))

    def test_documents_the_fail_closed_trade(self):
        text = README.read_text(encoding="utf-8")
        assert "block_on_failure" in text
        assert "fail-open" in text  # the upstream default being overridden


# ── VotalGuardrail honors the config key ────────────────────────────


class GuardrailBlocked(Exception):
    """Stub of litellm's guardrail violation (name must contain 'guardrail'
    so the plugin's re-raise filters treat it as a passthrough)."""


@pytest.fixture
def votal_guardrail_module(monkeypatch):
    """Import votal_guardrail.py against a stub litellm (the proxy extra is
    deliberately not a test dependency)."""
    custom_guardrail = types.ModuleType("litellm.integrations.custom_guardrail")

    class CustomGuardrail:
        def __init__(self, **kwargs):
            pass

        def raise_passthrough_exception(
            self, violation_message="", request_data=None, detection_info=None
        ):
            raise GuardrailBlocked(violation_message)

    custom_guardrail.CustomGuardrail = CustomGuardrail
    proxy_types = types.ModuleType("litellm.proxy._types")
    proxy_types.UserAPIKeyAuth = type("UserAPIKeyAuth", (), {})
    caching = types.ModuleType("litellm.caching.caching")
    caching.DualCache = type("DualCache", (), {})

    fakes = {
        "litellm": types.ModuleType("litellm"),
        "litellm.integrations": types.ModuleType("litellm.integrations"),
        "litellm.integrations.custom_guardrail": custom_guardrail,
        "litellm.proxy": types.ModuleType("litellm.proxy"),
        "litellm.proxy._types": proxy_types,
        "litellm.caching": types.ModuleType("litellm.caching"),
        "litellm.caching.caching": caching,
    }
    for name, mod in fakes.items():
        monkeypatch.setitem(sys.modules, name, mod)
    for var in ("RUNPOD_TOKEN", "SHIELD_API_TOKEN", "SHIELD_API_BASE", "SHIELD_URL"):
        monkeypatch.delenv(var, raising=False)

    sys.modules.pop("votal_guardrail", None)
    yield importlib.import_module("votal_guardrail")
    sys.modules.pop("votal_guardrail", None)


def _construct(module, monkeypatch, config_path=None):
    argv = ["litellm"]
    if config_path is not None:
        argv += ["--config", str(config_path)]
    monkeypatch.setattr(sys, "argv", argv)
    return module.VotalGuardrail()


class TestVotalGuardrailFailPolicy:
    def test_shipped_sandbox_config_yields_fail_closed(
        self, votal_guardrail_module, monkeypatch, cfg
    ):
        g = _construct(votal_guardrail_module, monkeypatch, CONFIG)
        assert g.block_on_failure is True
        assert g.api_base == cfg["votal_guardrail"]["api_base"].rstrip("/")

    def test_explicit_false_opts_out(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        p = tmp_path / "config.yaml"
        p.write_text(
            yaml.safe_dump(
                {"votal_guardrail": {"api_base": "http://shield.test",
                                     "block_on_failure": False}}
            ),
            encoding="utf-8",
        )
        g = _construct(votal_guardrail_module, monkeypatch, p)
        assert g.block_on_failure is False

    def test_absent_key_defaults_fail_closed(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        p = tmp_path / "config.yaml"
        p.write_text(
            yaml.safe_dump({"votal_guardrail": {"api_base": "http://shield.test"}}),
            encoding="utf-8",
        )
        g = _construct(votal_guardrail_module, monkeypatch, p)
        assert g.block_on_failure is True

    def test_no_config_reads_env_and_defaults_fail_closed(
        self, votal_guardrail_module, monkeypatch
    ):
        monkeypatch.setenv("SHIELD_API_BASE", "http://shield.env/")
        g = _construct(votal_guardrail_module, monkeypatch)
        assert g.block_on_failure is True
        assert g.streaming_tool_rbac == "enforce"
        assert g.api_base == "http://shield.env"

    def test_no_endpoint_anywhere_refuses_to_boot(
        self, votal_guardrail_module, monkeypatch
    ):
        with pytest.raises(ValueError, match="no Shield endpoint"):
            _construct(votal_guardrail_module, monkeypatch)


# ── streaming tool RBAC is enforced, not just logged ─────────────────


def _tool_call_chunk():
    fn = SimpleNamespace(name="send_email", arguments='{"to": "x@y"}')
    dtc = SimpleNamespace(index=0, id="t1", function=fn)
    delta = SimpleNamespace(content=None, tool_calls=[dtc])
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


class _StubResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _StubClient:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    async def post(self, url, json=None, headers=None):
        self.calls.append((url, json))
        return self.resp


def _drain_stream(guard) -> list:
    async def go():
        chunks = []
        agen = guard.async_post_call_streaming_iterator_hook(
            None,
            _one_chunk_stream(),
            {"metadata": {"agent_key": "billing-bot", "user_role": "agent"}},
        )
        async for chunk in agen:
            chunks.append(chunk)
        return chunks

    return asyncio.run(go())


async def _one_chunk_stream():
    yield _tool_call_chunk()


def _guard_with(votal_guardrail_module, monkeypatch, tmp_path, resp, **votal_cfg):
    votal_cfg.setdefault("api_base", "http://shield.test")
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump({"votal_guardrail": votal_cfg}), encoding="utf-8")
    g = _construct(votal_guardrail_module, monkeypatch, p)
    g.client = _StubClient(resp)
    return g


BLOCKED_CHECK = {
    "allowed": False,
    "guardrail_results": [{"passed": False, "message": "role denied"}],
}


class TestStreamingToolRbac:
    def test_blocked_tool_call_fails_the_request(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        g = _guard_with(
            votal_guardrail_module, monkeypatch, tmp_path, _StubResp(200, BLOCKED_CHECK)
        )
        with pytest.raises(GuardrailBlocked, match="send_email"):
            _drain_stream(g)
        # the check actually went to Shield's tool/check with the tool context
        url, body = g.client.calls[-1]
        assert url.endswith("/v1/shield/tool/check")
        assert body["tool_name"] == "send_email"

    def test_log_mode_restores_audit_only(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        g = _guard_with(
            votal_guardrail_module, monkeypatch, tmp_path,
            _StubResp(200, BLOCKED_CHECK), streaming_tool_rbac="log",
        )
        chunks = _drain_stream(g)  # no raise
        assert len(chunks) == 1

    def test_allowed_tool_call_streams_through(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        g = _guard_with(
            votal_guardrail_module, monkeypatch, tmp_path,
            _StubResp(200, {"allowed": True, "guardrail_results": []}),
        )
        chunks = _drain_stream(g)
        assert len(chunks) == 1

    def test_check_failure_fails_closed(
        self, votal_guardrail_module, monkeypatch, tmp_path
    ):
        g = _guard_with(
            votal_guardrail_module, monkeypatch, tmp_path, _StubResp(503, {})
        )
        with pytest.raises(GuardrailBlocked, match="failed"):
            _drain_stream(g)
