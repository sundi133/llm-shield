"""Sandbox egress gateway config (examples/sandbox/gateway/) — the L2 layer
from docs/spec-sandbox-guardrails.md (task 4).

What must hold (spec §5):
  * the shipped config registers VotalGuardrail on BOTH hooks (pre_call and
    post_call) with default_on: true, so the vanilla OpenAI client inside a
    sandbox is screened without knowing the guard exists;
  * the config ships fail-CLOSED (block_on_failure: true) and VotalGuardrail
    actually honors that key — LiteLLM guardrails default fail-open upstream;
  * the residual-risk statement ships verbatim in the README.

litellm is faked in sys.modules so votal_guardrail.py imports without the
proxy extra (same pattern as the faked modal SDK in test_sandbox_broker.py).
"""

from __future__ import annotations

import importlib
import re
import sys
import types
from pathlib import Path

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


@pytest.fixture
def votal_guardrail_module(monkeypatch):
    """Import votal_guardrail.py against a stub litellm (the proxy extra is
    deliberately not a test dependency)."""
    custom_guardrail = types.ModuleType("litellm.integrations.custom_guardrail")

    class CustomGuardrail:
        def __init__(self, **kwargs):
            pass

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
    monkeypatch.delenv("RUNPOD_TOKEN", raising=False)
    monkeypatch.delenv("SHIELD_API_TOKEN", raising=False)

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

    def test_no_config_at_all_defaults_fail_closed(
        self, votal_guardrail_module, monkeypatch
    ):
        g = _construct(votal_guardrail_module, monkeypatch)
        assert g.block_on_failure is True
