"""Sandbox egress gateway config (examples/sandbox/gateway/) — the L2 layer
from docs/spec-sandbox-guardrails.md (task 4).

The gateway is a LiteLLM proxy running the (unmodified) votal_guardrail.py
plugin in the customer's trusted plane. What must hold (spec §5):
  * the shipped config registers VotalGuardrail on BOTH hooks (pre_call and
    post_call) with default_on: true, so the vanilla OpenAI client inside a
    sandbox is screened without knowing the guard exists;
  * the config points at a Shield data plane;
  * the residual-risk statement ships verbatim in the README.

This example does NOT modify votal_guardrail.py (it is identical to main),
so it must not set config knobs the plugin does not read — the plugin is
fail-closed by default and its streaming tool RBAC is audit-only.
``test_no_over_promised_knobs`` guards against re-introducing dead keys.
"""

from __future__ import annotations

import re
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

    def test_points_at_a_shield_data_plane(self, cfg):
        assert cfg["votal_guardrail"]["api_base"]

    def test_no_over_promised_knobs(self, cfg):
        # votal_guardrail.py is used unmodified (identical to main); it does
        # not read these keys, so the config must not advertise them.
        votal_cfg = cfg["votal_guardrail"]
        assert "block_on_failure" not in votal_cfg
        assert "streaming_tool_rbac" not in votal_cfg


class TestReadme:
    def test_residual_risk_statement_verbatim(self):
        assert _norm(RESIDUAL_RISK) in _norm(README.read_text(encoding="utf-8"))
