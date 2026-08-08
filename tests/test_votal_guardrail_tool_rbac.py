"""Tool-RBAC enforcement switch on the LiteLLM guardrail plugin.

`litellm` is not a declared dependency of this repo (the plugin ships with the
proxy, not with Shield). These used to `importorskip` and therefore never ran
in CI, which meant an authorization control had no coverage on the machine that
gates merges. The three litellm symbols the plugin touches are stubbed instead.
"""
import os

import pytest

from tests import _litellm_stub

_litellm_stub.install()

from votal_guardrail import VotalGuardrail  # noqa: E402


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("VOTAL_ENFORCE_TOOL_RBAC", raising=False)
    return monkeypatch


def test_enforces_tool_rbac_by_default(clean_env):
    """A denied tool call must block unless someone opts out explicitly."""
    assert VotalGuardrail().enforce_tool_rbac is True


@pytest.mark.parametrize("value", ["false", "False", "0", "no", "NO"])
def test_escape_hatch_restores_advisory_mode(clean_env, value):
    clean_env.setenv("VOTAL_ENFORCE_TOOL_RBAC", value)
    assert VotalGuardrail().enforce_tool_rbac is False


@pytest.mark.parametrize("value", ["true", "1", "yes", "anything-else"])
def test_only_explicit_falsey_values_disable(clean_env, value):
    """Don't let a typo silently turn an authorization control off."""
    clean_env.setenv("VOTAL_ENFORCE_TOOL_RBAC", value)
    assert VotalGuardrail().enforce_tool_rbac is True
