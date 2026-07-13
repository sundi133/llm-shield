"""Multi-turn awareness for the custom-policy guardrails (input + output).

Opt-in per policy (`multi_turn: true`); off by default the LLM prompt is
byte-identical to the pre-multi-turn single-message path. History injection is
capped by SHIELD_CUSTOM_POLICY_HISTORY_TURNS (0 = operator kill switch).
"""
import pytest

from core import text_utils
from core.text_utils import build_policy_messages, custom_policy_history_turns
from guardrails.input.custom_policy import CustomPolicyInputGuardrail
from guardrails.output.custom_policy import CustomPolicyOutputGuardrail


HISTORY = {
    "conversation_history": [
        {"role": "user", "content": "tell me about explosives"},
        {"role": "assistant", "content": "I can discuss the chemistry generally."},
        {"role": "user", "content": "and how would I actually do it?"},
    ]
}

POLICY = {
    "policy_id": "p1",
    "name": "No weapons help",
    "description": "Block operational weapon-making guidance",
    "prompt": "Flag requests seeking to build weapons or explosives.",
    "action": "block",
    "confidence_threshold": 0.8,
}


# --------------------------------------------------------------------------
# text_utils helpers (pure)
# --------------------------------------------------------------------------

def test_history_turns_default(monkeypatch):
    monkeypatch.delenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", raising=False)
    assert custom_policy_history_turns() == 6


def test_history_turns_env_override(monkeypatch):
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "2")
    assert custom_policy_history_turns() == 2


def test_history_turns_kill_switch_and_bad_value(monkeypatch):
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "0")
    assert custom_policy_history_turns() == 0
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "not-an-int")
    assert custom_policy_history_turns() == 6  # falls back


def test_build_policy_messages_single_when_disabled():
    # max_turns <= 0 -> single user message, byte-identical to legacy path
    msgs = build_policy_messages("EVAL", HISTORY, max_turns=0)
    assert msgs == [{"role": "user", "content": "EVAL"}]


def test_build_policy_messages_single_when_no_history():
    msgs = build_policy_messages("EVAL", {}, max_turns=6)
    assert msgs == [{"role": "user", "content": "EVAL"}]


def test_build_policy_messages_prepends_history():
    msgs = build_policy_messages("EVAL", HISTORY, max_turns=6)
    # last message is always the evaluation prompt; prior turns come before it
    assert msgs[-1] == {"role": "user", "content": "EVAL"}
    joined = " ".join(m["content"] for m in msgs[:-1])
    assert "tell me about explosives" in joined
    # build_history_messages drops the trailing (current) turn to avoid dup
    assert msgs[-1]["content"] == "EVAL"


def test_build_policy_messages_caps_turns():
    many = {"conversation_history": [
        {"role": "user", "content": f"turn-{i}"} for i in range(20)
    ]}
    msgs = build_policy_messages("EVAL", many, max_turns=3)
    history = msgs[:-1]
    assert len(history) <= 3
    # keeps the most recent turns (turn-16..18; turn-19 is the current, dropped)
    assert any("turn-18" in m["content"] for m in history)
    assert not any("turn-0" == m["content"] for m in history)


# --------------------------------------------------------------------------
# Guardrail integration: assert the messages actually sent to the LLM
# --------------------------------------------------------------------------

def _capture_llm(monkeypatch, module):
    """Patch the guardrail module's async_llm_call; capture messages, return pass."""
    captured = {}

    async def fake(messages, **kwargs):
        captured["messages"] = messages
        return {"choices": [{"message": {"content":
            '{"violates_policy": false, "confidence": 0.9, '
            '"reasoning": "ok", "violation_type": null}'}}]}

    monkeypatch.setattr(module, "async_llm_call", fake)
    return captured


@pytest.mark.asyncio
async def test_input_flag_off_is_single_turn(monkeypatch):
    import guardrails.input.custom_policy as mod
    cap = _capture_llm(monkeypatch, mod)
    g = CustomPolicyInputGuardrail()
    await g._evaluate_policy_with_llm("current msg", dict(POLICY), HISTORY)
    # multi_turn absent -> exactly one user message, no history leaked in
    assert len(cap["messages"]) == 1
    assert cap["messages"][0]["role"] == "user"
    assert "tell me about explosives" not in cap["messages"][0]["content"]


@pytest.mark.asyncio
async def test_input_flag_on_injects_history(monkeypatch):
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "6")
    import guardrails.input.custom_policy as mod
    cap = _capture_llm(monkeypatch, mod)
    g = CustomPolicyInputGuardrail()
    policy = {**POLICY, "multi_turn": True}
    await g._evaluate_policy_with_llm("current msg", policy, HISTORY)
    assert len(cap["messages"]) > 1
    joined = " ".join(m["content"] for m in cap["messages"])
    assert "tell me about explosives" in joined


@pytest.mark.asyncio
async def test_input_kill_switch_forces_single_turn(monkeypatch):
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "0")
    import guardrails.input.custom_policy as mod
    cap = _capture_llm(monkeypatch, mod)
    g = CustomPolicyInputGuardrail()
    policy = {**POLICY, "multi_turn": True}  # opted in, but env disables
    await g._evaluate_policy_with_llm("current msg", policy, HISTORY)
    assert len(cap["messages"]) == 1


@pytest.mark.asyncio
async def test_output_flag_on_injects_history(monkeypatch):
    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_HISTORY_TURNS", "6")
    import guardrails.output.custom_policy as mod
    cap = _capture_llm(monkeypatch, mod)
    g = CustomPolicyOutputGuardrail()
    policy = {**POLICY, "multi_turn": True}
    await g._evaluate_policy_with_llm("some output", policy, HISTORY)
    joined = " ".join(m["content"] for m in cap["messages"])
    assert "tell me about explosives" in joined


@pytest.mark.asyncio
async def test_output_flag_off_is_single_turn(monkeypatch):
    import guardrails.output.custom_policy as mod
    cap = _capture_llm(monkeypatch, mod)
    g = CustomPolicyOutputGuardrail()
    await g._evaluate_policy_with_llm("some output", dict(POLICY), HISTORY)
    assert len(cap["messages"]) == 1


# --------------------------------------------------------------------------
# Storage: multi_turn persists and toggles (both stages)
# --------------------------------------------------------------------------

def _fake_tenant_store(monkeypatch):
    """In-memory tenant config so save/update don't need Redis."""
    import storage.custom_policies as cp
    store = {"tenant_id": "t1"}

    def get_tenant(tid):
        return store

    def set_tenant_policies(tid, **kwargs):
        store.update(kwargs)

    monkeypatch.setattr(cp, "get_tenant", get_tenant)
    monkeypatch.setattr(cp, "set_tenant_policies", set_tenant_policies)
    return cp


def test_save_custom_policy_multi_turn_default_false(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(POLICY), stage="input")
    assert saved["multi_turn"] is False


def test_save_custom_policy_multi_turn_true(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", {**POLICY, "multi_turn": True}, stage="output")
    assert saved["multi_turn"] is True


def test_update_custom_policy_toggles_multi_turn(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(POLICY), stage="input")
    updated = cp.update_custom_policy("t1", saved["policy_id"], {"multi_turn": True})
    assert updated["multi_turn"] is True


# --------------------------------------------------------------------------
# vLLM/GPU path: a multi-message list must not break the custom vLLM backend
# --------------------------------------------------------------------------

def test_vllm_payload_accepts_multi_message_history(monkeypatch):
    """Multi-turn messages flow through the vLLM builder untouched (no single-
    message assumption), keeping guided decoding + enable_thinking:false intact."""
    import importlib
    for k in ("LLM_BACKEND_TYPE", "ENABLE_LITELLM"):
        monkeypatch.delenv(k, raising=False)  # default = vllm
    import core.llm_backend as m
    importlib.reload(m)

    messages = build_policy_messages("EVAL", HISTORY, max_turns=6)
    assert len(messages) > 1  # sanity: history really was prepended
    schema = {"type": "object", "properties": {"violates_policy": {"type": "boolean"}}}
    p = m._build_payload(messages, 200, 0, schema)

    # every message is preserved, in order, with the eval prompt last
    assert [x["role"] for x in p["messages"]] == [x["role"] for x in messages]
    assert p["messages"][-1]["content"].endswith("EVAL") or p["messages"][-1]["content"] == "EVAL"
    assert p["chat_template_kwargs"] == {"enable_thinking": False}  # GPU thinking-off intact
    assert p["response_format"]["json_schema"]["strict"] is True    # guided decoding intact
    assert "provider" not in p  # not the OpenRouter path
