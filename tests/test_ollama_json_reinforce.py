"""Ollama-only JSON reinforcement (GPU/vLLM path untouched)."""
from core.llm_backend import _reinforce_json_only, _build_ollama_payload, _build_payload

SCHEMA = {"type": "object", "properties": {"violates_policy": {"type": "boolean"}}}


def test_reinforce_appends_to_last_user_and_is_idempotent():
    msgs = [{"role": "user", "content": "hi"}]
    once = _reinforce_json_only(msgs)
    assert "ONLY the JSON object" in once[-1]["content"]
    twice = _reinforce_json_only(once)
    assert twice[-1]["content"].count("ONLY the JSON object") == 1  # idempotent
    assert msgs[0]["content"] == "hi"  # original not mutated


def test_ollama_payload_reinforces_only_with_response_format():
    m = [{"role": "user", "content": "evaluate"}]
    with_fmt = _build_ollama_payload(m, 200, 0, SCHEMA)
    assert "ONLY the JSON object" in with_fmt["messages"][-1]["content"]
    assert with_fmt["format"] == SCHEMA
    # no response_format (e.g. CSV guardrails) -> untouched
    without = _build_ollama_payload(m, 20, 0, None)
    assert without["messages"][-1]["content"] == "evaluate"


def test_vllm_payload_not_reinforced(monkeypatch):
    # default backend is vllm (not ollama) -> _build_payload takes the else branch
    monkeypatch.delenv("LLM_BACKEND_TYPE", raising=False)
    monkeypatch.delenv("ENABLE_LITELLM", raising=False)
    p = _build_payload([{"role": "user", "content": "evaluate"}], 200, 0, SCHEMA)
    assert p["messages"][-1]["content"] == "evaluate"          # GPU prompt untouched
    assert p["response_format"]["json_schema"]["strict"] is True  # still strict guided decoding
