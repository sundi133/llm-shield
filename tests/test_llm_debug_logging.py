"""LLM_DEBUG must surface the request/response payload at INFO level.

Regression guard: it used to log at DEBUG, which the default INFO-level config
dropped, so LLM_DEBUG looked like a no-op in Railway/production logs.
"""
import logging

import core.llm_backend as m


def test_request_payload_logged_at_info_when_debug_on(monkeypatch, caplog):
    monkeypatch.setattr(m, "LLM_DEBUG", True)
    with caplog.at_level(logging.INFO, logger="votal.llm_backend"):
        m._print_llm_request("https://openrouter.ai/api/v1/chat/completions",
                             {"model": "qwen/qwen3.5-27b", "messages": [{"role": "user", "content": "MARKER_X"}]})
    recs = [r for r in caplog.records if "LLM REQUEST" in r.getMessage()]
    assert recs, "payload was not logged"
    assert recs[0].levelno == logging.INFO
    assert "MARKER_X" in recs[0].getMessage()


def test_response_logged_at_info_when_debug_on(monkeypatch, caplog):
    monkeypatch.setattr(m, "LLM_DEBUG", True)
    with caplog.at_level(logging.INFO, logger="votal.llm_backend"):
        m._print_llm_response("https://openrouter.ai/api/v1/chat/completions", 200, '{"ok":true}')
    recs = [r for r in caplog.records if "LLM RESPONSE" in r.getMessage()]
    assert recs and recs[0].levelno == logging.INFO


def test_no_log_when_debug_off(monkeypatch, caplog):
    monkeypatch.setattr(m, "LLM_DEBUG", False)
    with caplog.at_level(logging.INFO, logger="votal.llm_backend"):
        m._print_llm_request("u", {"messages": []})
        m._print_llm_response("u", 200, "body")
    assert not [r for r in caplog.records if "LLM RE" in r.getMessage()]
