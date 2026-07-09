"""_perform_llm_validation in api/routes_classify_output.py.

Regression guard: this function previously awaited the SYNC llm_call with a
bare string as `messages`, which always raised (a dict isn't awaitable and a
string isn't a messages list) -- the broad except then rejected every
validation, so the llm_validation tool-policy feature never worked. Now it
must go through async_llm_call with a proper messages list and parse the
completion content.
"""

import pytest

from api import routes_classify_output


def _response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.asyncio
async def test_appropriate_verdict(monkeypatch):
    captured = {}

    async def fake_call(messages, max_tokens=10, temperature=0, **kwargs):
        captured["messages"] = messages
        return _response("APPROPRIATE: doctor may read patient records")

    monkeypatch.setattr(routes_classify_output, "async_llm_call", fake_call)

    result = await routes_classify_output._perform_llm_validation(
        "read_records", "doctor", {"patient_id": "p1"}, "records...", {}
    )

    assert result["is_appropriate"] is True
    assert result["confidence"] == 1.0
    # A real messages list reached the backend, not a bare string.
    assert isinstance(captured["messages"], list)
    assert captured["messages"][0]["role"] == "user"
    assert "read_records" in captured["messages"][0]["content"]


@pytest.mark.asyncio
async def test_inappropriate_verdict(monkeypatch):
    async def fake_call(messages, max_tokens=10, temperature=0, **kwargs):
        return _response("INAPPROPRIATE: role lacks access")

    monkeypatch.setattr(routes_classify_output, "async_llm_call", fake_call)

    result = await routes_classify_output._perform_llm_validation(
        "delete_records", "viewer", None, "output", {}
    )

    assert result["is_appropriate"] is False
    assert result["confidence"] == 0.0


@pytest.mark.asyncio
async def test_llm_error_fails_closed(monkeypatch):
    async def fake_call(messages, max_tokens=10, temperature=0, **kwargs):
        return {"error": {"message": "backend down"}}

    monkeypatch.setattr(routes_classify_output, "async_llm_call", fake_call)

    result = await routes_classify_output._perform_llm_validation(
        "read_records", "doctor", None, "output", {}
    )

    assert result["is_appropriate"] is False
    assert "backend down" in result["reason"]


@pytest.mark.asyncio
async def test_exception_fails_closed(monkeypatch):
    async def fake_call(messages, max_tokens=10, temperature=0, **kwargs):
        raise ConnectionError("unreachable")

    monkeypatch.setattr(routes_classify_output, "async_llm_call", fake_call)

    result = await routes_classify_output._perform_llm_validation(
        "read_records", "doctor", None, "output", {}
    )

    assert result["is_appropriate"] is False
    assert result["confidence"] == 0.0
