"""Offline guards for scripts/eval_adversarial_fp.py.

The eval itself talks to a live data plane (no endpoint in CI), so these tests
only validate the static corpus invariants and pure helpers — enough to catch a
malformed corpus or a broken percentile before someone runs the live gate.
"""
import importlib.util
import os

import pytest

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "eval_adversarial_fp.py",
)


def _load():
    spec = importlib.util.spec_from_file_location("eval_adversarial_fp", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mod = _load()


def test_corpus_shape_and_labels():
    assert mod.CORPUS, "corpus is empty"
    for entry in mod.CORPUS:
        group, prompt, expect_safe = entry
        assert isinstance(group, str) and group
        assert isinstance(prompt, str) and prompt.strip()
        assert isinstance(expect_safe, bool)
        # group prefix must agree with the label
        if group.startswith("benign"):
            assert expect_safe is True
        elif group == "attack":
            assert expect_safe is False
        else:
            pytest.fail(f"unknown group {group!r}")


def test_corpus_has_enough_coverage():
    benign = [c for c in mod.CORPUS if c[2]]
    attacks = [c for c in mod.CORPUS if not c[2]]
    # Spec floor: a meaningful FP rate needs a real benign set; recall needs attacks.
    assert len(benign) >= 40, f"only {len(benign)} benign prompts"
    assert len(attacks) >= 20, f"only {len(attacks)} attack prompts"
    # Agentic prompts (the regression target) must be represented.
    assert any(c[0] == "benign-meta" for c in mod.CORPUS)
    assert any(c[0] == "benign-action" for c in mod.CORPUS)


def test_corpus_prompts_unique():
    prompts = [c[1] for c in mod.CORPUS]
    dupes = {p for p in prompts if prompts.count(p) > 1}
    assert not dupes, f"duplicate prompts: {dupes}"


@pytest.mark.parametrize("values,p,expected", [
    ([], 50, 0.0),
    ([5], 95, 5),
    ([10, 20, 30, 40], 50, 20),
    ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95, 10),
    ([10, 20, 30, 40], 100, 40),
])
def test_percentile(values, p, expected):
    assert mod.percentile(values, p) == expected


def test_build_headers_includes_bearer_only_when_set(monkeypatch):
    monkeypatch.setenv("SHIELD_API_KEY", "k1")
    monkeypatch.delenv("SHIELD_AUTH_TOKEN", raising=False)
    h = mod.build_headers()
    assert h["X-API-Key"] == "k1"
    assert "Authorization" not in h

    monkeypatch.setenv("SHIELD_AUTH_TOKEN", "tok")
    h = mod.build_headers()
    assert h["Authorization"] == "Bearer tok"
