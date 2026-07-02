"""load_config must never crash-loop the data plane on a bad config file.

create_app() -> load_config() runs at boot. A corrupt or schema-invalid config
at CONFIG_PATH previously raised straight out of yaml.safe_load, so one bad
(e.g. partially-written) file would crash-loop every worker. load_config now
logs and falls back to built-in defaults, and still applies env-based auth so a
corrupt file can't silently disable authentication.

    PYTHONPATH=. pytest tests/test_config_load_resilience.py
"""

import pytest

import config.schema as schema_module
from config.schema import load_config, ShieldConfig


@pytest.fixture(autouse=True)
def _restore_global_config():
    """load_config() sets the module-level singleton config.schema.config;
    snapshot and restore it so these tests don't pollute others."""
    saved = schema_module.config
    yield
    schema_module.config = saved


def _write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return str(p)


def test_corrupt_yaml_falls_back_to_defaults(tmp_path):
    """Malformed YAML -> defaults, not an exception."""
    path = _write(tmp_path, "guardrails: [1, 2, 3\nrbac: }bad")  # unparseable
    cfg = load_config(path)
    assert isinstance(cfg, ShieldConfig)  # did not raise


def test_schema_invalid_config_falls_back(tmp_path):
    """Valid YAML but a guardrail value that isn't a mapping -> defaults."""
    path = _write(tmp_path, "guardrails:\n  mytool: not_a_mapping\n")
    cfg = load_config(path)
    assert isinstance(cfg, ShieldConfig)  # GuardrailConfig(**str) would TypeError


def test_missing_file_uses_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert isinstance(cfg, ShieldConfig)


def test_valid_config_still_loads(tmp_path):
    """Happy-path regression: a valid config parses normally."""
    path = _write(tmp_path, "guardrails:\n  toxicity:\n    enabled: true\n    action: block\n")
    cfg = load_config(path)
    assert "toxicity" in cfg.guardrails
    assert cfg.guardrails["toxicity"].action == "block"


def test_env_auth_applied_on_fallback(tmp_path, monkeypatch):
    """A corrupt file must NOT silently drop auth: SHIELD_AUTH_ENABLED still wins."""
    monkeypatch.setenv("SHIELD_AUTH_ENABLED", "true")
    monkeypatch.setenv("SHIELD_API_KEYS", "k-from-env")
    path = _write(tmp_path, "guardrails: [broken")  # corrupt -> fallback path
    cfg = load_config(path)
    assert cfg.auth.enabled is True
    assert "k-from-env" in cfg.auth.api_keys


def test_env_auth_applied_on_valid_config(tmp_path, monkeypatch):
    """Regression: env auth override still applies on the happy path."""
    monkeypatch.setenv("SHIELD_AUTH_ENABLED", "1")
    path = _write(tmp_path, "guardrails:\n  toxicity:\n    enabled: true\n")
    cfg = load_config(path)
    assert cfg.auth.enabled is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
