"""The DLP operator knobs are documented where a tenant looks for them
(spec: docs/spec-runtime-dlp-gaps.md, PR 7). A flag that exists only in code
is a flag nobody can turn."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

FLAGS = (
    "SHIELD_DLP_FULL_SCAN", "SHIELD_DLP_FAIL_CLOSED", "SHIELD_DLP_LLM_TIMEOUT_S",
    "SHIELD_DLP_CONFIDENCE_FLOOR", "SHIELD_DLP_ECHO_CHECK", "SHIELD_DLP_REGEX_TIMEOUT_MS",
    "SHIELD_TAINT_RECORD", "SHIELD_CHAT_REDACTION",
)
SETTINGS = ("judge_chunk_chars", "max_chunks", "llm_timeout_s", "confidence_floor",
            "skip_llm_when_floor_clean")
FIELDS = ("allowlist", "thresholds", "exact_match", "/v1/data-policies/exact-match/hash")


def test_every_dlp_flag_and_setting_is_documented():
    doc = (ROOT / "docs" / "tool-data-policies.md").read_text()
    for name in FLAGS + SETTINGS + FIELDS:
        assert name in doc, name


def test_every_documented_flag_exists_in_code():
    code = "\n".join(p.read_text() for p in
                     list((ROOT / "core").rglob("*.py")) + list((ROOT / "guardrails").rglob("*.py"))
                     + list((ROOT / "api").rglob("*.py")))
    for name in FLAGS:
        assert name in code, name


def test_the_yaml_carries_the_settings_with_the_documented_defaults():
    yaml = (ROOT / "config" / "default.yaml").read_text()
    block = yaml.split("tool_output_sanitization:")[1].split("\n  sensitive_action_confirmation:")[0]
    for key, val in (("judge_chunk_chars", "4000"), ("max_chunks", "8"), ("llm_timeout_s", "20"),
                     ("confidence_floor", "0.75"), ("skip_llm_when_floor_clean", "false")):
        assert re.search(rf"^\s+{key}:\s*{re.escape(val)}\s*$", block, re.M), key
