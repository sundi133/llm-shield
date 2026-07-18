"""Tests for the insecure_output guardrail (P0-1, OWASP LLM02).

Spec: docs/specs/insecure-output-guardrail.md — XSS/HTML injection, dangerous
markdown URI schemes, and SQL injection fragments in model output must be
detected (and optionally sanitized) before a downstream app renders them.
"""

import asyncio

from guardrails.output.insecure_output import InsecureOutputGuardrail


def _check(content, settings=None, action="block", enabled=True):
    g = InsecureOutputGuardrail()
    g._temp_config = {
        "enabled": enabled,
        "action": action,
        "settings": settings or {},
    }
    return asyncio.run(g.check(content))


def _categories(res):
    return set(d["category"] for d in (res.details or {}).get("detections", []))


# --- HTML/XSS injection ---

def test_script_tag_blocked():
    res = _check('Sure! <script>alert(document.cookie)</script>')
    assert res.passed is False
    assert res.action == "block"
    assert "html_injection" in _categories(res)


def test_img_onerror_handler_blocked():
    res = _check('<img src=x onerror=alert(1)>')
    assert res.passed is False
    assert "html_injection" in _categories(res)


def test_iframe_and_javascript_uri_blocked():
    res = _check('<iframe src="javascript:alert(1)"></iframe>')
    assert res.passed is False
    assert "html_injection" in _categories(res)


def test_data_html_uri_blocked():
    res = _check('<a href="data:text/html,<script>alert(1)</script>">click</a>')
    assert res.passed is False
    assert "html_injection" in _categories(res)


# --- Markdown injection ---

def test_markdown_javascript_link_blocked():
    res = _check("[click me](javascript:alert(1))")
    assert res.passed is False
    assert "markdown_injection" in _categories(res)


def test_markdown_reference_scheme_blocked():
    res = _check("[link]: javascript:alert(1)")
    assert res.passed is False
    assert "markdown_injection" in _categories(res)


def test_normal_markdown_link_passes():
    res = _check("See [our docs](https://example.com/docs) for details.")
    assert res.passed is True


# --- SQL injection ---

def test_union_select_blocked():
    res = _check("SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admins")
    assert res.passed is False
    assert "sql_injection" in _categories(res)


def test_tautology_blocked():
    res = _check("query: SELECT * FROM t WHERE user = '' OR '1'='1'")
    assert res.passed is False
    assert "sql_injection" in _categories(res)


def test_stacked_drop_table_blocked():
    res = _check("Robert'); DROP TABLE students;--")
    assert res.passed is False
    assert "sql_injection" in _categories(res)


def test_plain_select_passes():
    """Legitimate generated SQL without injection fragments must pass."""
    res = _check("SELECT id, name FROM customers WHERE region = ?")
    assert res.passed is True


# --- Safe content / defaults ---

def test_plain_text_passes():
    res = _check("The capital of France is Paris.")
    assert res.passed is True
    assert res.action == "pass"


def test_empty_content_passes():
    res = _check("")
    assert res.passed is True


def test_html_talk_without_markup_passes():
    res = _check("You should escape script tags and avoid inline event handlers.")
    assert res.passed is True


# --- Fenced code handling ---

def test_fenced_code_ignored_by_default():
    res = _check("Here is the fix:\n```html\n<script>alert(1)</script>\n```\nDone.")
    assert res.passed is True


def test_fenced_code_scanned_when_disabled():
    res = _check(
        "```html\n<script>alert(1)</script>\n```",
        settings={"ignore_fenced_code": False},
    )
    assert res.passed is False


def test_payload_outside_fence_still_detected():
    res = _check("```\nsafe code\n```\n<script>alert(1)</script>")
    assert res.passed is False


# --- Sanitize mode ---

def test_sanitize_escapes_script_tag():
    res = _check(
        "hello <script>alert(1)</script> world",
        settings={"sanitize": True, "ignore_fenced_code": False},
    )
    assert res.passed is False
    sanitized = res.details["sanitized_output"]
    assert "<script" not in sanitized
    assert "&lt;" in sanitized
    assert sanitized.startswith("hello ")


def test_sanitize_neutralizes_markdown_scheme():
    res = _check("[x](javascript:alert(1))", settings={"sanitize": True})
    sanitized = res.details["sanitized_output"]
    assert "javascript:" not in sanitized
    assert "blocked:" in sanitized


def test_sanitize_overlapping_spans_offsets_hold():
    """Event handler + javascript: URI overlap in one tag; both neutralized."""
    content = 'safe <a onclick=go() href="javascript:alert(1)">x</a> tail'
    res = _check(content, settings={"sanitize": True})
    sanitized = res.details["sanitized_output"]
    assert sanitized.startswith("safe ")
    assert sanitized.endswith(" tail")
    assert "<a onclick" not in sanitized


def test_no_sanitized_output_without_flag():
    res = _check("<script>alert(1)</script>")
    assert "sanitized_output" not in (res.details or {})


# --- Category configuration ---

def test_code_execution_off_by_default():
    res = _check('You can run eval("2+2") in the console.')
    assert res.passed is True


def test_code_execution_detected_when_enabled():
    res = _check(
        'os.system("rm -rf /") does the trick',
        settings={"detect_categories": ["code_execution"], "ignore_fenced_code": False},
    )
    assert res.passed is False
    assert _categories(res) == {"code_execution"}


def test_only_configured_categories_run():
    res = _check(
        "<script>alert(1)</script>",
        settings={"detect_categories": ["sql_injection"]},
    )
    assert res.passed is True


def test_unknown_category_ignored():
    res = _check("hello", settings={"detect_categories": ["nonexistent"]})
    assert res.passed is True


# --- Action propagation and detection metadata ---

def test_warn_action_propagated():
    res = _check("<script>x</script>", action="warn")
    assert res.passed is False
    assert res.action == "warn"


def test_detection_offsets_index_original_content():
    content = "before <script>alert(1)</script> after"
    res = _check(content)
    d = res.details["detections"][0]
    assert content[d["start"]:d["end"]] == d["match"]


def test_registry_discovers_guardrail():
    from guardrails.registry import get_guardrail

    g = get_guardrail("insecure_output")
    assert g is not None
    assert g.tier == "fast"
    assert g.stage == "output"
