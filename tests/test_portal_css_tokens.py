"""Every CSS custom property the tenant portal uses must be defined in it.

An undefined ``var(--x)`` with no fallback resolves to nothing, so the element
silently renders uncoloured. That happened with ``--red`` (the portal's red is
``--danger``): the Board Report's blocked count, trend bars, top-threat counts
and "Missing" coverage list all lost their colour. A fallback such as
``var(--x, #f00)`` hides the gap but drifts from the theme, so it is not an
excuse to leave the token undefined either.
"""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "static" / "tenant.html").read_text()

# A declaration starts a line or follows "{" / ";" (inline styles, compact rules).
_DEFINED = set(re.findall(r"(?:^|[{;\s])(--[A-Za-z0-9_-]+)\s*:", HTML, re.M))
_DEFINED |= set(re.findall(r"setProperty\(\s*['\"](--[A-Za-z0-9_-]+)", HTML))
_USED = set(re.findall(r"var\(\s*(--[A-Za-z0-9_-]+)", HTML))


def test_scan_is_not_vacuous():
    assert len(_USED) >= 20, _USED
    assert {"--danger", "--warn", "--success", "--accent", "--text-muted"} <= _DEFINED


def test_every_used_token_is_defined():
    missing = sorted(_USED - _DEFINED)
    assert not missing, f"var() tokens used but never defined in tenant.html: {missing}"


def test_board_report_blocked_number_is_red():
    fn = HTML[HTML.index("document.getElementById('board-report-cards')"):]
    assert "var(--red)" not in HTML
    assert 'style="color:var(--danger);">${(s.blocked_count || 0)' in fn
