"""Guardrail cards on Input & Output Guardrails keep their controls aligned.

The action select, setting summary and switch used to size to their content,
so each card put them somewhere different and the switch was squeezed to
15-23px (it rendered as a broken knob). The button row also started 4px left
of the guardrail name.
"""

import re
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "static" / "tenant.html").read_text()


def _render_policy_stage():
    start = HTML.index("function renderPolicyStage(stage)")
    return HTML[start:HTML.index("function getSettingsSummary", start)]


def test_controls_use_fixed_columns():
    body = _render_policy_stage()
    assert 'class="guardrail-controls gr-controls-grid"' in body
    # The summary always occupies its column, even when a guardrail has none.
    assert '<div class="gr-summary">${summary || \'\'}</div>' in body
    assert re.search(r"\.guardrail-controls\.gr-controls-grid\s*\{[^}]*grid-template-columns:\s*96px 88px 36px", HTML)


def test_switch_cannot_shrink():
    assert re.search(r"\.guardrail-controls \.switch\s*\{\s*flex:\s*none;", HTML)


def test_button_row_lines_up_with_the_name():
    body = _render_policy_stage()
    assert 'class="gr-actions"' in body
    assert "padding-left:2.75rem" not in body
    # icon width + row gap, the same offset the name has
    assert re.search(r"\.gr-actions\s*\{[^}]*padding-left:\s*calc\(36px \+ 0\.75rem\)", HTML)
    assert "font-size:10px;padding:0.15rem 0.5rem" not in body


def test_cards_never_get_wider_than_the_screen():
    """`1fr` is minmax(auto, 1fr): the column grew to the card's min-content
    width (the three control columns plus padding), so on a phone each card
    ran past the right edge and its description was clipped."""
    assert re.search(r"\.policy-grid\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)", HTML)
    mobile = HTML[HTML.index(".guardrail-row { flex-wrap: wrap; }"):]
    mobile = mobile[:mobile.index("}\n  }") if "}\n  }" in mobile else 2000]
    assert "grid-template-columns: 96px minmax(0, 1fr) 36px" in mobile
    assert ".gr-actions, .gr-detail { padding-left: 0; }" in mobile
    assert ".gr-actions button.small { flex: 1 1 auto;" in mobile
