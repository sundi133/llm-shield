"""Rating core: ScanReport dict -> numeric 0-100 score (Phase 3 Task 1)."""

from mcp_registry.rating import score, RATING_VERSION, PENALTY


def _report(severity_counts, tools=1, resources=0, prompts=0):
    return {
        "counts": {"tools": tools, "resources": resources, "prompts": prompts},
        "severity_counts": {**{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}, **severity_counts},
        "verdict": "fail" if severity_counts else "pass",
    }


# ── test 1: a critical finding lands in the high-risk band ──
def test_critical_finding_is_high_risk():
    r = score(_report({"critical": 1}))
    assert r["score"] == 100 - PENALTY["critical"]  # 20
    assert r["band"] == "high-risk"
    assert any("critical" in x for x in r["reasons"])


# ── test 2: banding across severities ──
def test_band_progression():
    # bands: 90-100 clean, 70-89 minor, 40-69 review, 0-39 high-risk
    assert score(_report({"medium": 1}))["score"] == 92           # clean (>=90)
    assert score(_report({"medium": 1}))["band"] == "clean"
    assert score(_report({"high": 1}))["score"] == 75             # minor
    assert score(_report({"high": 1}))["band"] == "minor"
    assert score(_report({"high": 2}))["score"] == 50             # review
    assert score(_report({"high": 2}))["band"] == "review"
    assert score(_report({"critical": 1}))["band"] == "high-risk" # 20
    clean = score(_report({}))
    assert clean["score"] == 100 and clean["band"] == "clean"
    assert clean["reasons"] == ["no findings"]


# ── test 3: deterministic + floored + versioned ──
def test_deterministic_floored_versioned():
    rep = _report({"critical": 2, "high": 3})
    a, b = score(rep), score(dict(rep))
    assert a == b
    assert a["score"] == 0                # 100 - (160+75) floored at 0
    assert a["rating_version"] == RATING_VERSION


def test_score_never_negative():
    assert score(_report({"critical": 5}))["score"] == 0


# ── test 4: insufficient signal -> unrated (never 100) ──
def test_scan_failed_is_unrated():
    for bad in (None, {}, {"counts": None}):
        r = score(bad)
        assert r["score"] is None and r["band"] == "unrated"


def test_zero_surface_is_unrated_not_100():
    r = score(_report({}, tools=0, resources=0, prompts=0))
    assert r["score"] is None
    assert r["band"] == "unrated"
    assert "no tools" in r["reasons"][0]


def test_resources_or_prompts_count_as_surface():
    # a server exposing only resources is scannable -> not unrated
    r = score(_report({}, tools=0, resources=2, prompts=0))
    assert r["score"] == 100 and r["band"] == "clean"


def test_reasons_pluralize_and_order_high_to_low():
    r = score(_report({"critical": 1, "medium": 2}))
    assert r["reasons"][0] == "1 critical finding"
    assert r["reasons"][1] == "2 medium findings"


def test_missing_severity_counts_defaults_to_clean_when_surface_present():
    # a report with tools but no severity_counts key -> no penalty -> 100
    r = score({"counts": {"tools": 3, "resources": 0, "prompts": 0}})
    assert r["score"] == 100
