"""The device agent load test's pure parts (R6). Main CI job: no mitmproxy,
psutil or websockets. Spec: docs/specs/device-agent-load-test.md, section 8.
"""
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LT = ROOT / "packages" / "votal-device-agent" / "loadtest"
sys.path.insert(0, str(LT))

import load  # noqa: E402
import report as rep  # noqa: E402


# ── statistics ────────────────────────────────────────────────────────

def test_percentiles_match_a_known_series():
    xs = list(range(1, 11))
    assert rep.percentile(xs, 50) == 5.5
    assert rep.percentile(xs, 95) == pytest.approx(9.55)
    assert rep.percentile(xs, 99) == pytest.approx(9.91)
    assert rep.percentile([7], 95) == 7 and rep.percentile([], 50) is None


def test_added_latency_is_paired_and_skips_gaps():
    assert rep.added([(12, 10), (30, 5), (None, 4), (8, None)]) == [2, 25]


def test_summarize_a_class():
    samples = [{"proxied_ms": 15, "direct_ms": 10, "outcome": "ok"},
               {"proxied_ms": 30, "direct_ms": 10, "outcome": "ok", "ttfb_proxied_ms": 40, "ttfb_direct_ms": 10},
               {"outcome": "blocked", "direct_ms": 9},
               {"error": "timeout", "outcome": "proxy_error"}]
    s = rep.summarize(samples)
    assert (s["count"], s["errors"]) == (4, 1)
    assert s["added_p50_ms"] == 12.5 and s["ttfb_delta_p95_ms"] == 30
    assert s["outcomes"] == {"ok": 2, "blocked": 1, "proxy_error": 1}
    t = rep.summarize([{"proxied_ms": 3, "direct_ms": 1, "identical": True},
                       {"proxied_ms": 4, "direct_ms": 1, "identical": False}])
    assert t["bytes_identical"] is False


def test_resources_and_audit_headroom():
    samples = [{"t": i, "cpu": c, "rss_mb": 50 + i, "threads": 8} for i, c in enumerate([10, 20, 30])]
    r = rep.resources(samples)
    assert r["agent_cpu_mean_pct"] == 20 and r["agent_rss_peak_mb"] == 52 and r["agent_rss_growth_mb"] == 2
    assert rep.resources([]) == {}
    assert rep.audit_headroom_pct(600, 3600) == 25.0 and rep.audit_headroom_pct(1, 0) is None


# ── budgets ───────────────────────────────────────────────────────────

def _report(**over):
    r = {"meta": {"profile": "t", "model": "fake", "hardware": "apple_silicon"},
         "classes": {"prompt_s": {"count": 3, "errors": 0, "added_p95_ms": 50.0},
                     "tunnel": {"count": 1, "errors": 0, "bytes_identical": True}},
         "resources": {}, "queues": {}, "failures": {"proxy": 0}, "valid": True}
    r.update(over)
    return r


@pytest.mark.parametrize("limit,expected", [(50, True), (49.99, False)])
def test_max_budget_at_its_boundary(limit, expected):
    rows = rep.grade(_report(), [{"name": "short_prompt_added_p95_ms", "max": limit}])
    assert rows[0]["pass"] is expected and rows[0]["measured"] == 50.0


def test_equals_budgets_and_unmeasured_and_invalid():
    rows = rep.grade(_report(), [{"name": "proxy_failures", "equals": 0},
                                 {"name": "tunnel_bytes_identical", "equals": True},
                                 {"name": "ws_frame_added_p95_ms", "max": 50}])
    assert [r["pass"] for r in rows] == [True, True, None]           # nothing measured: not graded
    rows = rep.grade(_report(failures={"proxy": 2}), [{"name": "proxy_failures", "equals": 0}])
    assert rows[0]["pass"] is False
    rows = rep.grade(_report(valid=False), [{"name": "proxy_failures", "equals": 0}])
    assert rows[0]["pass"] is None                                   # an invalid run grades nothing


def test_only_enforced_failures_fail_the_run():
    rows = rep.grade(_report(), [{"name": "short_prompt_added_p95_ms", "max": 10, "enforce": False},
                                 {"name": "proxy_failures", "equals": 0}])
    assert rep.enforced_failures(rows) == []
    rows = rep.grade(_report(), [{"name": "short_prompt_added_p95_ms", "max": 10}])
    assert [r["name"] for r in rep.enforced_failures(rows)] == ["short_prompt_added_p95_ms"]


# ── profiles ──────────────────────────────────────────────────────────

BASE = {"name": "x", "duration_s": 10, "tabs": 2, "mix": {"prompt_s": 100},
        "budgets": [{"name": "proxy_failures", "equals": 0}]}


@pytest.mark.parametrize("bad,needle", [
    ({**BASE, "turbo": 1}, "unknown keys"),
    ({**BASE, "mix": {}}, "non-empty"),
    ({**BASE, "mix": {"prompt_s": 60, "ws": 30}}, "sum to 90"),
    ({**BASE, "mix": {"telepathy": 100}}, "unknown classes"),
    ({**BASE, "tabs": 0}, "tabs"),
    ({**BASE, "budgets": [{"name": "vibes", "max": 1}]}, "budgets[0]"),
    ({**BASE, "budgets": [{"name": "proxy_failures", "max": 1, "equals": 0}]}, "exactly one"),
    ({k: v for k, v in BASE.items() if k != "mix"}, "missing keys"),
])
def test_bad_profiles_are_refused(bad, needle):
    with pytest.raises(rep.ProfileError) as e:
        rep.load_profile(bad)
    assert needle in str(e.value)


def test_shipped_profiles_load():
    for name in ("smoke", "poc", "saturate"):
        p = rep.load_profile(LT / "profiles" / f"{name}.json")
        assert p["name"] == name
    smoke = rep.load_profile(LT / "profiles" / "smoke.json")
    enforced = {b["name"] for b in smoke["budgets"] if b.get("enforce", True)}
    assert enforced == {"proxy_failures", "tunnel_bytes_identical", "short_prompt_added_p95_ms"}


# ── report ────────────────────────────────────────────────────────────

def test_report_schema_and_markdown():
    r = _report()
    r["budgets"] = rep.grade(r, [{"name": "proxy_failures", "equals": 0},
                                 {"name": "short_prompt_added_p95_ms", "max": 10, "enforce": False}])
    assert rep.validate_report(r) == []
    md = rep.render_markdown(r)
    assert "| proxy_failures | = 0 | 0 | pass |" in md
    assert "| short_prompt_added_p95_ms | <= 10 | 50.0 | FAIL (reported only) |" in md
    assert "| prompt_s | 3 | 0 |" in md
    bad = dict(r, valid="yes", classes={"telepathy": {}})
    errs = rep.validate_report(bad)
    assert any("valid" in e for e in errs) and any("telepathy" in e for e in errs)


def test_the_pure_modules_import_no_harness_dependencies():
    code = ("import sys; sys.path.insert(0, %r); import report, load; "
            "print([m for m in ('psutil', 'websockets', 'mitmproxy') if m in sys.modules])" % str(LT))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


# ── the load generator's pure parts ───────────────────────────────────

def test_prompt_sampling_is_deterministic_and_sized():
    prompts = load.load_prompts()
    a = [load.sample_prompt(random.Random(7), prompts, 200, 2000) for _ in range(1)]
    b = [load.sample_prompt(random.Random(7), prompts, 200, 2000) for _ in range(1)]
    assert a == b and 200 <= len(a[0]) <= 2000


def test_http_samples_classify_outcomes():
    s = load._http_sample({"proxied": (20.0, 200, b"{}"), "direct": (5.0, 200, b"{}")})
    assert (s["proxied_ms"], s["direct_ms"], s["outcome"]) == (20.0, 5.0, "ok")
    s = load._http_sample({"proxied": (3.0, 403, b'{"votal": {"code": "blocked"}}'), "direct": (5.0, 200, b"")})
    assert s["outcome"] == "blocked" and "proxied_ms" not in s and "error" not in s
    s = load._http_sample({"proxied": (3.0, 502, b"bad gateway"), "direct": (5.0, 200, b"")})
    assert s["outcome"] == "proxy_error" and s["error"] == "HTTP 502"
    s = load._http_sample({"proxied": TimeoutError("slow"), "direct": (5.0, 200, b"")})
    assert s["outcome"] == "proxy_error" and "TimeoutError" in s["error"]
    s = load._http_sample({"proxied": (9.0, 200, b""), "direct": ConnectionError("x")})
    assert "direct_error" in s and "proxied_ms" not in s                 # unpaired: no latency sample
    s = load._http_sample({"proxied": (load.PolicyOutcome(4.0), 200, b""), "direct": (5.0, 200, b"")})
    assert s["outcome"] == "blocked"
