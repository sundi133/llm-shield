"""Device agent, task 1: the DLP evaluation set and the /v1/systemone benchmark.
Spec: docs/specs/device-dlp-agent.md §2.6, §10.

The harness is tested against a fake decision server that answers in the shape
Ollama documents for /v1/systemone (answers.<name>.choice / probabilities /
confidence, and noul for yes/no questions)."""

import importlib.util
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "..", "dlp-bench")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BENCH, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bench = _load("run_dlp_bench")
build = _load("build_eval")
CASES = [json.loads(l) for l in open(os.path.join(BENCH, "dlp_eval.jsonl")) if l.strip()]
CFG = json.load(open(os.path.join(BENCH, "questions.json")))


# ── the corpus ───────────────────────────────────────────────────────


def test_jsonl_is_built_from_the_source():
    assert open(os.path.join(BENCH, "dlp_eval.jsonl")).read() == build.render(), \
        "run: python dlp-bench/build_eval.py"


def test_corpus_shape():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)) and len(CASES) >= 300
    for cat in bench.CATEGORIES:
        pos = [c for c in CASES if c["group"] == f"{cat}-pos"]
        near = [c for c in CASES if c["group"] == f"{cat}-near"]
        assert len(pos) >= 25 and len(near) >= 24, cat
        assert all(c["sensitive"] and c["category"] == cat for c in pos)
        assert all(not c["sensitive"] and c["category"] == "none" for c in near)
    assert {c["split"] for c in CASES} == {"calibration", "test"}
    cal = sum(c["split"] == "calibration" for c in CASES)
    assert 0.3 < cal / len(CASES) < 0.4
    assert set(CASES[0]) >= {"text", "destination", "app", "category", "sensitive", "exfil"}


# Token shapes that secret scanners treat as live credentials. None may appear:
# the set uses documentation examples and obviously fake values only.
LIVE_SHAPES = [r"ghp_[A-Za-z0-9]{20,}", r"xox[abpr]-[A-Za-z0-9-]{10,}", r"sk_live_[A-Za-z0-9]{10,}",
               r"AIza[0-9A-Za-z_-]{30,}", r"sk-proj-[A-Za-z0-9]{10,}", r"sk-ant-[A-Za-z0-9-]{10,}",
               r"AKIA(?!IOSFODNN7EXAMPLE)[A-Z0-9]{16}", r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"]


def test_no_live_looking_secrets():
    text = open(os.path.join(BENCH, "dlp_eval.jsonl")).read()
    for shape in LIVE_SHAPES:
        assert not re.search(shape, text), shape


# ── decisions (spec §3.2, model rows) ────────────────────────────────


T = CFG["thresholds"]


def _p(cat, p=0.95, conf=0.9, exfil=0.0):
    return {"category": cat, "p_category": p, "confidence": conf, "probabilities": {cat: p},
            "exfil": exfil}


def test_decision_table():
    assert bench.decide(_p("credentials", 0.95), T) == "block"          # blocking category
    assert bench.decide(_p("health", 0.95), T) == "justify"             # non-blocking category
    assert bench.decide(_p("credentials", 0.7), T) == "justify"         # below block_p
    assert bench.decide(_p("credentials", 0.4), T) == "allow"
    assert bench.decide(_p("none", 0.99), T) == "allow"
    assert bench.decide(_p("none", 0.99, exfil=0.85), T) == "justify"   # exfil intent
    assert bench.decide(_p("credentials", 0.99, conf=0.1), T) == "uncertain"
    assert bench.decide(_p("credentials", 0.99, conf=0.1, exfil=0.9), T) == "justify"


def test_parse_matches_the_documented_response():
    resp = {"model": "tev1:0.8b", "answers": {
        "category": {"type": "choice", "choice": "customer_data",
                     "probabilities": {"customer_data": 0.81, "none": 0.19}, "confidence": 0.6},
        "exfil_intent": {"type": "noul", "noul": 0.12}}}
    assert bench.parse(resp) == {"category": "customer_data", "choice": "customer_data",
                                 "p_category": 0.81, "confidence": 0.6,
                                 "probabilities": {"customer_data": 0.81, "none": 0.19},
                                 "exfil": 0.12}
    assert bench.parse({"answers": {}})["category"] is None


def test_the_signal_is_mass_away_from_none():
    """Measured on Tev1: it often still chooses 'none' on real data while
    shifting probability away from it. The label is the top non-none option."""
    resp = {"answers": {"category": {
        "choice": "none", "confidence": 0.4,
        "probabilities": {"none": 0.6, "credentials": 0.3, "health": 0.1}}}}
    p = bench.parse(resp)
    assert p["choice"] == "none" and p["category"] == "credentials"
    assert p["p_category"] == pytest.approx(0.4)


# ── a fake /v1/systemone ─────────────────────────────────────────────


KEYWORDS = {"credentials": ("password", "secret", "token", "key"),
            "health": ("patient", "diagnos", "mrn"),
            "financial": ("revenue", "ebitda", "board", "acquir"),
            "customer_data": ("customer", "crm", "account"),
            "source_code": ("repo", "proprietary", "internal"),
            "personal_data": ("dob", "ssn", "passport", "address")}


class FakeDecisions(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *a):
        pass

    def do_POST(self):
        # Read the body first on every path: replying and closing with request
        # bytes unread makes the OS reset the connection, and the client then
        # sees a reset instead of the 404 (an intermittent failure).
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path != "/v1/systemone" or FakeDecisions.mode == "old_ollama":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 page not found")
            return
        body = json.loads(raw)
        text = body["state"]["prompt"].lower()
        cat = next((c for c, words in KEYWORDS.items() if any(w in text for w in words)), "none")
        exfil = 0.9 if any(w in text for w in ("personal", "leaving", "quit", "journalist")) else 0.05
        resp = {"model": body["model"], "answers": {
            "category": {"type": "choice", "choice": cat,
                         "probabilities": {cat: 0.93, "none" if cat != "none" else "health": 0.07},
                         "confidence": 0.8},
            "exfil_intent": {"type": "noul", "noul": exfil}},
            "usage": {"input_tokens": 100, "output_tokens": 4}}
        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture(scope="module")
def fake():
    srv = HTTPServer(("127.0.0.1", 0), FakeDecisions)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1/systemone"
    srv.shutdown()


def test_preflight_names_an_old_ollama(fake):
    FakeDecisions.mode = "old_ollama"
    try:
        with pytest.raises(bench.EndpointError, match="no decision-model support"):
            bench.run(fake, "tev1:0.8b", CASES[:3], CFG, warmup=0, log=lambda m: None)
    finally:
        FakeDecisions.mode = "ok"


def test_full_run_produces_the_report(fake, tmp_path):
    r = bench.run(fake, "tev1:0.8b", CASES, CFG, warmup=1, log=lambda m: None)
    assert r["errors"] == [] and len(r["rows"]) == len(CASES)
    tc = r["test_calibrated"]
    assert set(tc["per_category"]) == set(bench.CATEGORIES)
    assert tc["false_positive_rate"] <= bench.GATES["false_positive_rate"] or \
        r["thresholds_calibrated"] == CFG["thresholds"]                 # nothing qualified
    assert set(r["gates"]) >= {"recall_per_category", "false_positive_rate", "latency_p95"}
    assert r["hardware"]["class"] in ("apple_silicon", "x86_cpu")
    assert r["latency"]["n"] == len(CASES) and r["latency"]["p95_ms"] >= r["latency"]["p50_ms"]
    md = bench.markdown(r)
    assert "# DLP benchmark" in md and "latency p95" in md
    json.dumps(r)                                                       # report is serialisable


def test_calibration_uses_only_the_calibration_split(fake):
    r = bench.run(fake, "tev1:0.8b", CASES, CFG, warmup=0, log=lambda m: None)
    cal_ids = {c["id"] for c in CASES if c["split"] == "calibration"}
    test_fp = set(r["test_calibrated"]["false_positives"])
    assert not (test_fp & cal_ids)                                      # test metrics: test split only


def test_calibration_respects_the_false_positive_gate():
    # Lowering thresholds would catch the positive but also the benign case: 50 % FP.
    rows = [{"case": {"id": "p", "sensitive": True, "category": "health", "exfil": False},
             "parsed": _p("health", 0.5)},
            {"case": {"id": "b", "sensitive": False, "category": "none", "exfil": False},
             "parsed": _p("health", 0.5)}]
    tuned = bench.calibrate(rows, T, fp_gate=0.03)
    assert bench.metrics(rows, tuned)["false_positive_rate"] <= 0.03
