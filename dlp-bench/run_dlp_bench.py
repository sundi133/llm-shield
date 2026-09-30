#!/usr/bin/env python3
"""Benchmark a /v1/systemone decision model on the DLP evaluation set.

Spec: docs/specs/device-dlp-agent.md §2.6 (gates) and §10 (task 1).
Standard library only, so it runs on any laptop, Mac or Windows.

    python dlp-bench/run_dlp_bench.py --model tev1:0.8b
    python dlp-bench/run_dlp_bench.py --endpoint http://127.0.0.1:11535/v1/systemone --model tev1:0.8b

What it does, in order:
  1. Preflight: the endpoint must exist. Ollama builds without decision-model
     support answer 404 on /v1/systemone; that is reported as such.
  2. One call per case (after a short warm-up), with the questions and default
     thresholds from questions.json, timing each call.
  3. Decisions: the spec's model table (§3.2): block / justify / allow /
     uncertain (allow, recorded).
  4. Calibration: thresholds are tuned on the `calibration` split only (the
     highest macro recall with false positives at or under the gate) and then
     reported, together with the defaults, on the `test` split only.
  5. Gates: per-category recall >= 0.80, false positives <= 3 %, latency p95
     <= 300 ms (Apple Silicon) or 800 ms (x86 CPU). Hardware is recorded.

Writes dlp-bench/reports/<model>-<host>.json (every answer, for re-analysis
without re-running the model) and .md (the summary).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import platform
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
CATEGORIES = ("credentials", "personal_data", "customer_data", "source_code", "financial",
              "health")
GATES = {"recall": 0.80, "false_positive_rate": 0.03, "p95_ms_apple": 300, "p95_ms_x86": 800}
CAUGHT = ("block", "justify")


class EndpointError(Exception):
    pass


# ── calling the model ────────────────────────────────────────────────


def call(endpoint: str, body: dict, timeout: float) -> tuple[dict, float]:
    req = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # The status is the answer; the body only decorates the message, and
        # reading it can fail (a server that closes early resets the socket).
        try:
            detail = e.read()[:200].decode("utf-8", "replace")
        except OSError:
            detail = ""
        if e.code == 404:
            raise EndpointError(f"{endpoint} returned 404: this Ollama build has no decision-model "
                                f"support, or the model is not pulled ({detail.strip()})") from None
        raise EndpointError(f"HTTP {e.code}: {detail}") from None
    except (urllib.error.URLError, OSError) as e:
        raise EndpointError(f"cannot reach {endpoint}: {e}") from None
    return data, (time.perf_counter() - t0) * 1000.0


def request_body(model: str, case: dict, questions: dict) -> dict:
    return {"model": model,
            "state": {"prompt": case["text"], "destination": case["destination"],
                      "app": case["app"]},
            "questions": questions}


def parse(answers: dict) -> dict:
    """{category, p_category, confidence, probabilities, exfil} from a response.

    The signal is p_category = 1 - P(none): how much the model moved away from
    "nothing sensitive". `category` is the most likely non-"none" option, used to
    label the finding and pick block vs justify. Measured in task 1: with
    well-worded questions Tev1 often still *chooses* "none" on real data while
    shifting mass away from it, so the chosen option's own probability is the
    wrong signal (spec §3.2, updated).
    """
    a = answers.get("answers") or {}
    cat = a.get("category") or {}
    probs = {k: float(v) for k, v in (cat.get("probabilities") or {}).items()}
    sensitive = {k: v for k, v in probs.items() if k != "none"}
    label = max(sensitive, key=sensitive.get) if sensitive else cat.get("choice")
    ex = a.get("exfil_intent") or {}
    return {"category": label,
            "choice": cat.get("choice"),
            "p_category": round(1.0 - probs.get("none", 0.0), 6) if probs else 0.0,
            "confidence": float(cat.get("confidence", 0.0)),
            "probabilities": probs,
            "exfil": float(ex.get("noul", 0.0))}


# ── deciding (spec §3.2, the model rows) ─────────────────────────────


def decide(p: dict, t: dict) -> str:
    confident = p["confidence"] >= t["min_confidence"]
    cat = p["category"]
    if confident and cat in t["block_categories"] and p["p_category"] >= t["block_p"]:
        return "block"
    if confident and cat not in (None, "none") and p["p_category"] >= t["justify_p"]:
        return "justify"
    if p["exfil"] >= t["exfil_intent"]:
        return "justify"
    return "allow" if confident else "uncertain"


def metrics(rows: list[dict], t: dict) -> dict:
    """Recall per category, exfil recall, false positives on benign cases."""
    out: dict = {"per_category": {}}
    for cat in CATEGORIES:
        pos = [r for r in rows if r["case"]["sensitive"] and r["case"]["category"] == cat
               and not r["case"]["exfil"]]
        caught = [r for r in pos if decide(r["parsed"], t) in CAUGHT]
        named = [r for r in pos if r["parsed"]["category"] == cat]
        out["per_category"][cat] = {"n": len(pos),
                                    "recall": round(len(caught) / len(pos), 3) if pos else None,
                                    "named_correctly": round(len(named) / len(pos), 3) if pos else None}
    ex = [r for r in rows if r["case"]["exfil"]]
    out["exfil_recall"] = round(sum(decide(r["parsed"], t) in CAUGHT for r in ex) / len(ex), 3) \
        if ex else None
    benign = [r for r in rows if not r["case"]["sensitive"] and not r["case"]["exfil"]]
    fp = [r for r in benign if decide(r["parsed"], t) in CAUGHT]
    out["benign_n"] = len(benign)
    out["false_positive_rate"] = round(len(fp) / len(benign), 3) if benign else None
    out["false_positives"] = [r["case"]["id"] for r in fp]
    recalls = [v["recall"] for v in out["per_category"].values() if v["recall"] is not None]
    out["macro_recall"] = round(sum(recalls) / len(recalls), 3) if recalls else None
    out["uncertain"] = sum(decide(r["parsed"], t) == "uncertain" for r in rows)
    return out


def calibrate(rows: list[dict], defaults: dict, fp_gate: float) -> dict:
    """The thresholds with the best macro recall on these rows (the calibration
    split) with false positives at or under the gate. Defaults if none qualify."""
    best, best_key = dict(defaults), None
    grid = [0.02, 0.03] + [round(0.05 * i, 2) for i in range(1, 20)]   # 0.02 .. 0.95
    # block_p never changes whether a case is caught (block and justify both
    # count), only how; it is tuned after, as the highest value that keeps
    # blocking-category positives blocked.
    for justify_p in grid:
        for exfil_t in grid:
            for min_conf in (0.0, 0.2):
                t = {**defaults, "justify_p": justify_p, "exfil_intent": exfil_t,
                     "min_confidence": min_conf, "block_p": max(defaults["block_p"], justify_p)}
                m = metrics(rows, t)
                if m["false_positive_rate"] is None or m["false_positive_rate"] > fp_gate:
                    continue
                key = (m["macro_recall"] or 0, m["exfil_recall"] or 0, -m["false_positive_rate"])
                if best_key is None or key > best_key:
                    best, best_key = t, key
    if best_key is not None:
        blocking = [r["parsed"]["p_category"] for r in rows
                    if r["case"]["sensitive"] and r["case"]["category"] in best["block_categories"]
                    and r["parsed"]["p_category"] >= best["justify_p"]]
        if blocking:
            best["block_p"] = round(max(best["justify_p"], sorted(blocking)[len(blocking) // 2]), 3)
    return best


# ── hardware, latency, gates ─────────────────────────────────────────


def hardware() -> dict:
    info = {"os": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
            "cpu": platform.processor() or "", "python": platform.python_version()}
    if platform.system() == "Darwin":
        try:
            info["cpu"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                         capture_output=True, text=True).stdout.strip()
            mem = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                     text=True).stdout.strip())
            info["memory_gb"] = round(mem / 2**30)
        except (OSError, ValueError):
            pass
    info["class"] = "apple_silicon" if (platform.system() == "Darwin"
                                        and platform.machine() == "arm64") else "x86_cpu"
    return info


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))
    return round(xs[k], 1)


def gates(test: dict, latency: dict, hw: dict) -> dict:
    p95_gate = GATES["p95_ms_apple"] if hw["class"] == "apple_silicon" else GATES["p95_ms_x86"]
    recall_ok = all((v["recall"] or 0) >= GATES["recall"] for v in test["per_category"].values())
    return {"recall_per_category": recall_ok,
            "false_positive_rate": (test["false_positive_rate"] or 0) <= GATES["false_positive_rate"],
            "latency_p95": latency["p95_ms"] <= p95_gate, "latency_gate_ms": p95_gate}


# ── the run ──────────────────────────────────────────────────────────


def run(endpoint: str, model: str, cases: list[dict], cfg: dict, *, timeout: float = 30.0,
        warmup: int = 3, log=print) -> dict:
    questions, defaults = cfg["questions"], cfg["thresholds"]
    call(endpoint, request_body(model, cases[0], questions), timeout)        # preflight
    for c in cases[:warmup]:
        call(endpoint, request_body(model, c, questions), timeout)
    rows, lat, errors = [], [], []
    for i, c in enumerate(cases, 1):
        try:
            data, ms = call(endpoint, request_body(model, c, questions), timeout)
        except EndpointError as e:
            errors.append({"id": c["id"], "error": str(e)})
            continue
        rows.append({"case": c, "parsed": parse(data), "ms": round(ms, 1), "raw": data})
        lat.append(ms)
        if i % 50 == 0:
            log(f"  {i}/{len(cases)}")
    latency = {"n": len(lat), "p50_ms": percentile(lat, 0.50), "p95_ms": percentile(lat, 0.95),
               "p99_ms": percentile(lat, 0.99),
               "mean_ms": round(statistics.fmean(lat), 1) if lat else None}
    cal = [r for r in rows if r["case"]["split"] == "calibration"]
    test = [r for r in rows if r["case"]["split"] == "test"]
    tuned = calibrate(cal, defaults, GATES["false_positive_rate"])
    hw = hardware()
    result = {"model": model, "endpoint": endpoint, "hardware": hw, "cases": len(cases),
              "errors": errors, "latency": latency, "thresholds_default": defaults,
              "thresholds_calibrated": tuned,
              "test_default": metrics(test, defaults), "test_calibrated": metrics(test, tuned),
              "calibration_calibrated": metrics(cal, tuned)}
    result["gates"] = gates(result["test_calibrated"], latency, hw)
    result["rows"] = [{"id": r["case"]["id"], "split": r["case"]["split"], "ms": r["ms"],
                       **r["parsed"]} for r in rows]
    return result


def markdown(r: dict) -> str:
    hw, lat, g = r["hardware"], r["latency"], r["gates"]
    mark = lambda ok: "pass" if ok else "**FAIL**"
    lines = [f"# DLP benchmark: `{r['model']}`", "",
             f"Hardware: {hw.get('cpu') or hw['machine']}, {hw.get('memory_gb', '?')} GB, "
             f"{hw['os']} ({hw['class']}). Cases: {r['cases']}, errors: {len(r['errors'])}.", "",
             "## Gates (test split, calibrated thresholds)", "",
             "| Gate | Target | Result | |", "|---|---|---|---|"]
    tc = r["test_calibrated"]
    for cat, v in tc["per_category"].items():
        lines.append(f"| recall: {cat} | >= {GATES['recall']:.2f} | {v['recall']} | "
                     f"{mark((v['recall'] or 0) >= GATES['recall'])} |")
    lines += [f"| false positives | <= {GATES['false_positive_rate']:.0%} | "
              f"{tc['false_positive_rate']:.1%} of {tc['benign_n']} | {mark(g['false_positive_rate'])} |",
              f"| latency p95 | <= {g['latency_gate_ms']} ms | {lat['p95_ms']} ms | "
              f"{mark(g['latency_p95'])} |", "",
              "## Detail", "",
              "| | Default thresholds | Calibrated |", "|---|---|---|",
              f"| macro recall | {r['test_default']['macro_recall']} | {tc['macro_recall']} |",
              f"| exfil recall | {r['test_default']['exfil_recall']} | {tc['exfil_recall']} |",
              f"| false positive rate | {r['test_default']['false_positive_rate']} | "
              f"{tc['false_positive_rate']} |",
              f"| uncertain (allowed) | {r['test_default']['uncertain']} | {tc['uncertain']} |", "",
              "Category named correctly (test split): " + ", ".join(
                  f"{c} {v['named_correctly']}" for c, v in tc["per_category"].items()), "",
              f"Latency: p50 {lat['p50_ms']} ms, p95 {lat['p95_ms']} ms, p99 {lat['p99_ms']} ms "
              f"over {lat['n']} calls.", "",
              f"Calibrated thresholds (chosen on the calibration split only): "
              f"`{json.dumps(r['thresholds_calibrated'])}`", ""]
    if tc["false_positives"]:
        lines.append("False positives (test split): " + ", ".join(tc["false_positives"]))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--endpoint", default="http://127.0.0.1:11434/v1/systemone")
    ap.add_argument("--model", default="tev1:0.8b")
    ap.add_argument("--corpus", type=pathlib.Path, default=HERE / "dlp_eval.jsonl")
    ap.add_argument("--questions", type=pathlib.Path, default=HERE / "questions.json")
    ap.add_argument("--out-dir", type=pathlib.Path, default=HERE / "reports")
    ap.add_argument("--limit", type=int, default=0, help="only the first N cases (smoke test)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--tag", default="", help="suffix for the report file names")
    args = ap.parse_args()
    cases = [json.loads(l) for l in args.corpus.read_text().splitlines() if l.strip()]
    if args.limit:
        cases = cases[:args.limit]
    cfg = json.loads(args.questions.read_text())
    try:
        result = run(args.endpoint, args.model, cases, cfg, timeout=args.timeout)
    except EndpointError as e:
        print(f"preflight failed: {e}", file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    result["questions_file"] = args.questions.name
    stem = f"{args.model.replace(':', '-')}-{result['hardware']['class']}" + \
        (f"-{args.tag}" if args.tag else "")
    (args.out_dir / f"{stem}.json").write_text(json.dumps(result, indent=1))
    (args.out_dir / f"{stem}.md").write_text(markdown(result))
    print(markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
