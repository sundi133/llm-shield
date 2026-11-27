"""The agent under test, in its own process (docs/specs/device-agent-load-test.md).

Starts the agent's real Engine and LocalProxy with a test policy (AI host
`localhost`, enforce), a per-run device CA, a real audit log in a temp
directory, and either a scripted fake model (with a latency knob) or the local
Ollama. Prints one JSON line when ready ({"ready": true, "port", "pid"}), then
one stats line a second, until stdin closes or it is terminated.

    python agent_runner.py --state DIR --upstream-ca FILE --model fake|real
                           [--model-latency-ms 50] [--ollama-url URL]
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for p in (REPO, HERE.parent, REPO / "packages" / "shield-mavlink"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

RULES = [
    {"id": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "action": "block", "severity": "critical"},
    {"id": "aws-key", "regex": r"AKIA[0-9A-Z]{16}", "action": "redact", "severity": "critical",
     "replacement": "[AWS_KEY]"},
]


class FakeModel:
    """A scripted /v1/systemone: every prompt judged benign after `latency_ms`,
    the way the test suite's FakeOllama answers."""

    def __init__(self, latency_ms: float, digest: str):
        self.latency_s = max(0.0, latency_ms) / 1000.0
        self.digest = digest

    def __call__(self, method, url, headers, body, timeout):
        if url.endswith("/api/version"):
            return 200, json.dumps({"version": "0.35.0"}).encode()
        if url.endswith("/api/tags"):
            return 200, json.dumps({"models": [{"name": "tev1:0.8b",
                                                "digest": self.digest.removeprefix("sha256:")}]}).encode()
        time.sleep(self.latency_s)
        req = json.loads(body)
        return 200, json.dumps({"model": req["model"], "answers": {
            "category": {"type": "choice", "choice": "none",
                         "probabilities": {"none": 0.98}, "confidence": 0.9},
            "exfil_intent": {"type": "noul", "noul": 0.01}}}).encode()


def build(args):
    from core.dlp.device_policy import DEFAULT_MODEL, for_fleet, validate_policy
    from votal_device_agent import ca as vca
    from votal_device_agent.audit import AuditLog
    from votal_device_agent.engine import Engine
    from votal_device_agent.model import DecisionModel, LatencyGate
    from votal_device_agent.proxy import LocalProxy
    from votal_device_agent.trust import Trust

    state = Path(args.state)
    policy = for_fleet(validate_policy({"mode": "enforce"}), "loadtest")
    policy.update(rules=RULES, blocklists=["project-atlas"], ai_hosts=["localhost"],
                  pinned_host_action={"default": "allow_and_log", "hosts": {}})
    if args.model == "fake":
        model = DecisionModel("http://fake-ollama", http=FakeModel(args.model_latency_ms,
                                                                    DEFAULT_MODEL["digest"]),
                              gate=LatencyGate())
        model.health(DEFAULT_MODEL["name"], DEFAULT_MODEL["digest"], DEFAULT_MODEL["min_ollama"])
    else:
        model = DecisionModel(args.ollama_url, gate=LatencyGate())
        h = model.health(DEFAULT_MODEL["name"], DEFAULT_MODEL["digest"], DEFAULT_MODEL["min_ollama"])
        if h != "ok":
            print(json.dumps({"ready": False, "error": f"real model not usable: {h}"}), flush=True)
            sys.exit(3)
    audit = AuditLog(state / "audit", device_id="loadtest")
    records = {"n": 0}
    original = audit.record

    def counting_record(d):
        records["n"] += 1
        return original(d)
    audit.record = counting_record
    engine = Engine(Trust("verified", policy, "", {"bundle_version": 1}), model, audit=audit)
    confdir = state / "ca"
    vca.ensure_ca(confdir, ["localhost"], device_name="loadtest")
    proxy = LocalProxy(engine, port=0, confdir=confdir, upstream_ca=args.upstream_ca,
                       justify_base="http://127.0.0.1:47823")
    return engine, model, proxy, records, confdir / vca.CERT_FILE


def stats(engine, model, records) -> dict:
    ex = getattr(engine, "_executor", None)
    queue = ex._work_queue.qsize() if ex is not None else 0
    return {"t": round(time.time(), 3), "queue": queue, "counters": dict(engine.counters),
            "gate_p95_ms": model.gate.p95(), "inline": model.gate.inline(),
            "audit_records": records["n"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--upstream-ca", required=True)
    ap.add_argument("--model", choices=("fake", "real"), default="fake")
    ap.add_argument("--model-latency-ms", type=float, default=50.0)
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = ap.parse_args(argv)
    engine, model, proxy, records, device_ca = build(args)
    port = proxy.start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    threading.Thread(target=lambda: (sys.stdin.read(), stop.set()), daemon=True).start()
    print(json.dumps({"ready": True, "port": port, "pid": os.getpid(),
                      "device_ca": str(device_ca), "model_state": model.state}), flush=True)
    while not stop.wait(1.0):
        print(json.dumps(stats(engine, model, records)), flush=True)
    print(json.dumps({"final": True, **stats(engine, model, records)}), flush=True)
    proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
