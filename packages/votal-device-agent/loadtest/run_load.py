"""Device agent load test (docs/specs/device-agent-load-test.md, POC AG-60).

    python packages/votal-device-agent/loadtest/run_load.py \\
        --profile smoke|poc|saturate --model fake|real [--model-latency-ms 50] \\
        [--out packages/votal-device-agent/loadtest/reports] [--allow-battery] \\
        [--expect-gate after_send|inline]

Three processes: the agent under test (agent_runner.py), the fake AI service
(fake_upstream.py) and this one, the load generator. Everything is on
127.0.0.1 with port 0; the run's CAs live in a temp directory and are trusted
only by this harness. No real provider or Shield is contacted.

Exit code: 0 when every enforced budget passes, 1 when one fails or the run is
invalid, 2 for a harness error.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
for p in (REPO, HERE.parent, REPO / "packages" / "shield-mavlink"):
    if str(p) not in sys.path:
        sys.path.append(str(p))

import report as rep  # noqa: E402

GEN_CPU_LIMIT = 80.0     # % of one core: above this the generator, not the agent, is the limit


def _ca(name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, tmp: Path):
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp / "up.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "up.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                                   serialization.NoEncryption()))
    (tmp / "upstream-ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return tmp / "up.pem", tmp / "up.key", tmp / "upstream-ca.pem"


class Child:
    """A subprocess that prints one JSON line when ready, then stats lines."""

    def __init__(self, args, env):
        self.p = subprocess.Popen([sys.executable, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=env, bufsize=1)
        self.lines: "queue.Queue[dict]" = queue.Queue()
        self.stats: list[dict] = []
        self.stderr: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=lambda: self.stderr.extend(self.p.stderr), daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if "ready" in d:
                self.lines.put(d)
            else:
                self.stats.append(d)

    def ready(self, timeout=60.0) -> dict:
        try:
            d = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise RuntimeError("did not start: " + "".join(self.stderr)[-2000:])
        if not d.get("ready"):
            raise RuntimeError(d.get("error") or "did not start")
        return d

    def stop(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(15)
        except subprocess.TimeoutExpired:
            self.p.kill()


def _meta(args, profile, agent_stats) -> dict:
    import psutil
    from votal_device_agent import _version
    from votal_device_agent.model import hardware_class
    try:
        git = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True,
                             text=True, timeout=5).stdout.strip()
    except Exception:
        git = ""
    cpu = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        try:
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                 text=True, timeout=5).stdout.strip() or cpu
        except Exception:
            pass
    bat = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    last = agent_stats[-1] if agent_stats else {}
    return {"profile": profile["name"], "model": args.model,
            "model_latency_ms": args.model_latency_ms if args.model == "fake" else None,
            "hardware": hardware_class(), "cpu": cpu,
            "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
            "os": f"{platform.system()} {platform.release()}",
            "power": "battery" if bat is not None and not bat.power_plugged else "ac",
            "agent_version": _version.__version__, "git": git,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "gate": "inline" if last.get("inline") else "after_send",
            "gate_p95_ms": None if last.get("gate_p95_ms") is None else round(last["gate_p95_ms"], 1),
            "tabs": profile["tabs"],
            "duration_s": profile["duration_s"]}


def build_report(args, profile, work, sampler, agent) -> dict:
    samples = work["samples"]
    classes = {c: rep.summarize(s) for c, s in samples.items()}
    proxy_failures = sum(1 for s in samples.values() for x in s if x.get("error"))
    direct_failures = sum(1 for s in samples.values() for x in s if x.get("direct_error"))
    load_end = work["t_end"]
    q_during = [s["queue"] for s in agent.stats if s.get("t", 0) <= load_end]
    if not q_during or q_during[-1] == 0:
        drained = 0.0                          # no backlog when the load stopped
    else:
        drained = next((round(s["t"] - load_end, 1) for s in agent.stats
                        if s.get("t", 0) > load_end and s.get("queue", 1) == 0), None)
    audit = agent.stats[-1]["audit_records"] if agent.stats else 0
    seconds = max(1e-6, load_end - work["t_start"])
    gen_cpu = sum(sampler.gen_cpu) / len(sampler.gen_cpu) if sampler.gen_cpu else 0.0
    r = {"meta": _meta(args, profile, agent.stats), "classes": classes,
         "resources": rep.resources([s for s in sampler.samples if s["t"] <= load_end]),
         "queues": {"after_send_max": max(q_during) if q_during else 0,
                    "after_send_end": agent.stats[-1]["queue"] if agent.stats else 0,
                    "backlog_drained_s": drained, "audit_records": audit,
                    "audit_headroom_pct": rep.audit_headroom_pct(audit, seconds)},
         "failures": {"proxy": proxy_failures, "direct": direct_failures},
         "load": {"achieved_rps": work["achieved_rps"], "generator_cpu_mean_pct": round(gen_cpu, 1)},
         "valid": True}
    if gen_cpu > GEN_CPU_LIMIT:
        r["valid"], r["invalid_reason"] = False, f"load generator at {gen_cpu:.0f}% of a core"
    elif r["meta"]["power"] == "battery" and not args.allow_battery and profile["name"] != "smoke":
        r["valid"], r["invalid_reason"] = False, "laptop on battery (use --allow-battery to grade anyway)"
    r["budgets"] = rep.grade(r, profile["budgets"])
    return r


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", default="smoke")
    ap.add_argument("--model", choices=("fake", "real"), default=None)
    ap.add_argument("--model-latency-ms", type=float, default=None)
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    ap.add_argument("--duration-s", type=int, default=None, help="override the profile's duration")
    ap.add_argument("--out", default=str(HERE / "reports"))
    ap.add_argument("--allow-battery", action="store_true")
    ap.add_argument("--expect-gate", choices=("inline", "after_send"), default=None)
    args = ap.parse_args(argv)

    pfile = Path(args.profile) if args.profile.endswith(".json") else HERE / "profiles" / f"{args.profile}.json"
    profile = rep.load_profile(pfile)
    if args.duration_s:
        profile["duration_s"] = args.duration_s
    args.model = args.model or profile["model"]
    if args.model_latency_ms is None:
        args.model_latency_ms = float(profile["model_latency_ms"])

    import load
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
    for k in ("https_proxy", "http_proxy", "all_proxy"):
        os.environ.pop(k, None)
        os.environ.pop(k.upper(), None)
    with tempfile.TemporaryDirectory(prefix="votal-loadtest-") as tmp_s:
        tmp = Path(tmp_s)
        cert, key, up_ca = _leaf(*_ca("Load Test Upstream CA"), tmp)
        up = Child([str(HERE / "fake_upstream.py"), "--cert", str(cert), "--key", str(key)], env)
        agent = Child([str(HERE / "agent_runner.py"), "--state", str(tmp / "agent"), "--upstream-ca",
                       str(up_ca), "--model", args.model, "--model-latency-ms", str(args.model_latency_ms),
                       "--ollama-url", args.ollama_url], env)
        try:
            u, a = up.ready(), agent.ready(120)
            ep = load.Endpoints(a["port"], u["http_port"], u["ws_port"], a["device_ca"], str(up_ca))
            sampler = load.Sampler(a["pid"], with_ollama=args.model == "real").start()
            print(f"running {profile['name']} for {profile['duration_s']} s, {profile['tabs']} tabs, "
                  f"{args.model} model", flush=True)
            work = load.run_workload(profile, ep)
            idle = profile.get("idle_after_s", 0)
            if idle:
                print(f"idle {idle} s (backlog drain)", flush=True)
                time.sleep(idle)
            time.sleep(1.5)                     # one more stats line after the load
            sampler.stop()
        except Exception as e:
            print(f"harness error: {e}", file=sys.stderr)
            agent.stop()
            up.stop()
            return 2
        agent.stop()
        up.stop()
        if agent.p.returncode not in (0, None, -15):
            print("agent exited with", agent.p.returncode, "".join(agent.stderr)[-2000:], file=sys.stderr)

    r = build_report(args, profile, work, sampler, agent)
    errors = rep.validate_report(r)
    if errors:
        print("report schema: " + "; ".join(errors), file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{r['meta']['hardware']}-{profile['name']}-{args.model}-{datetime.date.today().isoformat()}"
    (out / f"{stem}.json").write_text(json.dumps(r, indent=2) + "\n")
    (out / f"{stem}.md").write_text(rep.render_markdown(r))
    print(rep.render_markdown(r))
    print(f"report: {out / stem}.json and .md")
    failed = rep.enforced_failures(r["budgets"])
    if args.expect_gate and r["meta"]["gate"] != args.expect_gate:
        print(f"FAIL: model gate ended {r['meta']['gate']}, expected {args.expect_gate}")
        return 1
    if not r["valid"] or failed:
        print("FAIL: " + (r.get("invalid_reason") or ", ".join(b["name"] for b in failed)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
