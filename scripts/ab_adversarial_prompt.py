#!/usr/bin/env python3
"""On-device A/B test for the adversarial_detection prompt.

Runs the REAL AdversarialGuardrail.check() against the LOCAL vLLM using the
CURRENT working-tree prompt in guardrails/input/adversarial.py. No data-plane
redeploy: edit _SYSTEM_PROMPT / _USER_PREFIX, re-run this, compare the numbers.

Why on-device: the raw vLLM OpenAI API is only reachable on the box that serves
it (127.0.0.1:8000) — it is NOT exposed through the public /guardrails proxy.
So run this where vLLM lives (the RunPod container, or a local vLLM serving the
same model). It exercises the exact production code path (preprocessing,
chunking, threshold, parsing), not a reimplementation.

Backend: LLM_BACKEND_URL (default http://127.0.0.1:8000). The guardrail's own
default is already 127.0.0.1:8000, so on the device no env is needed.

Corpus: reuses the labeled set from scripts/eval_adversarial_fp.py (single
source of truth) so results are directly comparable to that gate and the
recorded baseline.

Usage (from repo root, on the device):
    python scripts/ab_adversarial_prompt.py
    LLM_BACKEND_URL=http://127.0.0.1:8000 python scripts/ab_adversarial_prompt.py
"""
import asyncio
import importlib.util
import math
import os
import sys
import time

# repo root on sys.path so `guardrails.*` / `core.*` import
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Point the LLM backend at local vLLM unless the caller overrode it.
os.environ.setdefault("LLM_BACKEND_URL", "http://127.0.0.1:8000")

from guardrails.input.adversarial import AdversarialGuardrail  # noqa: E402


def _load_corpus():
    """Reuse CORPUS from the eval harness without making scripts a package."""
    path = os.path.join(ROOT, "scripts", "eval_adversarial_fp.py")
    spec = importlib.util.spec_from_file_location("eval_adversarial_fp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CORPUS


def percentile(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil((p / 100.0) * len(s)) - 1))
    return s[k]


async def main():
    corpus = _load_corpus()
    g = AdversarialGuardrail()
    print(f"backend = {os.environ['LLM_BACKEND_URL']}  |  prompt = working tree "
          f"(guardrails/input/adversarial.py)\n")

    benign_total = benign_fp = attack_total = attack_miss = 0
    fps = []
    lat = []
    print(f"{'verdict':7} {'group':16} {'detail':30} prompt")
    print("-" * 100)
    for group, prompt, expect_safe in corpus:
        res = await g.check(prompt)
        blocked = not res.passed
        det = res.details or {}
        atype = det.get("attack_type", "none")
        conf = det.get("confidence", 0.0)
        detail = f"{atype}@{conf}" if blocked else "-"
        if res.latency_ms:
            lat.append(res.latency_ms)
        if expect_safe:
            benign_total += 1
            if blocked:
                benign_fp += 1
                verdict = "FALSE+"
                fps.append((group, prompt, detail))
            else:
                verdict = "ok"
        else:
            attack_total += 1
            if blocked:
                verdict = "ok"
            else:
                attack_miss += 1
                verdict = "MISS"
        print(f"{verdict:7} {group:16} {detail:30.30} {prompt[:46]}")

    fp_rate = benign_fp / benign_total if benign_total else 0.0
    recall = (attack_total - attack_miss) / attack_total if attack_total else 1.0
    print("\n" + "=" * 60)
    if fps:
        print("False positives (benign blocked):")
        for group, prompt, detail in fps:
            print(f"  [{group}] {detail}  <- {prompt}")
    print(f"\nBenign:  {benign_total - benign_fp}/{benign_total} passed | "
          f"FALSE POSITIVES {benign_fp}/{benign_total} = {fp_rate*100:.1f}%")
    print(f"Attacks: {attack_total - attack_miss}/{attack_total} blocked | "
          f"recall {recall*100:.1f}%" +
          (f" | MISSED {attack_miss}" if attack_miss else ""))
    print(f"adversarial latency_ms: p50={percentile(lat,50):.1f} "
          f"p95={percentile(lat,95):.1f} (n={len(lat)})")
    print("=" * 60)

    # best-effort cleanup of shared httpx/requests clients
    try:
        from core.llm_backend import _close_shared_clients
        await _close_shared_clients()
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(main())
