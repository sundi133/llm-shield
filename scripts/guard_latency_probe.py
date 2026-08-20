"""Guard-path latency decomposition. Run before and after a deploy.

Splits wall time into network / pipeline / everything-else. The last column is
the one that matters: work the caller pays for that inference_time_ms does not
report.

    SHIELD_API_KEY=... python scripts/guard_latency_probe.py

Read the KEYED vs ANONYMOUS rows together, not the absolute numbers. Both hit
the same endpoint with the same payload; the only difference is whether a tenant
key is sent, which is exactly what gates the metrics write-back. Anonymous
unreported overhead is the floor (measured 6-45ms); keyed should match it once
the write is off the request path.

Absolute figures are NOT reproducible across days. Between 2026-08-19 and
2026-08-20 the pipeline moved 700ms -> 2900ms and the metrics write moved
1630ms -> 440ms, in opposite directions. Quote the keyed-minus-anonymous delta,
never a single p50.

Spec: docs/spec-metrics-off-hot-path.md
"""
import os
import statistics
import time

import httpx

KEY = os.environ["SHIELD_API_KEY"]
HOST = os.environ.get("SHIELD_BASE_URL", "https://api.guardrails.votal.ai")
MSG = os.environ.get("PROBE_MSG", "What time does the office open?")
N = int(os.environ.get("PROBE_N", "6"))

c = httpx.Client(timeout=90)
p = statistics.median


def sample(headers):
    """One request. Wall measured strictly around the call."""
    t0 = time.time()
    r = c.post(f"{HOST}/guardrails/input", headers=headers, json={"message": MSG})
    wall = (time.time() - t0) * 1000
    try:
        srv = float(r.json().get("inference_time_ms") or 0)
    except Exception:
        srv = 0.0
    return wall, srv, r.status_code


def floor():
    t0 = time.time()
    c.get(f"{HOST}/health")
    return (time.time() - t0) * 1000


def run(label, headers):
    walls, srvs = [], []
    for _ in range(N):
        w, s, code = sample(headers)
        if code != 200:
            print(f"  {label}: HTTP {code} - skipping")
            return None
        walls.append(w)
        srvs.append(s)
    return p(walls), p(srvs)


print(f"  host {HOST}")
print(f"  msg  {MSG!r}   n={N}\n")

net = p([floor() for _ in range(N)])
keyed = run("keyed", {"X-API-Key": KEY, "Content-Type": "application/json"})
anon = run("anon", {"Content-Type": "application/json"})

print(f"  {'':<10} {'wall':>9} {'pipeline':>10} {'network':>9} {'UNREPORTED':>12}")
for label, res in (("keyed", keyed), ("anonymous", anon)):
    if not res:
        continue
    w, s = res
    print(f"  {label:<10} {w:9.0f} {s:10.0f} {net:9.0f} {w - s - net:12.0f}")

if keyed and anon:
    gap = (keyed[0] - keyed[1] - net) - (anon[0] - anon[1] - net)
    print(f"\n  tenant-gated overhead: {gap:.0f} ms")
    print("  (the metrics write-back; measured 340-1630 ms before the fix,")
    print("   varies with store latency. Should be ~0 after.)")
    print(f"\n  header reports {keyed[1] / keyed[0] * 100:.0f}% of what the caller waits "
          f"(understates {keyed[0] / max(keyed[1], 1):.1f}x)")
