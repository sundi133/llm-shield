"""Summary of a product-mode demo run (rev 8 step R8): what each wave got
done at the shop, and when the edge started challenging it.

    python3 product/summary.py <label>     (reads <label>-wave1 and <label>-wave2)

Ground truth from state/runs/<label>-waveN/manifest.json (which IPs were
agents), outcomes from the edge's access log, and Shield's own view from the
product admin API with this run's admin key. Standard library only.
"""
import json
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
STATE = LAB / "state"
API = "http://127.0.0.1:8205"


def api(path):
    key = (STATE / "product" / "admin_key").read_text().strip()
    req = urllib.request.Request(API + path, headers={"X-API-Key": key})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def rows():
    out = []
    for line in (STATE / "logs" / "access.jsonl").read_text().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        r["t"] = datetime.fromisoformat(r["ts"]).timestamp()
        out.append(r)
    return out


def wave(label, log):
    m = json.loads((STATE / "runs" / label / "manifest.json").read_text())
    agents = []
    for a in m["agents"]:
        mine = [r for r in log if r["ip"] == a["ip"] and a["started"] - 5 <= r["t"] <= a["ended"] + 5
                and not r["uri"].startswith(("/_shs/", "/static/"))]
        hit = [i for i, r in enumerate(mine) if r.get("enforced") == "1"]
        agents.append({"ip": a["ip"], "requests": len(mine), "promos": sum(r.get("event") == "promo" for r in mine),
                       "orders": sum(r.get("event") == "order" for r in mine),
                       "first_challenge": (hit[0] + 1) if hit else None})
    return agents


def show(name, agents):
    stopped = [a for a in agents if a["first_challenge"]]
    print(f"{name}: {len(agents)} agents, {sum(a['promos'] for a in agents)} promotions redeemed, "
          f"{sum(a['orders'] for a in agents)} orders, {len(stopped)} challenged")
    if stopped:
        firsts = sorted(a["first_challenge"] for a in stopped)
        print(f"  challenged at page request #{firsts[0]} at the earliest, #{firsts[len(firsts) // 2]} "
              f"typically (the window before the first beacon and the next feed poll)")


def main():
    label = sys.argv[1]
    log = rows()
    w1, w2 = wave(f"{label}-wave1", log), wave(f"{label}-wave2", log)
    print("== product mode: tag, collector, worker, feed and edge are Shield's shipping code")
    show("wave 1 (watch mode, nothing enforced)", w1)
    show("wave 2 (session cookie and browser signature enforced)", w2)
    fleets = api("/v1/agent-detection/fleets")["fleets"]
    stats = api("/v1/agent-detection/stats?days=1")
    print(f"Shield: {len(fleets)} fleet(s) "
          + ", ".join(f"{f['member_count']} sessions across {f['networks']} networks linked by "
                      + ", ".join(sorted(f["traits"])) for f in fleets)
          + f"; {stats['indicators_active']} indicators active; today {stats['days'][0].get('beacons', 0)} beacons, "
          f"{stats['days'][0].get('clear_agent', 0)} clear agents, {stats['days'][0].get('grey', 0)} grey")


if __name__ == "__main__":
    main()
