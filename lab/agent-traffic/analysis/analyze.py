"""Analyze a window of the shop's access log: SIEM rules (before) vs Shield (after).

    python analyze.py --name wave1 --runs fleet10 [--since ISO|epoch] [--review] [--publish]

Ground truth comes from the run manifests: an agent session is one whose IP
belongs to an agent the controller launched. People browsing the shop arrive
without X-Forwarded-For (the Docker gateway address) and count as humans.

--review   send grey-zone sessions to the investigator agent (spec 4.3). It
           sees derived features only, never raw log strings, and it can
           raise a grey-zone session but never clear a statistical verdict.
--publish  write the enforcement maps for Nginx and the suspended-accounts
           list (the lab's stand-in for a SOAR playbook), then reload Nginx.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LAB / "agents"))

import detect  # noqa: E402
import siem_rules  # noqa: E402
from sessions import build_sessions, load_events  # noqa: E402

HUMAN_PREFIXES = ("192.168.65.", "172.17.", "172.18.", "127.")
TOOLING_UA = ("curl/", "python-requests", "Wget")
PREVALENCE_MAX = 0.001


def _ts(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value).timestamp()


def truth_for(s, agent_ips: set) -> str:
    if s.ip in agent_ips:
        return "agent"
    if any(s.ua.startswith(t) for t in TOOLING_UA):
        return "tooling"
    if s.ip.startswith(HUMAN_PREFIXES):
        return "human"
    return "unknown"


def indicators(fleets, verdicts, sessions, enforce_clear_agents=True):
    """Spec section 5: only confirmed fleets and clear agents; prevalence check on fingerprints and networks."""
    by_key = {s.key: s for s in sessions}
    flagged = set()
    for f in fleets:
        flagged |= set(f["members"])
    if enforce_clear_agents:
        flagged |= {k for k, v in verdicts.items() if v.band == "clear_agent"}
    others = [s for s in sessions if s.key not in flagged]
    out = {"sessions": sorted(flagged), "accounts": sorted({by_key[k].account for k in flagged if by_key[k].account}),
           "fingerprints": [], "networks": [], "withheld": []}
    for fp in sorted({by_key[k].fingerprint for k in flagged}):
        share = sum(o.fingerprint == fp for o in others) / max(1, len(others))
        if share < PREVALENCE_MAX:
            out["fingerprints"].append(fp)
        else:
            out["withheld"].append({"type": "fingerprint", "share_of_other_sessions": round(share, 4),
                                    "why": "shared by sessions outside the fleet"})
    fleet_keys = {k for f in fleets for k in f["members"]}
    for net in sorted({by_key[k].net24 for k in fleet_keys}):
        share = sum(o.net24 == net for o in others) / max(1, len(others))
        (out["networks"] if share < PREVALENCE_MAX else out["withheld"]).append(
            net if share < PREVALENCE_MAX else {"type": "network", "value": net, "why": "shared by other sessions"})
    return out


def _nginx_key(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def publish(ind: dict) -> None:
    shield = LAB / "state" / "shield"
    shield.mkdir(parents=True, exist_ok=True)
    (shield / "sid.map").write_text("".join(f'{_nginx_key(k)} "sid";\n' for k in ind["sessions"]))
    (shield / "fp.map").write_text("".join(f'{_nginx_key(fp)} "fp";\n' for fp in ind["fingerprints"]))
    (shield / "net.map").write_text("".join(
        f'~^{net.replace(".", chr(92) + ".")}\\. "net";\n' for net in ind["networks"]))
    (LAB / "state" / "suspended.json").write_text(json.dumps(ind["accounts"]))
    r = subprocess.run(["docker", "exec", "shield-lab-nginx", "nginx", "-s", "reload"], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"nginx reload failed: {r.stderr.strip()}")


REVIEW_SYSTEM = """You review web sessions that automated statistics scored as uncertain: they might be an AI agent
operating a browser, or a person. You get derived measurements only. Decide whether to raise a detection.
Raise only when the evidence, taken together, points to an automated agent. Otherwise choose no_action.
Explain in one or two plain sentences, citing the measurements."""
REVIEW_SCHEMA = {
    "type": "object",
    "properties": {"decision": {"type": "string", "enum": ["raise", "no_action"]},
                   "explanation": {"type": "string"}},
    "required": ["decision", "explanation"], "additionalProperties": False,
}


async def review_grey(grey, by_key, fleets_of):
    from llm import LLM
    llm = LLM.from_env()
    decisions = {}
    for v in grey:
        s = by_key[v.key]
        # Derived features only: no user agent, path or referrer strings reach the model.
        features = {
            "statistical_score": v.score, "detectors_fired": {k: x for k, x in v.signals.items() if x},
            "pages": len(s.events), "static_assets_loaded": s.assets,
            "median_action_gap_s": s.summary()["median_gap"],
            "funnel_steps_completed": s.signups + s.promos + s.orders,
            "browsing_pages_viewed": s.browsing_pages(),
            "in_fleet": fleets_of.get(v.key) is not None,
            "client_hint_mismatch": bool(v.signals.get("A6")),
        }
        out = await llm.json_call(REVIEW_SYSTEM, json.dumps(features), REVIEW_SCHEMA, max_tokens=2000)
        decisions[v.key] = out
    return decisions, llm.usage.__dict__, llm.describe()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--runs", nargs="*", default=[], help="run labels whose agents are ground truth")
    ap.add_argument("--since", default=None)
    ap.add_argument("--until", default=None)
    ap.add_argument("--min-size", type=int, default=10)
    ap.add_argument("--review", action="store_true")
    ap.add_argument("--publish", action="store_true")
    args = ap.parse_args()

    manifests = [json.loads((LAB / "state" / "runs" / r / "manifest.json").read_text()) for r in args.runs]
    agent_ips = {a["ip"] for m in manifests for a in m["agents"]}
    since = _ts(args.since) if args.since else (min(m["started"] for m in manifests) - 5 if manifests else 0)
    until = _ts(args.until) if args.until else (max(m["ended"] for m in manifests) + 5 if manifests else time.time())

    events = load_events(LAB / "state" / "logs" / "access.jsonl", since, until)
    sessions = build_sessions(events)
    by_key = {s.key: s for s in sessions}
    truth = {s.key: truth_for(s, agent_ips) for s in sessions}
    sessions = [s for s in sessions if truth[s.key] != "tooling"]

    # Before: SIEM rules.
    alerts = siem_rules.run([e for e in events if not any(e["ua"].startswith(t) for t in TOOLING_UA)])
    alerted_ips = {a["entity"] for a in alerts if a["entity_type"] == "ip"}
    alerted_accts = {a["entity"] for a in alerts if a["entity_type"] == "acct"}
    caught_before = {s.key for s in sessions if s.ip in alerted_ips or (s.account and s.account in alerted_accts)}

    # After: Shield.
    verdicts = {s.key: detect.score_session(s) for s in sessions}
    fleets = detect.find_fleets(sessions, min_size=args.min_size)
    fleet_of = {k: f["id"] for f in fleets for k in f["members"]}

    review, review_usage, review_model = {}, None, None
    if args.review:
        grey = [v for v in verdicts.values() if v.band == "grey"]
        if grey:
            review, review_usage, review_model = asyncio.run(review_grey(grey, by_key, fleet_of))

    def flagged(k):
        v = verdicts[k]
        return v.band == "clear_agent" or k in fleet_of or (review.get(k, {}).get("decision") == "raise")

    def rate(keys, pred):
        keys = list(keys)
        return {"count": sum(pred(k) for k in keys), "of": len(keys)}

    agents = [s.key for s in sessions if truth[s.key] == "agent"]
    humans = [s.key for s in sessions if truth[s.key] == "human"]
    ind = indicators(fleets, verdicts, sessions)
    if args.publish:
        publish(ind)

    result = {
        "name": args.name, "runs": args.runs, "window": [since, until], "analyzed_at": time.time(),
        "sessions": len(sessions), "agents": len(agents), "humans": len(humans),
        "before": {
            "alerts": alerts,
            "agent_sessions_caught": rate(agents, lambda k: k in caught_before),
            "human_sessions_alerted": rate(humans, lambda k: k in caught_before),
        },
        "after": {
            "agent_sessions_flagged": rate(agents, flagged),
            "agent_sessions_clear": rate(agents, lambda k: verdicts[k].band == "clear_agent"),
            "agent_sessions_in_fleet": rate(agents, lambda k: k in fleet_of),
            "human_sessions_flagged": rate(humans, flagged),
            "human_sessions_grey": rate(humans, lambda k: verdicts[k].band == "grey"),
            "new_vs_existing": {
                "new": sum(1 for k in agents + humans if flagged(k) and k not in caught_before),
                "already_alerted": sum(1 for k in agents + humans if flagged(k) and k in caught_before),
            },
            "fleets": fleets,
            "review": {"model": review_model, "usage": review_usage, "decisions": review},
        },
        "indicators": ind, "published": args.publish,
        "containment": {
            "agent_sessions_challenged_at_first_request": rate(agents, lambda k: by_key[k].first_request_enforced),
            "agent_sessions_with_any_challenge": rate(agents, lambda k: by_key[k].enforced_requests > 0),
            "human_sessions_challenged": rate(humans, lambda k: by_key[k].enforced_requests > 0),
            "promos_redeemed_by_agents": sum(by_key[k].promos for k in agents),
            "orders_by_agents": sum(by_key[k].orders for k in agents),
        },
        "per_session": [
            {**by_key[k].summary(), "truth": truth[k], "score": verdicts[k].score, "band": verdicts[k].band,
             "reasons": verdicts[k].reasons, "fleet": fleet_of.get(k), "siem_alerted": k in caught_before,
             "review": review.get(k)}
            for k in sorted(verdicts, key=lambda k: by_key[k].start)
        ],
        "run_manifests": [{k: v for k, v in m.items() if k != "agents"} | {"agents": m["agents"]} for m in manifests],
    }
    out_dir = LAB / "state" / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{args.name}.json").write_text(json.dumps(result, indent=2, default=str))

    b, a = result["before"], result["after"]
    print(f"{args.name}: {len(sessions)} sessions ({len(agents)} agent, {len(humans)} human)")
    print(f"  before (SIEM rules): {len(alerts)} alerts; agent sessions caught "
          f"{b['agent_sessions_caught']['count']}/{len(agents)}; humans alerted {b['human_sessions_alerted']['count']}/{len(humans)}")
    print(f"  after (Shield):      agent sessions flagged {a['agent_sessions_flagged']['count']}/{len(agents)} "
          f"(clear {a['agent_sessions_clear']['count']}, in fleet {a['agent_sessions_in_fleet']['count']}); "
          f"humans flagged {a['human_sessions_flagged']['count']}/{len(humans)}; fleets {len(fleets)}")
    print(f"  indicators: {len(ind['sessions'])} sessions, {len(ind['accounts'])} accounts, "
          f"{len(ind['fingerprints'])} fingerprints, {len(ind['networks'])} networks, "
          f"{len(ind['withheld'])} withheld; published={args.publish}")
    c = result["containment"]
    print(f"  containment: agents challenged at first request {c['agent_sessions_challenged_at_first_request']['count']}"
          f"/{len(agents)}, promos by agents {c['promos_redeemed_by_agents']}, orders by agents {c['orders_by_agents']}")


if __name__ == "__main__":
    main()
