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

Every session is scored twice: from the log alone ("after") and with the
tier 2 tag's beacons ("after_tag"), so the tag's gain is measured on the same
sessions. Indicators are published from the tag column when beacons exist.
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

import beacons  # noqa: E402
import detect  # noqa: E402
import tier2  # noqa: E402
import siem_rules  # noqa: E402
import trapcheck  # noqa: E402
from sessions import build_sessions, load_events  # noqa: E402

HUMAN_PREFIXES = ("192.168.65.", "172.17.", "172.18.", "127.")
TOOLING_UA = ("curl/", "python-requests", "Wget")
PREVALENCE_MAX = 0.001
DETECTOR_IDS = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12")


def _ts(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value).timestamp()


def truth_for(s, agent_ips: set, declared_ips: set = frozenset()) -> str:
    if s.ip in declared_ips:
        return "declared_agent"
    if s.ip in agent_ips:
        return "agent"
    if any(s.ua.startswith(t) for t in TOOLING_UA):
        return "tooling"
    if s.ip.startswith(HUMAN_PREFIXES):
        return "human"
    return "unknown"


def indicators(fleets, verdicts, sessions, enforce_clear_agents=True, exclude=frozenset()):
    """Spec section 5: only confirmed fleets and clear agents; prevalence check on fingerprints and networks.

    `exclude`: declared agents from allowed operators, never indicators (spec 2.5).
    """
    by_key = {s.key: s for s in sessions}
    flagged = set()
    for f in fleets:
        flagged |= set(f["members"])
    if enforce_clear_agents:
        flagged |= {k for k, v in verdicts.items() if v.band == "clear_agent"}
    flagged -= set(exclude)
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


async def review_grey(grey, by_key, fleets_of, tags=None):
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
        if tags is not None:
            t = tags[v.key]
            features |= {"tag_joined": t.joined, "graphics_class": t.device.get("renderer_class"),
                         "interaction": t.interaction() if t.joined else None}
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
    ap.add_argument("--declared-allow", nargs="*", default=["https://operator-a.agents.example"],
                    help="key directory URLs of agent operators this tenant allows (spec 2.5)")
    ap.add_argument("--no-baseline-update", action="store_true",
                    help="don't add this window's unflagged devices to the prevalence baseline")
    args = ap.parse_args()

    manifests = [json.loads((LAB / "state" / "runs" / r / "manifest.json").read_text()) for r in args.runs]
    agent_ips = {a["ip"] for m in manifests for a in m["agents"]}
    agent_meta = {a["ip"]: {"observe": a.get("observe", "dom"), "sandbox": a.get("sandbox", "local"),
                            "declare": a.get("declare", "none")}
                  for m in manifests for a in m["agents"]}
    declared_ips = {ip for ip, meta in agent_meta.items() if meta["declare"] in ("allowed", "unknown")}
    since = _ts(args.since) if args.since else (min(m["started"] for m in manifests) - 5 if manifests else 0)
    until = _ts(args.until) if args.until else (max(m["ended"] for m in manifests) + 5 if manifests else time.time())

    events = load_events(LAB / "state" / "logs" / "access.jsonl", since, until)
    sessions = build_sessions(events)
    trapcheck.resolve(sessions, trapcheck.traps.secret(LAB / "state"))
    by_key = {s.key: s for s in sessions}
    truth = {s.key: truth_for(s, agent_ips, declared_ips) for s in sessions}
    sessions = [s for s in sessions if truth[s.key] != "tooling"]

    # Before: SIEM rules.
    alerts = siem_rules.run([e for e in events if not any(e["ua"].startswith(t) for t in TOOLING_UA)])
    alerted_ips = {a["entity"] for a in alerts if a["entity_type"] == "ip"}
    alerted_accts = {a["entity"] for a in alerts if a["entity_type"] == "acct"}
    caught_before = {s.key for s in sessions if s.ip in alerted_ips or (s.account and s.account in alerted_accts)}

    # Declared agents (spec 2.5): labeled from the edge's Web Bot Auth fields, kept out of fleets and indicators.
    allow = set(args.declared_allow)
    declared_of = {s.key: detect.declared(s, allow) for s in sessions}
    # Both labels are exempt from impersonation fleets and indicators: a valid signature says who it is.
    # Unknown operators are reported for the customer to allow or limit.
    exempt = {k for k, d in declared_of.items() if d}

    # After: Shield on logs only.
    verdicts = {s.key: detect.score_session(s) for s in sessions}
    fleets = detect.find_fleets(sessions, min_size=args.min_size, exclude=exempt)
    fleet_of = {k: f["id"] for f in fleets for k in f["members"]}

    # After, with the tag: the same sessions plus their beacons.
    tags = beacons.attach(sessions, beacons.load_beacons(LAB / "state" / "logs" / "beacons.jsonl", since, until + 120))
    baseline = tier2.DeviceBaseline(LAB / "state" / "baseline_devices.json")
    verdicts_t = {s.key: detect.score_session(s, tags[s.key]) for s in sessions}
    verdicts_t_no_a8 = {s.key: detect.score_session(s, tags[s.key], include_a8=False) for s in sessions}
    fleets_t = detect.find_fleets(sessions, min_size=args.min_size, tags=tags, rare_device=baseline.rare,
                                  exclude=exempt)
    fleet_of_t = {k: f["id"] for f in fleets_t for k in f["members"]}
    has_tag = any(t.joined for t in tags.values())

    review, review_usage, review_model = {}, None, None
    review_t, review_t_usage = {}, None
    if args.review:
        grey = [v for v in verdicts.values() if v.band == "grey"]
        if grey:
            review, review_usage, review_model = asyncio.run(review_grey(grey, by_key, fleet_of))
        grey_t = [v for v in verdicts_t.values() if v.band == "grey"]
        if grey_t and has_tag:
            review_t, review_t_usage, _ = asyncio.run(review_grey(grey_t, by_key, fleet_of_t, tags))

    def flagged(k):
        v = verdicts[k]
        if k in exempt:
            return False
        return v.band == "clear_agent" or k in fleet_of or (review.get(k, {}).get("decision") == "raise")

    def flagged_t(k, vs=None):
        v = (vs or verdicts_t)[k]
        if k in exempt:
            return False
        return v.band == "clear_agent" or k in fleet_of_t or (review_t.get(k, {}).get("decision") == "raise")

    def rate(keys, pred):
        keys = list(keys)
        return {"count": sum(pred(k) for k in keys), "of": len(keys)}

    agents = [s.key for s in sessions if truth[s.key] == "agent"]
    humans = [s.key for s in sessions if truth[s.key] == "human"]
    ind = (indicators(fleets_t, verdicts_t, sessions, exclude=exempt) if has_tag
           else indicators(fleets, verdicts, sessions, exclude=exempt))
    if not args.no_baseline_update:
        # Production counterpart: hourly prevalence counters of non-fleet sessions (spec 3.4, 8).
        baseline.add(tags[k].device_hash for k in by_key
                     if k in verdicts_t and not flagged_t(k) and truth[k] != "tooling")
        baseline.save()
    if args.publish:
        publish(ind)

    result = {
        "name": args.name, "runs": args.runs, "window": [since, until], "analyzed_at": time.time(),
        "sessions": len(sessions), "agents": len(agents), "humans": len(humans),
        "declared": {
            "allow_list": sorted(allow),
            "declared_agents_labeled": rate([k for k in by_key if truth.get(k) == "declared_agent"
                                             and agent_meta.get(by_key[k].ip, {}).get("declare") == "allowed"],
                                            lambda k: declared_of[k] == "declared"),
            "unknown_operator_reported": rate([k for k in by_key if truth.get(k) == "declared_agent"
                                               and agent_meta.get(by_key[k].ip, {}).get("declare") == "unknown"],
                                              lambda k: declared_of[k] == "declared_unknown"),
            "forged_caught_a11": rate([k for k in agents if agent_meta.get(by_key[k].ip, {}).get("declare") == "forged"],
                                      lambda k: bool(verdicts[k].signals.get("A11"))),
            "by_operator": {op: sum(1 for k, d in declared_of.items() if d and by_key[k].wba_agent == op)
                            for op in sorted({by_key[k].wba_agent for k, d in declared_of.items() if d})},
            "declared_in_any_fleet_or_indicator": sum(1 for k in exempt if k in fleet_of or k in fleet_of_t
                                                      or k in ind["sessions"]),
            # Signed agents that touch decoys are reported by operator: being signed doesn't excuse it (spec 2.6).
            "decoy_touches_by_operator": {op: sum(1 for k, d in declared_of.items()
                                                  if d and by_key[k].wba_agent == op and by_key[k].decoy_hits)
                                          for op in sorted({by_key[k].wba_agent for k, d in declared_of.items() if d})},
        },
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
        "decoys": {
            "agent_sessions_touching": rate(agents, lambda k: any(h[:2] in ("D1", "D2", "D3", "D4")
                                                                 for h in by_key[k].decoy_hits)),
            "agent_sessions_following": rate(agents, lambda k: any(h.endswith("f") or h == "D3k" or "x:" in h
                                                                  for h in by_key[k].decoy_hits)),
            "human_sessions_touching": rate(humans, lambda k: bool(by_key[k].decoy_hits)),
            "by_decoy": {d: sum(1 for k in agents if d in by_key[k].decoy_hits) for d in ("D1", "D2", "D4")},
        },
        "after_tag": {
            "tag_joined": rate(agents + humans, lambda k: tags[k].join == "shs"),
            "tag_fallback_join": rate(agents + humans, lambda k: tags[k].join == "fallback"),
            "agent_sessions_flagged": rate(agents, flagged_t),
            "agent_sessions_flagged_without_a8": rate(agents, lambda k: flagged_t(k, verdicts_t_no_a8)),
            "agent_sessions_clear": rate(agents, lambda k: verdicts_t[k].band == "clear_agent"),
            "agent_sessions_in_fleet": rate(agents, lambda k: k in fleet_of_t),
            "human_sessions_flagged": rate(humans, flagged_t),
            "human_sessions_grey": rate(humans, lambda k: verdicts_t[k].band == "grey"),
            "detector_hits_on_agents": {d: sum(1 for k in agents if verdicts_t[k].signals.get(d))
                                        for d in DETECTOR_IDS},
            "detector_hits_on_humans": {d: sum(1 for k in humans if verdicts_t[k].signals.get(d))
                                        for d in DETECTOR_IDS},
            "fleets": fleets_t,
            "review": {"usage": review_t_usage, "decisions": review_t},
            "baseline_sessions": baseline.sessions,
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
            {**by_key[k].summary(), "truth": truth[k], **agent_meta.get(by_key[k].ip, {}), "score": verdicts[k].score, "band": verdicts[k].band,
             "reasons": verdicts[k].reasons, "fleet": fleet_of.get(k), "siem_alerted": k in caught_before,
             "review": review.get(k), "declared": declared_of[k], "wba": sorted(by_key[k].wba),
             "tag": {"join": tags[k].join, "graphics": tags[k].device.get("renderer_class"),
                     "device_hash": tags[k].device_hash, "interaction": tags[k].interaction() if tags[k].joined else None,
                     "score": verdicts_t[k].score, "band": verdicts_t[k].band, "reasons": verdicts_t[k].reasons,
                     "fleet": fleet_of_t.get(k), "review": review_t.get(k)}}
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
    t = result["after_tag"]
    print(f"  with the tag:        agent sessions flagged {t['agent_sessions_flagged']['count']}/{len(agents)} "
          f"(without A8 {t['agent_sessions_flagged_without_a8']['count']}, in fleet {t['agent_sessions_in_fleet']['count']}); "
          f"humans flagged {t['human_sessions_flagged']['count']}/{len(humans)}; tag joined {t['tag_joined']['count']}"
          f"/{t['tag_joined']['of']}")
    print(f"  indicators: {len(ind['sessions'])} sessions, {len(ind['accounts'])} accounts, "
          f"{len(ind['fingerprints'])} fingerprints, {len(ind['networks'])} networks, "
          f"{len(ind['withheld'])} withheld; published={args.publish}")
    c = result["containment"]
    print(f"  containment: agents challenged at first request {c['agent_sessions_challenged_at_first_request']['count']}"
          f"/{len(agents)}, promos by agents {c['promos_redeemed_by_agents']}, orders by agents {c['orders_by_agents']}")


if __name__ == "__main__":
    main()
