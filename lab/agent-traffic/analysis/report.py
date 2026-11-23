"""Build the before/after page from analysis JSON files.

    python report.py --detect wave1 --enforce wave2 [--out state/reports/demo.html]

--detect   the analysis of the first fleet wave (SIEM rules vs Shield detection)
--enforce  the analysis of the second wave, run after Shield published
           indicators to the edge (containment)
"""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent


def _load(name):
    return json.loads((LAB / "state" / "analysis" / f"{name}.json").read_text()) if name else None


def _pct(r):
    return f"{r['count']} of {r['of']}" if r["of"] else "none"


def _esc(x):
    return html.escape(str(x))


def _cell(n, of):
    return f"{n} of {of}" if of else "none"


def _three_columns(d: dict) -> str:
    b, a, t = d["before"], d["after"], d.get("after_tag")
    cards = [
        f"""<div class="card bad"><h3>SIEM correlation rules</h3>
  <p class="big">{_pct(b['agent_sessions_caught'])}</p><p>agent sessions alerted</p>
  <p>People alerted: {_pct(b['human_sessions_alerted'])}</p></div>""",
        f"""<div class="card"><h3>Shield on logs only</h3>
  <p class="big">{_pct(a['agent_sessions_flagged'])}</p><p>agent sessions flagged
  ({a['agent_sessions_clear']['count']} clear by statistics, {a['agent_sessions_in_fleet']['count']} in a fleet)</p>
  <p>People flagged: {_pct(a['human_sessions_flagged'])}</p></div>"""]
    if t:
        cards.append(f"""<div class="card good"><h3>Shield with the tag</h3>
  <p class="big">{_pct(t['agent_sessions_flagged'])}</p><p>agent sessions flagged
  ({t['agent_sessions_clear']['count']} clear, {t['agent_sessions_in_fleet']['count']} in a fleet).
  Without the automation-trace check (A8), which a careful operator hides: {_pct(t['agent_sessions_flagged_without_a8'])}.</p>
  <p>People flagged: {_pct(t['human_sessions_flagged'])}</p>
  <p class="muted">Tag joined by cookie on {_pct(t['tag_joined'])} sessions,
  by fallback on {t['tag_fallback_join']['count']}.</p></div>""")
    return f'<div class="cols">{"".join(cards)}</div>'


def _breakdown(d: dict) -> str:
    rows = []
    names = {"observe": {"dom": "Reads page text (DOM)", "screen": "Screenshots only"},
             "sandbox": {"local": "Browser on this machine", "docker": "Sandbox container"}}
    for dim, groups in (d.get("breakdown") or {}).items():
        for val, g in groups.items():
            rows.append(f"<tr><td>{_esc(names.get(dim, {}).get(val, val or 'unknown'))}</td><td>{g['agents']}</td>"
                        f"<td>{g['siem']}</td><td>{g['logs']}</td><td>{g['tag']}</td></tr>")
    if not rows:
        return ""
    return ("<h3>By how the agent sees the page, and where it runs</h3><div class='wrap'><table><thead><tr>"
            "<th>Agents</th><th>Sessions</th><th>SIEM rules</th><th>Shield, logs</th><th>Shield, tag</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")


DETECTOR_NAMES = {"A1": "Model-latency rhythm", "A2": "Form fill timing", "A3": "Error recovery loop",
                  "A4": "Goal-directed navigation", "A5": "Hidden traps", "A6": "Client traits",
                  "A7": "Interaction (tag)", "A8": "Automation traces (tag)", "A9": "Environment (tag, supporting)",
                  "A10": "Tag missing or contradicting", "A11": "Forged agent identity", "A12": "Decoys"}


def _detectors(d: dict) -> str:
    t = d.get("after_tag")
    if not t or "detector_hits_on_agents" not in t:
        return ""
    ha, hh = t["detector_hits_on_agents"], t["detector_hits_on_humans"]
    rows = "".join(f"<tr><td>{k}</td><td>{_esc(DETECTOR_NAMES.get(k, ''))}</td><td>{_cell(ha.get(k, 0), d['agents'])}</td>"
                   f"<td>{_cell(hh.get(k, 0), d['humans'])}</td></tr>" for k in DETECTOR_NAMES)
    return ("<h3>Which checks fired</h3><div class='wrap'><table><thead><tr><th>ID</th><th>Check</th>"
            f"<th>Agent sessions</th><th>People</th></tr></thead><tbody>{rows}</tbody></table></div>")


def _traps_decoys_declared(d: dict) -> str:
    out = []
    tr = d.get("traps")
    if tr:
        bi, bo = tr["by_inert"], tr["by_observe"]
        out.append(f"""<div class="card"><h3>Hidden traps</h3>
  <p>Agents that followed a trap with their own code: {_pct(bi['not_inert'])} when the trap was not
  <code>inert</code>, {_pct(bi['inert'])} when it was.</p>
  <p>Page-text agents {_pct(bo['dom'])}; screenshot agents {_pct(bo['screen'])} (they never see a hidden trap).</p>
  <p>People with only a honeypot value (autofill): {_pct(tr['t4_only_humans'])}.</p></div>""")
    dc = d.get("decoys")
    if dc:
        by = ", ".join(f"{k} {v}" for k, v in dc["by_decoy"].items())
        out.append(f"""<div class="card"><h3>Decoys</h3>
  <p>Agent sessions that touched a decoy: {_pct(dc['agent_sessions_touching'])}; that followed its instruction
  or used the fake key: {_pct(dc['agent_sessions_following'])}.</p><p>By decoy: {_esc(by)}.</p>
  <p>People who touched one: {_pct(dc['human_sessions_touching'])}.</p></div>""")
    de = d.get("declared")
    if de and (de["declared_agents_labeled"]["of"] or de["unknown_operator_reported"]["of"] or de["forged_caught_a11"]["of"]):
        out.append(f"""<div class="card"><h3>Declared agents (Web Bot Auth)</h3>
  <p>Signed by an allowed operator and labeled declared: {_pct(de['declared_agents_labeled'])}.</p>
  <p>Signed by an operator not yet allowed, reported: {_pct(de['unknown_operator_reported'])}.</p>
  <p>Forged signatures caught (A11): {_pct(de['forged_caught_a11'])}.</p>
  <p>Declared agents put in a fleet or an indicator: {de['declared_in_any_fleet_or_indicator']}.</p></div>""")
    return f'<h3>Traps, decoys and declared agents</h3><div class="cols">{"".join(out)}</div>' if out else ""


def build(detect: dict, enforce: dict | None) -> str:
    b, a = detect["before"], detect["after"]
    t = detect.get("after_tag")
    m = detect["run_manifests"][0] if detect["run_manifests"] else {}
    usage = {k: sum(x.get("usage", {}).get(k, 0) for x in detect["run_manifests"])
             for k in ("calls", "input_tokens", "output_tokens")}
    rows = []
    for s in detect["per_session"]:
        if s["truth"] not in ("agent", "human", "declared_agent"):
            continue
        tag = s.get("tag") or {}
        reasons = tag.get("reasons") or s["reasons"]
        if s.get("declared"):
            label = "declared agent" if s["declared"] == "declared" else "declared, operator not allowed"
            reasons = [f"Web Bot Auth: {label} ({s.get('wba') and ', '.join(s['wba'])}); kept out of fleets "
                       f"and indicators"] + reasons
        rows.append(
            f"<tr><td>{_esc(s['truth'].replace('_', ' '))}</td><td>{_esc(s.get('observe', ''))}</td>"
            f"<td>{_esc(s.get('sandbox', ''))}</td><td>{_esc(s['ip'])}</td><td>{s['pages']}</td>"
            f"<td>{'yes' if s['siem_alerted'] else 'no'}</td>"
            + ((f"<td colspan='2'>{_esc(s['declared'].replace('_', ' '))}</td>") if s.get("declared") else
               (f"<td>{s['score']:.2f} {_esc(s['band'].replace('_', ' '))}</td>"
                f"<td>{(str(round(tag['score'], 2)) + ' ' + tag['band'].replace('_', ' ')) if tag else ''}</td>")) +
            f"<td>{_esc(tag.get('fleet') or s['fleet'] or '')}</td>"
            f"<td>{'<br>'.join(_esc(r) for r in reasons)}</td></tr>")
    fleet_src = (t or a)["fleets"]
    fleets = "".join(
        f"<li><b>{_esc(f['id'])}</b>: {f['size']} sessions across {f['networks']} networks, "
        f"{f['signups']} sign-ups, {f['promos']} promotions redeemed, {f['orders']} orders. "
        f"Linked by: {_esc(', '.join(f'{k} ({v} pairs)' for k, v in f['linking_traits'].items()))}</li>"
        for f in fleet_src) or "<li>No fleet found.</li>"
    alerts = "".join(f"<li>{_esc(x['rule'])} {_esc(x['description'])}: {_esc(x['entity'])}</li>"
                     for x in b["alerts"]) or "<li>No alerts.</li>"
    ind = detect["indicators"]
    withheld = "".join(f"<li>{_esc(w.get('type'))}: {_esc(w.get('why'))}</li>" for w in ind["withheld"])

    enforce_html = ""
    if enforce:
        c, c1 = enforce["containment"], detect["containment"]
        enforce_html = f"""
<h2>Wave 2: the same fleet again, after Shield published indicators</h2>
<div class="cols">
 <div class="card"><h3>Without Shield (wave 1)</h3>
  <p class="big">{c1['promos_redeemed_by_agents']}</p><p>promotions redeemed by agents</p>
  <p class="big">{c1['orders_by_agents']}</p><p>orders placed by agents</p></div>
 <div class="card good"><h3>With Shield indicators at the edge (wave 2)</h3>
  <p class="big">{c['promos_redeemed_by_agents']}</p><p>promotions redeemed by agents</p>
  <p class="big">{_pct(c['agent_sessions_challenged_at_first_request'])}</p><p>agent sessions challenged at their first request</p>
  <p>People challenged: {_pct(c['human_sessions_challenged'])}</p></div>
</div>"""

    when = datetime.fromtimestamp(detect["analyzed_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scripted = "scripted" in str(m.get("model", ""))
    warn = ("<p class='card bad'><b>Plumbing run.</b> These agents followed a fixed script, not a model. "
            "The numbers test the lab, they are not detection results.</p>") if scripted else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent detection lab report</title>
<style>
:root{{--bg:#fff;--fg:#1b2433;--muted:#5b6474;--line:#dcd9cf;--accent:#2457c5;--good:#e9f3ec;--bad:#fbecec}}
@media (prefers-color-scheme: dark){{:root{{--bg:#14171c;--fg:#e8eaee;--muted:#a2a9b5;--line:#30353e;--accent:#7aa2ff;--good:#173322;--bad:#3a1c1c}}}}
body{{background:var(--bg);color:var(--fg);font-family:Arial,system-ui,sans-serif;margin:0;padding:24px 16px;line-height:1.5}}
main{{max-width:1100px;margin:0 auto}}h1{{font-size:26px}}h2{{font-size:20px;margin-top:36px}}
.muted{{color:var(--muted)}}.cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}
.card{{border:1px solid var(--line);border-radius:12px;padding:16px}}.card.good{{background:var(--good)}}.card.bad{{background:var(--bad)}}
.big{{font-size:34px;font-weight:700;margin:6px 0 0}}table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}}.wrap{{overflow-x:auto}}
code{{font-size:12px}}
</style></head><body><main>
<h1>AI agent fleet on a test shop: SIEM rules vs Shield</h1>
{warn}<p class="muted">{_esc(detect['agents'])} LLM browser agents ({_esc(m.get('model', ''))}, one controller, each on
its own simulated home IP) and {_esc(detect['humans'])} human sessions on the lab shop. Analysis {when}.
Agent run cost: {usage['calls']} model calls, {usage['input_tokens']:,} input and {usage['output_tokens']:,} output
tokens.</p>

<h2>Wave 1: detection, three ways on the same sessions</h2>
{_three_columns(detect)}
<details><summary>SIEM alerts</summary><ul>{alerts}</ul></details>
{_breakdown(detect)}
{_detectors(detect)}
{_traps_decoys_declared(detect)}
<h3>Fleets{' (with the tag)' if t else ''}</h3><ul>{fleets}</ul>
<h3>Indicators handed to the edge</h3>
<p>{len(ind['sessions'])} sessions, {len(ind['accounts'])} accounts suspended through the SOAR stand-in,
{len(ind['fingerprints'])} client fingerprints, {len(ind['networks'])} networks.</p>
{f'<p>Withheld by the prevalence check:</p><ul>{withheld}</ul>' if withheld else ''}
{enforce_html}
<h2>Every session in wave 1</h2>
<div class="wrap"><table><thead><tr><th>Truth</th><th>Sees</th><th>Runs in</th><th>IP</th><th>Pages</th>
<th>SIEM alert</th><th>Shield, logs</th><th>Shield, tag</th><th>Fleet</th><th>Reasons</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<p class="muted">Lab only: agents ran against a local test shop. IPs are simulated residential proxies. Detector weights
are starting values from this lab, not production measurements.</p>
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--detect", required=True)
    ap.add_argument("--enforce")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = Path(args.out) if args.out else LAB / "state" / "reports" / f"{args.detect}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(_load(args.detect), _load(args.enforce)))
    print(out)


if __name__ == "__main__":
    main()
