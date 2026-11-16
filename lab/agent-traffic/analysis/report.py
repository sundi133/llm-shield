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


def build(detect: dict, enforce: dict | None) -> str:
    b, a = detect["before"], detect["after"]
    m = detect["run_manifests"][0] if detect["run_manifests"] else {}
    usage = m.get("usage", {})
    rows = []
    for s in detect["per_session"]:
        if s["truth"] not in ("agent", "human"):
            continue
        rows.append(
            f"<tr><td>{_esc(s['truth'])}</td><td>{_esc(s['ip'])}</td><td>{s['pages']}</td>"
            f"<td>{_esc(s['median_gap'])}</td><td>{'yes' if s['siem_alerted'] else 'no'}</td>"
            f"<td>{s['score']:.2f} {_esc(s['band'].replace('_', ' '))}</td><td>{_esc(s['fleet'] or '')}</td>"
            f"<td>{'<br>'.join(_esc(r) for r in s['reasons'])}</td></tr>")
    fleets = "".join(
        f"<li><b>{_esc(f['id'])}</b>: {f['size']} sessions across {f['networks']} networks, "
        f"{f['signups']} sign-ups, {f['promos']} promotions redeemed, {f['orders']} orders. "
        f"Linked by: {_esc(', '.join(f'{k} ({v} pairs)' for k, v in f['linking_traits'].items()))}</li>"
        for f in a["fleets"]) or "<li>No fleet found.</li>"
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
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent fleet: before and after</title>
<style>
:root{{--bg:#fff;--fg:#1b2433;--muted:#5b6474;--line:#dcd9cf;--accent:#2457c5;--good:#e9f3ec;--bad:#fbecec}}
@media (prefers-color-scheme: dark){{:root{{--bg:#14171c;--fg:#e8eaee;--muted:#a2a9b5;--line:#30353e;--accent:#7aa2ff;--good:#173322;--bad:#3a1c1c}}}}
body{{background:var(--bg);color:var(--fg);font-family:Arial,system-ui,sans-serif;margin:0;padding:24px 16px;line-height:1.5}}
main{{max-width:1060px;margin:0 auto}}h1{{font-size:26px}}h2{{font-size:20px;margin-top:36px}}
.muted{{color:var(--muted)}}.cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}}
.card{{border:1px solid var(--line);border-radius:12px;padding:16px}}.card.good{{background:var(--good)}}.card.bad{{background:var(--bad)}}
.big{{font-size:34px;font-weight:700;margin:6px 0 0}}table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}}.wrap{{overflow-x:auto}}
</style></head><body><main>
<h1>AI agent fleet on a test shop: SIEM rules vs Shield</h1>
<p class="muted">{_esc(detect['agents'])} real LLM browser agents ({_esc(m.get('model', ''))}, one controller, each on its own
simulated home IP) and {_esc(detect['humans'])} human sessions on the lab shop. Analysis {when}.
Agent run cost: {usage.get('calls', 0)} model calls, {usage.get('input_tokens', 0):,} input and
{usage.get('output_tokens', 0):,} output tokens.</p>

<h2>Wave 1: detection</h2>
<div class="cols">
 <div class="card bad"><h3>Before: SIEM correlation rules</h3>
  <p class="big">{_pct(b['agent_sessions_caught'])}</p><p>agent sessions alerted</p>
  <p>Human sessions alerted: {_pct(b['human_sessions_alerted'])}</p><ul>{alerts}</ul></div>
 <div class="card good"><h3>After: Shield agent checks and fleet detection</h3>
  <p class="big">{_pct(a['agent_sessions_flagged'])}</p><p>agent sessions flagged
  ({a['agent_sessions_clear']['count']} clear by statistics, {a['agent_sessions_in_fleet']['count']} in a fleet)</p>
  <p>Human sessions flagged: {_pct(a['human_sessions_flagged'])}</p>
  <p>New detections {a['new_vs_existing']['new']}, already alerted by SIEM {a['new_vs_existing']['already_alerted']}</p></div>
</div>
<h3>Fleets</h3><ul>{fleets}</ul>
<h3>Indicators handed to the edge</h3>
<p>{len(ind['sessions'])} sessions, {len(ind['accounts'])} accounts suspended through the SOAR stand-in,
{len(ind['fingerprints'])} client fingerprints, {len(ind['networks'])} networks.</p>
{f'<p>Withheld by the prevalence check:</p><ul>{withheld}</ul>' if withheld else ''}
{enforce_html}
<h2>Every session in wave 1</h2>
<div class="wrap"><table><thead><tr><th>Truth</th><th>IP</th><th>Pages</th><th>Median gap (s)</th>
<th>SIEM alert</th><th>Shield score</th><th>Fleet</th><th>Reasons</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
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
