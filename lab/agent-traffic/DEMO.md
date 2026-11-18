# Customer demo runbook (about 15 minutes)

What the customer sees: a normal web shop, the hidden instructions only an AI
obeys, decoys, and a fleet of agents being detected and then stopped at the
edge on its second wave. It pairs with the deck *Shield AI Agent Detection*.

Everything runs on your laptop against the lab's own test shop. No customer
system is touched.

## Before the call (10 minutes)

1. Docker Desktop running. The sandbox image built once
   (`docker build -t shield-lab-sandbox:1.65.2 lab/agent-traffic/sandbox`); without
   it the fleet runs local browsers only.
2. Set `PY` to the lab Python (one-time setup in [README.md](README.md#setup-once),
   e.g. `PY=~/.venvs/shield-lab/bin/python`), then reset:
   ```bash
   cd lab/agent-traffic && ./demo_reset.sh "$PY"
   ```
   It prints this deployment's decoy paths. Note them for act 3.
3. **Pick the agents.**
   - *Scripted* (`AGENT_LLM_PROVIDER=scripted`): free, the fleet act takes about 2
     minutes, always behaves the same. The agents follow a fixed plan, not a
     model. Say so.
   - *Real model* (key in `~/.config/shield-lab/llm.env`): real Claude agents.
     Each agent takes minutes, and runs cost money. Run the fleet before the
     call, and show its report plus one live agent.
4. Arrange the screen: Chrome on `http://localhost:8180`, a terminal running
   `./watch_evidence.sh` (the live evidence feed), a second terminal for
   commands, and the deck.

## Act 1: a normal shop (2 minutes)

Browse the shop yourself: a product, the sign-up page. Point at the evidence
feed: each request appears as the customer's CDN or SIEM would log it.

> "This is the only data Shield needs to start: the logs you already have."

## Act 2: hidden instructions only an AI obeys (3 minutes)

1. Open `view-source:http://localhost:8180/signup` and search for `assistants`.
   Show the hidden instruction, the code that is different for every visitor,
   and the hidden link `/_shs/v/…`.
2. Back on the page: nothing is visible. Screen readers don't see it either.
3. Play the agent: copy the hidden link from the source into the address bar.
   The feed shows `<< TRAP LINK`.
4. Optional, one visible agent working the shop in a real Chrome window:
   ```bash
   cd agents && "$PY" fleet.py --n 1 --headed --slow-mo 300 --stagger 0 --label live-$(date +%H%M)
   ```
   Prefix `AGENT_LLM_PROVIDER=scripted` for the scripted agent. With a real model,
   whether it obeys a trap is exactly what the lab measures, so don't promise it
   will. The scripted agent never obeys traps.

> "A person never sees this. An AI reading the page does, and when it obeys, the code tells us which session it was."

## Act 3: decoys (2 minutes)

1. Open `/robots.txt`: it lists the hidden API under `Disallow`.
2. Open `/.env` (or the config path `demo_reset.sh` printed): fake secrets, and
   a note with a code for this visitor. The feed shows `<< DECOY D2`.
3. Open the API path from the note, then again with `?token=<the code>`. The
   feed shows `<< DECOY D4,D4f`: the instruction was followed.

> "No real customer ever needs these. Opening one proves little, scanners do it all day. Following the instruction inside proves an AI."

## Act 4: the fleet (5 minutes)

```bash
AGENT_LLM_PROVIDER=scripted ./demo_fleet.sh "$PY" acme
```
(Drop `AGENT_LLM_PROVIDER=scripted` for real agents.)

Narrate while it runs:
1. **Wave 1:** 12 agents, one controller, half of them in sandbox containers,
   each on its own home IP. They sign up, redeem the promotion, check
   out. The feed scrolls normally.
2. **Shield analyzes:** the printed lines compare SIEM rules, Shield on logs, and
   Shield with the tag, then publish indicators to the edge.
3. **Wave 2:** the same controller with new personas and IPs. The feed fills with
   `<< CHALLENGED`: stopped at the first request, no promotions, no orders.

### Act 4 on the product (recommended)

The same fleet act on Shield's shipping code: the product tag on the shop,
the product collector, worker and admin API, and Nginx polling the product
feed with a feed token.

```bash
AGENT_LLM_PROVIDER=scripted ./demo_product.sh "$PY"
```

It prints what each wave got done and when the edge started challenging. In
the scripted rehearsal (2026-11-18): wave 1 got 12 promotions and 12 orders;
Shield linked one fleet of 12 across 12 networks; with session cookies and
browser signatures enforced, wave 2 was challenged at its first request, with
no promotions and no orders. That first-request stop came from the fleet's
shared browser signature; a controller that varies its user agent per agent
is caught on its shared device instead, a few requests in. Plumbing only: these
agents are scripted, so the numbers are not detection rates.

Then show the portal at `http://localhost:8205/tenant` (sign in with the API
key in `state/product/admin_key`): Security Operations, AI Agent Detection.

## Act 5: the evidence (2 minutes)

The report opens in your browser. Walk through:
- the three columns on the same sessions;
- the fleet and the traits that linked it;
- the indicators, and what the prevalence check withheld;
- wave 2: promotions and orders before and after;
- the session table: every verdict has its reasons.

Then open `http://localhost:8180/challenge`: what a challenged agent got.

## What to say, honestly

- Scripted run: "These agents follow a fixed script so the demo is repeatable;
  the same harness runs real AI agents." The report shows a *Plumbing run*
  banner; don't present its numbers as detection rates.
- The product is in development; the lab shows how it works. No measured
  detection or false-positive rates exist yet.

## After the call

```bash
./demo_reset.sh "$PY"
```
Clears the indicators (your own browser is never challenged by them, but a
clean edge avoids surprises) and the shop's accounts.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `shop did not come up` | Docker isn't running, or port 8180 is taken |
| Every agent `error` with `sandbox:` | Build the sandbox image, or it falls back to local only on the next run |
| Your own browser gets the challenge page | Run `./demo_reset.sh "$PY"` |
| Real-model agents fail at once | No key in `~/.config/shield-lab/llm.env` (mode 600) |
| Feed shows nothing | Start `./watch_evidence.sh` before browsing; it shows new lines only |
