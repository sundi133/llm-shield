---
title: "AI Agent Detection: deployment runbook"
layout: default
nav_exclude: true
search_exclude: true
permalink: /agent-detection-deploy/
description: "How operators run Shield's AI agent detection: the collector and worker services, the tag on a CDN bucket, secrets, verification and day-two operations."
---

# AI Agent Detection: deployment runbook
{: .no_toc }

For operators. The customer-facing steps are in the
[integration guide]({{ "/agent-detection-integration/" | relative_url }}).
Design: `docs/specs/agent-impersonation-defense.md` (rev 8).

1. TOC
{:toc}

## What runs where

| Piece | Runs as | Faces | Needs |
|---|---|---|---|
| Portal and APIs (`/v1/agent-detection/*`, including the feed) | the existing admin service (`admin_app.py`) | the portal, and edges polling the feed | Redis |
| Collector | its own service: `python3 -m core.agent_detection.collector` | the internet (browsers send reports to it) | Redis, hash salt, trap secret |
| Worker | its own service: `python3 -m core.agent_detection.worker` | nothing (internal only) | Redis |
| The tag | static files on a CDN bucket (or the collector's `/shs.js`) | the internet | nothing |

All three services run from the **admin image** (`Dockerfile.admin`), CPU
only. None of it touches the guard path (`/guardrails/*`, `cap/mint`,
`tools/call`) or the data plane.

## Settings

| Variable | Where | Required | Meaning |
|---|---|---|---|
| `SHIELD_AGENT_DETECTION_HASH_SALT` | collector | yes | Salt for network hashes. `openssl rand -hex 32` |
| `SHIELD_AGENT_DETECTION_TRAP_SECRET` | collector | yes | Derives every tenant's trap codes. `openssl rand -hex 32` |
| `SHIELD_TRUST_PROXY_HEADERS` | collector | behind a proxy | `1` to read the visitor's address from `X-Forwarded-For` |
| `SHIELD_AGENT_DETECTION_TAG_URL` | admin | for real snippets | Where released tags live, e.g. `https://tag.votal.ai` |
| `SHIELD_AGENT_DETECTION_COLLECTOR_URL` | admin | for real snippets | The collector's public address, e.g. `https://collect.votal.ai` |
| `SHIELD_AGENT_DETECTION` | all | no | `off` hides the routes and stops the worker |
| `SHIELD_AGENT_DETECTION_COLLECTOR` | collector | no | `off` drops every report (still answers 204) |
| `SHIELD_AGENT_DETECTION_CYCLE_S` | worker | no | Seconds between cycles (default 30) |
| `SHIELD_AGENT_DETECTION_FLEET_S` | worker | no | Seconds between fleet recomputes (default 120) |
| `SHIELD_AGENT_DETECTION_FLEET_WINDOW_S` | worker | no | Sessions considered for fleets (default 21600, 6 hours) |

The collector refuses to start without the salt and the trap secret, so a
missing secret shows up at deploy time, not as silent data loss. Keep both
secrets out of the repo and out of chat.

## Railway

Add two services from this repository, both built with `Dockerfile.admin`:

| Service | Start command | Public domain | Variables |
|---|---|---|---|
| `agd-collector` | `python3 -m core.agent_detection.collector` | yes, e.g. `collect.votal.ai` | the admin service's Redis variables, the salt, the trap secret, `SHIELD_TRUST_PROXY_HEADERS=1` |
| `agd-worker` | `python3 -m core.agent_detection.worker` | no | the admin service's Redis variables |

On the admin service, set `SHIELD_AGENT_DETECTION_TAG_URL` and
`SHIELD_AGENT_DETECTION_COLLECTOR_URL`. The collector reads `PORT` from
Railway. Run one worker; it takes a per-tenant lock, so a second replica is
safe but not needed. The collector is stateless: add replicas for traffic.

## OpenShift

Add the `agent-detection` component to the overlay (see `openshift/README.md`):

```bash
oc create secret generic shield-agent-detection --from-literal=SHIELD_AGENT_DETECTION_HASH_SALT=$(openssl rand -hex 32) --from-literal=SHIELD_AGENT_DETECTION_TRAP_SECRET=$(openssl rand -hex 32)
```

It adds the collector (Deployment, Service, Route) and the worker (internal,
no Route), both reading only `REDIS_URL` from `shield-admin-secrets`, and
lets both reach Redis. Expose the collector's Route, or have the customer's
CDN forward `/_shs/` to it.

## The tag on a CDN bucket

One-time setup of a public GCS bucket behind Cloud CDN on your own domain
(commands in the header of `scripts/release_shs_tag.sh`): uniform access,
object versioning, public read, and the CORS rule in
`scripts/shs_tag_cors.json`. The CORS rule is required: a browser checks an
integrity hash on a cross-origin script only when the response allows it.

Each release:

```bash
scripts/release_shs_tag.sh <bucket> tag.votal.ai
```

It uploads `shs-<version>.js` from `static/agent-detection/shs.js`, refuses to
overwrite a published version, sets a one-year immutable cache, checks the CDN
copy and its CORS header, and prints the snippet with the integrity hash. It
runs with your own `gcloud` login. A tag change needs a new `@version` in the
file's first line; customers move to it by pasting the new snippet.

## Verify a deployment

1. `GET https://<collector>/health` answers `{"ok": true, "collector": "on"}`.
2. In the portal, create a site key for a test page, add the snippet, load
   the page: the **Tag** page shows **reporting** within seconds.
3. The worker's log shows a cycle for that tenant, and **Detections** with
   **All sessions** lists the visit.
4. Create a feed token and fetch the feed: `200` with an empty list in watch
   mode, then the indicators once a type is enforced.

## Operating it

- **Kill switch:** **Enforcement**, then **Kill switch: clear all**, or
  `POST /v1/agent-detection/indicators/clear`. Edges stop challenging at their
  next poll. Resume from the same page.
- **Rotating the trap secret** changes every code at once: hidden-trap hits
  from sessions already in progress stop matching for that day. Rotate
  between busy periods.
- **Rotating the hash salt** changes network hashes: fleets in progress lose
  their network trait until new sessions arrive.
- **Redis:** each tenant's report stream is capped at about 200,000 entries;
  sessions, fleets and indicators expire on their own within a day. Redis must
  not evict keys (`noeviction`).
- **Detector pack:** weights and thresholds are in
  `core/agent_detection/pack.json` and every verdict records the pack version.
  The values are the lab's starting values; replace them from the first lab
  run with real agents and real people before quoting any rates.

## Rehearse it locally

The lab runs the whole product end to end (tag, collector, worker, feed and
an Nginx edge) against its own test shop:

```bash
cd lab/agent-traffic && AGENT_LLM_PROVIDER=scripted ./demo_product.sh <lab python>
```

See `lab/agent-traffic/DEMO.md`.
