# Spec: AI agent and fleet detection from SIEM logs

Status: **draft rev 3, 2026-11-15, awaiting approval.** Branch `spec/agent-impersonation-defense`.

- Rev 2 moved detection to SIEM logs with no front-end SDK.
- Rev 3 narrows the scope to the two things a SIEM can't already do:
  1. detections built specifically for AI agents, backed by a maintained
     library of real agent traffic;
  2. fleet detection across new sessions that have no history.

  Everything that existing alerts already catch is out of scope, and existing
  alerts are read so Shield never raises a duplicate.

Reuses SIEM export (`core/siem_dispatcher.py`, `storage/siem_store.py`) and
ASIM shaping (`core/asim.py`).

## 1. Problem & outcome

**Problem.** One controlling AI runs many sandboxes, VMs or emulators, each
driving a browser or app like a real user. The customer's existing tools each
miss part of this:

| Existing tool | What it already catches (we don't rebuild it) | Why it misses this attack |
|---|---|---|
| SIEM threshold rules (Splunk correlation searches, Sentinel analytics rules, Elastic rules) | Volume per IP or account: brute force, failed-login spikes, sign-up bursts, password spraying | Agents go at human pace and spread across many IPs and accounts, so no single entity crosses a threshold |
| UEBA (Sentinel UEBA, Splunk UBA, Elastic ML) | An existing user or host departing from its own baseline: hijacked accounts, insider activity, impossible travel | New fake accounts and anonymous sessions have no baseline to deviate from |
| Threat intel and IP reputation (SIEM TI, WAF) | Known bad IPs, Tor, datacenter and proxy ranges | Fleets use residential and mobile proxies with clean reputation |
| WAF | Injection, malformed requests, known attack signatures | Agent requests are well-formed and legitimate-looking |
| Bot manager / CDN bot score | Headless browsers, automation frameworks, missing JavaScript, known bot fingerprints | LLM agents drive real browsers and pass these checks |

**The gap:** nothing in that list is looking for **how an LLM agent behaves**,
and nothing links **many brand-new, individually normal sessions** to one
controller. Shield fills those two gaps and nothing else.

**Outcome.** The customer connects Shield to their SIEM with a read-only
account. Shield reads their web, CDN and login logs **and their existing
alerts**, and sends back to the SIEM only:

- **agent detections**: a session behaves like an LLM agent, with the
  specific evidence;
- **fleet detections**: N sessions belong to one controller, with the traits
  that link them.

Each detection either is new (no existing alert covers it) or is attached to
the existing alert it adds evidence to. The customer's existing response
process (SOAR, analysts, bot manager rules) acts on them.

Observable success:
- on the evaluation set, the rates in section 8 are met;
- on a pilot tenant, at least 80% of Shield detections are not already
  covered by an existing alert (if most are, we are duplicating and the
  product has no reason to exist).

**Non-goals:**
- **Rebuilding anything in the table above:** volume thresholds, per-user
  baselines, IP reputation, WAF signatures, headless or automation checks.
  Their outputs are inputs to Shield, never re-alerted.
- **Blocking or enforcement:** the customer acts through their SOAR, WAF or
  bot manager. No block list, no edge integration in this spec.
- Inline browser script, device and VM checks, mobile SDKs.
- Cross-customer sharing; separate spec, if wanted later.
- Storing raw logs; Shield keeps 24-hour per-session summaries.

## 2. Part 1: detections built for AI agents

### 2.1 Detectors
Each detector targets something specific to an LLM driving a browser or
app. Each lists why existing alerts miss it and which log fields it needs.
Detectors only score sessions; a detection is raised when the combined score
passes the threshold set by the evaluation (section 4).

| ID | What it looks for | Why existing alerts miss it | Fields needed |
|---|---|---|---|
| **A1 Model-latency rhythm** | Gaps between a session's actions sit in the few-seconds band with low variation (the model thinking between steps), and quick follow-up clicks are almost absent | Thresholds count volume; this is the *shape* of timing at low volume | ts, session, path, event kind |
| **A2 Form fill timing** | Time from page load to submit barely changes with form length (fields filled at once) or grows exactly linearly (fixed typing speed) | Nobody alerts on fill time; bot managers see it only with their script | ts, path, method |
| **A3 Error recovery loop** | After a validation or 4xx error, the session resubmits a changed request after a model-latency pause, repeatedly, converging on success | Looks like a normal user retrying; no rule models the pause and change pattern | ts, method, path, status, request size |
| **A4 Goal-directed navigation** | Shortest path to the goal, no exploration (no back-navigation, browsing, or help pages), the same plan structure across tasks | Each request is normal; only the sequence is unusual | path sequence, referrer |
| **A5 Tripwire hits** | A request to a hidden link, or a value in a hidden field, that people never see or reach (`aria-hidden`, outside the tab order) | No existing tool places or watches these | path, optional form field logged by the app |
| **A6 Agent framework traits** | Header, client hint and timing defaults of known agent frameworks, kept current from the traffic library | Bot managers fingerprint automation tools, not agent frameworks running real browsers. If the customer's CDN bot score already labels it, Shield uses that and doesn't re-alert | headers or client hints if logged, user agent |

Detectors that need a field the customer doesn't log are switched off for that
source, and the source test (section 6) says which.

### 2.2 The agent traffic library (what keeps Part 1 ahead)
Any team could write rules like A1 to A6 once. The value is in keeping them
correct as agents change, which needs real agent traffic, continuously.

- **What it is.** A lab that runs agent frameworks against **our own test
  web app only**, never a customer or third-party site, and records the
  resulting web and login logs in the same schema the detectors read. Human
  sessions from staff on varied devices form the baseline.
- **Coverage matrix:**
  - **Frameworks:** open-source browser agents and computer-use agents,
    driving real browsers.
  - **Environments:** containers, VMs, Android emulators.
  - **Scale:** 1, 10 and 50 parallel instances under one controller.
  - **Tasks:** sign up, log in, search, checkout, scrape behind login.
  - **Networks:** direct, and through residential-style proxies.
- **Cadence:**
  - a scheduled run every week;
  - an extra run when a tracked framework releases a new major version;
  - new frameworks added when they become widely used.
- **Output:** a versioned, labeled dataset and an evaluation report per
  detector (detection rate on agents, false-positive rate on humans).
- **Release gate:** detector weights and rules ship as a versioned **detector
  pack** inside the Shield release (so on-prem and air-gapped installs get
  it). A pack that raises the human false-positive rate above target, or
  drops detection on any framework by more than 5 points, fails the gate.
- **Boundary:** this is test data for our own detectors, not a red-team
  product. It attacks only our test app, has no jailbreak or prompt-attack
  content, and is not offered to customers. If the separate red-team product
  already generates agent traffic, the lab takes its recordings instead of
  building its own runners.

## 3. Part 2: fleet detection across new sessions

### 3.1 Scope: where UEBA can't look
Fleet detection only considers **low-history entities**: anonymous sessions,
and accounts younger than a configurable age (default 14 days) or with fewer
than a configurable number of prior sessions. Established users are UEBA's
job and are excluded, so the two never overlap.

### 3.2 Linking traits
Two sessions are linked only when they share **at least two independent
traits** from different groups:

| Group | Trait | How it's compared |
|---|---|---|
| Behavior | Path sequence | MinHash over overlapping chunks of the first 20 page or API paths, so small variations still match |
| Behavior | Timing profile | A1 and A2 features bucketed into a short vector; distance under a threshold |
| Time | Synchronized start | Starts within the same 30-second bucket as many others |
| Client | Fingerprint | User agent plus client hints plus TLS fingerprint where logged, exact match |
| Network | Network | Same ASN class and /24, used only as a supporting trait |

The two-trait rule is what prevents false fleets:
- many real users behind one office or carrier IP share only a network
  trait, so they never link;
- users following a popular funnel share only a path trait, so they never
  link either.

A group of only one shared IP or one shared account is exactly what threshold
rules already catch, so it's left to them.

### 3.3 Fleets
- Linked sessions form groups (union-find over linked pairs, 1-hour sliding
  window, recomputed every 2 minutes).
- A group becomes a **fleet** when it has at least `min_size` sessions
  (default 10) across at least 3 distinct networks, so a fleet is by
  definition something per-IP rules can't see.
- Each fleet keeps its traits and size over time. A session that later
  matches a fleet's traits joins it.
- Fleet detections carry: size, networks, accounts involved, the linking
  traits with examples, and how many members also scored as agents in Part 1.

### 3.4 No duplicate alerts
Before raising anything, Shield checks the customer's existing alerts for the
same entities (IPs, accounts, sessions) in the same window:

| SIEM | Existing alerts read |
|---|---|
| Microsoft Sentinel | `SecurityAlert`, and UEBA `BehaviorAnalytics` / `Anomalies` |
| Splunk Enterprise Security | Notable events (`index=notable`) |
| Elastic Security | `.alerts-security.alerts-*` |

- **Entity already alerted on:** Shield does not raise a new alert. It sends
  an enrichment event that references the existing alert id and adds the agent
  or fleet evidence. For a fleet, the enrichment lists all other members,
  which the existing alert didn't know about.
- **Not alerted on:** Shield raises a new detection.
- The share of detections that were new vs enrichment is reported per tenant;
  it is the success metric in section 1.

## 4. Scoring and thresholds
- **Part 1:** weighted sum of detector scores, weights from the latest
  detector pack. Explainable: each detection lists the detectors that fired
  and their evidence.
- **Part 2:** a fleet is raised on the rules in 3.3; no learned model.
- Per-tenant thresholds can only be made stricter than the pack's default
  (fewer detections), never looser without an admin acknowledging the
  measured false-positive rate.

## 5. Plane & latency contract
- **Plane: admin (CPU) only.** A worker process
  (`python -m core.agent_detection.worker`, same admin image) polls sources,
  scores sessions, links fleets and sends results. Portal pages and APIs
  mount on `admin_app.py`.
- **Guard path untouched:** nothing on `/guardrails/*`, `cap/mint` or
  `tools/call`, and no data plane change. Off hot path, no impact on guarded
  traffic.
- **Detection delay:** poll interval (default 120 s) plus fleet recompute
  (120 s), target under 5 minutes.
- **Load on the SIEM:** one bounded query per source per interval, limited to
  the routes the tenant chooses (login, sign-up, checkout, search by
  default), plus one alerts query per interval.

## 6. Data model

Prefix `agd:` (agent detection). All keys are tenant-scoped.

| Key | Shape | TTL |
|---|---|---|
| `agd:{tenant}:sources` | JSON list: `{id, type, kind (logs or alerts), endpoint, query, field_map, interval_s, enabled}` | none |
| `agd:{tenant}:source:{id}:cred` | read-only credential; encrypted with the secret vault key when `SECRET_VAULT_ENABLED` | none |
| `agd:{tenant}:cursor:{id}` | last timestamp processed plus event hashes at that timestamp | none |
| `agd:{tenant}:sess:{key_hash}` | hash: entity age class, detector scores, timing vector, path MinHash, fingerprint hash, network hash, fleet_id | 24 h |
| `agd:{tenant}:lsh:{band}:{bucket_hash}` | set of session key hashes (path similarity candidates) | 1 h |
| `agd:{tenant}:trait:{kind}:{value_hash}:{bucket}` | set of session key hashes (start, fingerprint, network) | 1 h |
| `agd:{tenant}:fleet:{id}` | hash: size, networks, traits, member sample, first_seen, last_seen | 24 h after last match |
| `agd:{tenant}:alerted:{entity_hash}` | existing alert ids for this entity in the window | 2 h |
| `agd:{tenant}:detections` | capped list (10,000) of sent detections and enrichments | 7 days |
| `agd:{tenant}:stats:{yyyymmdd}` | counters: detections, enrichments, by detector, fleets | 35 days |

- **Tenant scoping:** routes resolve the tenant with
  `resolve_request_tenant_id`; the worker processes one tenant at a time and
  reads only its keys.
- **Settings** live in the tenant config (`tenant:{tenant_id}`) under
  `agent_detection`: enabled, routes, low-history age, `min_size`, threshold
  overrides.
- **Privacy:** IPs stored only as a salted hash of the /24 or /48 plus ASN
  class; account ids hashed; no bodies, query strings or field values kept.

## 7. API / interface (admin plane)

| Method, path | Auth | Purpose |
|---|---|---|
| `GET/POST/PUT/DELETE /v1/agent-detection/sources` | portal admin, or tenant key with write scope | Log and alert sources |
| `POST /v1/agent-detection/sources/{id}/test` | same | Run once; return mapped sample, unmapped fields, and which detectors that source can support |
| `POST /v1/agent-detection/logs` | tenant API key | NDJSON push for sources the worker can't reach; 5 MB per request, rate-limited |
| `GET /v1/agent-detection/detections`, `/fleets`, `/stats` | portal session or tenant key | Portal views, including new vs enrichment share |
| `GET /v1/agent-detection/pack` | portal session | Detector pack version and its evaluation summary |

Detections and enrichments go to the customer's SIEM through the existing
dispatcher as ASIM-shaped events (`event_type: agent_detection` and
`agent_fleet`, with `related_alert_ids` on enrichments).

Portal: an **AI Agent Detection** page with Sources, Detections, Fleets, and
the detector pack summary.

## 8. Security, compatibility, failure modes

**Compatibility.** Opt-in per tenant: nothing runs until a source is added.
Detection only, so no traffic is ever blocked by this feature.
`SHIELD_AGENT_DETECTION=off` stops the worker and hides the routes.

**Security:**
- **SIEM credentials:** read-only, limited by the docs to the web, login and
  alert indexes. Stored encrypted when the secret vault is on.
- **Existing gap, flagged:** today's SIEM export tokens are stored
  unencrypted in Redis. That should be fixed in a separate follow-up.
- **Queries:** written by the tenant and run with the tenant's own
  credential. Shield passes the time window and row cap as API parameters,
  not by editing query text.
- **Tripwire snippets:** `aria-hidden` and outside the tab order, checked by
  an accessibility test.

**Failure modes:**

| Case | Behavior |
|---|---|
| SIEM unreachable or slow | backoff; cursor not advanced, so nothing is skipped within SIEM retention; source shown as failing |
| Alerts source unavailable | detections are held up to 10 minutes waiting for it, then sent marked `dedupe: unavailable` rather than dropped |
| More rows than the cap | newest window processed, poll marked `truncated` |
| Missing fields | detectors needing them are off for that source; source test lists them |
| Duplicate events across polls | dedupe on event hash at the cursor boundary |
| Clock skew between sources | per-source cursors; 60-second tolerance in fleet windows |
| Redis down | worker pauses; nothing sent; resumes from cursors |
| NAT, popular funnels | two independent traits required to link (section 3.2) |
| Tenant's own automation | excluded by IP range, user agent or account allowlist |
| Large tenants | per-tenant time budget per cycle; LSH keeps linking near-linear |

**Targets (proposals; the first lab run sets the operating point):**
- Part 1, per session: at most 0.5% of human baseline sessions scored as
  agents. Agent detection rate reported per framework; at least 80% overall
  at that false-positive rate.
- Part 2: at least 95% of agent sessions in fleets of 10 or more grouped into
  a fleet; zero human sessions grouped into a fleet in the baseline.
- At least 80% of detections on a pilot tenant are new rather than enrichment.

## 9. Packaging & deploy
- New package `core/agent_detection/` (connectors, field mapping, detectors,
  LSH and fleets, dedupe, worker) and `api/routes_agent_detection.py`.
- **`Dockerfile.admin`:** add the route module and every
  `core/agent_detection/*.py` it imports; checked by
  `tests/test_admin_dockerfile_imports.py`.
- **Dependencies:** none new. Connectors use `httpx`, already in
  `requirements.txt` and `requirements-admin.txt`. MinHash is a small in-repo
  implementation. Sentinel uses Entra client-credentials over plain HTTP.
- **Worker:** a new process (Railway service; a Deployment in the OpenShift
  bundle, added in the same PR), admin image, CPU only.
- **Detector pack:** a versioned JSON file in the repo, produced by the lab,
  shipped in the image.
- **Lab:** lives outside the product image (`lab/agent-traffic/`), runs on
  our own infrastructure, writes datasets to a private bucket. It needs its
  own credentials for that bucket, provisioned by you.
- **Env flags:** `SHIELD_AGENT_DETECTION` (on/off),
  `SHIELD_AGENT_DETECTION_HASH_SALT` (required when on),
  `SHIELD_AGENT_DETECTION_MAX_ROWS` (default 200,000).

## 10. Test plan (Definition of Done)
- Detector unit tests on recorded lab samples: each detector fires on its
  agent sample and stays quiet on the human sample.
- Fleet tests: a fleet forms across 3 or more networks; NAT-only and
  funnel-only groups never form; established accounts are excluded.
- Dedupe tests per SIEM against recorded alert responses: enrichment instead
  of new alert, and the alerts-unavailable path.
- Connector tests against recorded API responses (no live SIEM in CI);
  cursor, dedupe and truncation.
- Detector pack gate as a CI test on a frozen lab sample.
- Accessibility test for tripwire snippets.
- Regression guards: the Dockerfile imports test; a test that no new route
  mounts on the data plane app.
- Full suite green in a clean venv; CI `pytest` gate passes.

## 11. Tasks (one PR each, in order)
0. **Lab v0 and baseline:**
   - test app with Nginx and login logs into a local Elastic;
   - three agent frameworks across containers, VMs and an Android emulator,
     at 1, 10 and 50 parallel;
   - staff human sessions;
   - offline evaluation harness.

   Report detector rates and **go/no-go before any product code**.
1. **Sources:** log and alert connectors for Splunk, Sentinel and Elastic,
   NDJSON push, field mapping, source test, cursors, credential storage.
2. **Part 1 detectors** A1 to A6, detector pack format and CI gate, portal
   Detections. Nothing is sent to the SIEM yet, so no duplicates can reach it
   before task 4.
3. **Part 2 fleets:** low-history scope, LSH and trait linking, fleets,
   portal Fleets.
4. **No duplicates, then send:** reading existing alerts, enrichment events,
   the new vs enrichment metric, and only now sending detections to the SIEM.
5. **Lab as a routine:** scheduled weekly runs, framework onboarding steps,
   detector pack release process and docs.
