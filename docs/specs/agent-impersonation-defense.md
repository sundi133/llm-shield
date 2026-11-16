# Spec: agent impersonation defense from SIEM logs

Status: **draft rev 2, 2026-11-15, awaiting approval.** Branch `spec/agent-impersonation-defense`.

Rev 2 change: detection is **behavior analysis on the web, CDN, WAF and login
logs the customer already has in their SIEM**, with no front-end SDK. The
inline browser script from rev 1 moves to phase 2.

Builds on SIEM export (`storage/siem_store.py`, `core/siem_dispatcher.py`),
ASIM shaping (`core/asim.py`), Sigma export (`core/sigma*.py`), monitor vs
enforce (`core/policy_mode.py`) and the shadow mode report
(`docs/specs/shadow-mode-report.md`).

## 0. Fit and honest limits

**Buildable: yes.** Every signal below is computed from fields that standard
web and login logs already carry.

**A new direction for Shield.** Today Shield governs a company's own AI. This
defends a company's website or app from someone else's AI. Shield's existing
SIEM work makes it a natural fit: today Shield only *writes* to the SIEM; this
adds *reading* from it.

**What logs can and can't do:**

| | From SIEM logs (v1) | Needs a browser script (phase 2) |
|---|---|---|
| Request timing, agent think-pause-act rhythm | yes | |
| Navigation paths, form submit timing | yes | |
| Network origin (datacenter, proxy, ASN) | yes | |
| Login and sign-up outcomes | yes | |
| **Fleets: many sessions from one controller** | **yes, the main strength** | |
| Hidden honeypot links and paths (tripwires) | yes, a page change only | |
| TLS client fingerprint | when the CDN or WAF logs it | |
| VM, sandbox or emulator graphics and hardware | no | yes |
| Mouse, scroll, keystroke timing | no | yes |
| Block on the very first request | no, minutes later | yes |

So v1 is strongest at exactly the customer's scenario (many sandboxes, one
controller), weakest against a single, careful agent on a residential proxy.

**Not claimable yet:** false-positive and false-negative rates, and customer
cases. Task 0 measures the rates before anything is promised.

## 1. Problem & outcome

**Problem.** One controlling AI starts many sandboxes, VMs or emulators, each
running an LLM agent that imitates a real user well enough to pass
conventional bot checks. Targets: sign-up and promotion abuse, credential
stuffing at human pace, scraping behind login, inventory hoarding, fake
reviews, account takeover follow-through.

**Outcome.** A security team connects Shield to their SIEM (Splunk, Microsoft
Sentinel or Elastic) with a read-only account and points it at their web and
login logs. With no change to their app, within an hour they see in the
Shield portal:

- sessions scored as human, automation or AI agent, each with its reasons;
- **fleets**: groups of sessions linked to one controller, with the shared
  traits that link them;
- detections sent back into their SIEM as alerts, in the same schema Shield
  already exports;
- in monitor mode, what enforce would have blocked (the shadow report).

In enforce mode their edge (CDN, WAF, Nginx, gateway) pulls a **block and
challenge list** from Shield every minute, or their SOAR acts on the SIEM
alerts.

Observable success: on the task 0 test set, rates meet the section 8 targets,
and time from attack start to detection is under 5 minutes at the default
poll interval.

**Non-goals (v1):**
- Inline per-request decisions and the browser script (phase 2).
- Native mobile SDKs, VM and emulator hardware checks (phase 2).
- Network-wide IP reputation; we use the customer's own traffic plus public
  datacenter and proxy range lists.
- Payment fraud scoring, KYC, chargebacks.
- Storing the customer's raw logs. Shield keeps per-session summaries for 24
  hours, not log lines.
- A red-team product. Task 0 builds only the test set needed to measure
  detection.

## 2. How detection works

### 2.1 Input: a minimal web event
Each log source maps its fields onto one schema (defaults match ASIM
WebSession and common Splunk and Elastic field names; the mapping is editable
per source):

`ts, src_ip, method, path, status, user_agent, session_id, account_id,
referrer, bytes, duration_ms, ja4 (optional), event_kind (page | asset | api |
auth_success | auth_failure | signup)`

Session key: `session_id` if logged, else `account_id`, else `src_ip + user_agent`
within a 30-minute idle window.

### 2.2 Per-session behavior
- **Agent rhythm:** gaps between page-level requests cluster in the seconds
  range with low variance (model latency), unlike human gaps, which are
  bursty and long-tailed.
- **Form timing:** time from a page load to its form submit is near-constant
  across sessions and fast for long forms.
- **Navigation:** direct deep links with no referrer, a straight line through
  a funnel with no browsing, identical paths per session.
- **Page without assets:** page requests with no CSS, JS or image requests
  (HTTP-library agents).
- **Network:** datacenter or cloud ASN, known proxy ranges, user agent vs TLS
  fingerprint mismatch when `ja4` is present.
- **Auth outcomes:** failure ratios, sign-ups per network, password resets.
- **Tripwires:** a hidden link or form field in the page that a person never
  sees or uses (`aria-hidden`, outside the tab order). A request to that path,
  or a submitted value in that field, shows in the logs. This needs a small
  page change but no SDK, and screen readers never reach it.

### 2.3 Fleet correlation (the main scenario)
Over a sliding 1-hour window per tenant, sessions are linked when they share:
- the same path sequence (first N pages, hashed in overlapping chunks so
  small variations still match);
- the same timing profile (rhythm and form timing, bucketed);
- synchronized starts (many sessions starting within seconds);
- the same user agent and TLS fingerprint across many networks;
- the same /24 or ASN with many concurrent sessions.

A group above a size and similarity threshold becomes a **fleet** with a
shared verdict. Sessions that later match a known fleet inherit it. A single
shared trait never forms a fleet on its own, so an office or carrier NAT
(many real users, one IP) doesn't get flagged.

### 2.4 Verdicts and scoring
Weighted rules, deterministic, with reasons on every verdict. Weights come
from task 0. Classes: `human`, `automation`, `ai_agent`, `verified_agent`
(allowlisted by the tenant: their monitoring, QA or partner agents, by IP
range, user agent or account), `unknown`.

### 2.5 Outputs
- **Back to the SIEM:** each detection and fleet as an ASIM-shaped event
  through the existing dispatcher (`event_type: agent_impersonation`).
- **Block and challenge list** for the edge: entries are session, account,
  fleet signature, or network (network only with fleet evidence, never alone).
  Every entry expires (default 1 hour).
- **Sigma rules pack** for the simple single-event checks (tripwire hits,
  datacenter sign-ups), exported with the existing Sigma tooling so teams can
  also run them inside their SIEM. Correlation and timing stay in Shield,
  because the Sigma engine here deliberately rejects correlation rules
  (`core/sigma.py`).

### 2.6 Coverage by environment

| Environment | v1 coverage |
|---|---|
| Web apps | Full section 2 from web and CDN logs |
| APIs (own front end, partner, mobile back end) | Full section 2 except asset and tripwire checks |
| Native mobile apps | Their API back end is covered; device checks are phase 2 |
| Where actions apply | Any CDN, WAF, Nginx, Envoy or gateway that can pull a list; or the customer's SOAR from SIEM alerts |

Supported log sources: Splunk (search API), Microsoft Sentinel (Log Analytics
query API), Elastic (search API), and a generic NDJSON push endpoint for
anything else (CDN log push, Fluent Bit, Vector).

## 3. Plane & latency contract

- **Plane: admin (CPU) only.** Log polling and analysis run in a new worker
  process (`python -m core.agent_impersonation.worker`, same admin image).
  Portal pages and APIs mount on `admin_app.py`. **The data plane is not
  changed.**
- **Guard path: untouched.** Nothing on `/guardrails/*`, `cap/mint` or
  `tools/call`. Off hot path, no impact on guarded traffic.
- **Detection delay**, not request latency, is the budget: poll interval
  (default 120 s) plus analysis, target under 5 minutes end to end. The
  blocklist endpoint is a read of one precomputed key.
- **Load on the customer's SIEM:** one bounded query per source per interval,
  filtered to the routes the tenant protects (login, sign-up, checkout,
  search, by default) and capped in rows.

## 4. Data model

Prefix `aid:` (agent impersonation defense). All keys are tenant-scoped.

| Key | Shape | TTL |
|---|---|---|
| `aid:{tenant}:sources` | JSON list: `{id, type, endpoint, query, field_map, interval_s, enabled}` | none |
| `aid:{tenant}:source:{id}:cred` | read-only SIEM credential, encrypted with the secret vault key when `SECRET_VAULT_ENABLED`, otherwise stored like today's SIEM export tokens (see section 6) | none |
| `aid:{tenant}:cursor:{id}` | last event timestamp processed, plus hashes of events at that timestamp (dedupe) | none |
| `aid:{tenant}:sess:{key_hash}` | hash: counts, timing summary, path hash, network class, reasons, score, verdict, fleet_id | 24 h |
| `aid:{tenant}:link:{kind}:{value_hash}:{bucket5m}` | set of session key hashes (path, timing, start, fingerprint, network) | 1 h |
| `aid:{tenant}:fleet:{id}` | hash: size, traits, verdict, first_seen, last_seen | 24 h after last match |
| `aid:{tenant}:fleets` | sorted set by last_seen | 24 h |
| `aid:{tenant}:detections` | capped list (10,000) of detection summaries | 7 days |
| `aid:{tenant}:blocklist` | sorted set, entry by expiry time | entries expire individually |
| `aid:{tenant}:stats:{yyyymmdd}` | counters by verdict and action | 35 days |

- **Tenant scoping:** every route resolves the tenant from the portal session
  or tenant API key the usual way (`resolve_request_tenant_id`); the worker
  iterates tenants with an enabled source and only reads that tenant's keys.
- **Policy** goes in the tenant config (`tenant:{tenant_id}`) under a new
  `agent_impersonation` block: mode, protected routes, thresholds, allowlist,
  blocklist entry lifetime.
- **Privacy:** IPs are stored only as a salted hash of the /24 (IPv4) or /48
  (IPv6) plus ASN class; account ids are hashed; no request bodies or query
  strings are kept. Data stays in the customer's SIEM; Shield keeps 24-hour
  summaries.

## 5. API / interface (all admin plane)

| Method, path | Auth | Purpose |
|---|---|---|
| `GET/POST/PUT/DELETE /v1/agent-impersonation/sources` | portal admin or tenant key with write scope | Manage log sources |
| `POST /v1/agent-impersonation/sources/{id}/test` | same | Run the query once, return 20 mapped events and any unmapped fields |
| `POST /v1/agent-impersonation/logs` | tenant API key | NDJSON push ingest; 5 MB per request, rate-limited |
| `GET /v1/agent-impersonation/sessions`, `/fleets`, `/detections`, `/stats` | portal session or tenant key | Portal views |
| `GET /v1/agent-impersonation/blocklist?format=json\|ips\|nginx` | tenant API key with a new `blocklist` read scope | Edge pulls current entries; empty in monitor mode |
| `PUT /v1/agent-impersonation/policy` | portal admin | Mode, routes, thresholds, allowlist |

Portal: a new **Agent Impersonation** page (Sources, Sessions, Fleets,
Detections), and shadow report rows for would-be blocks.

## 6. Security & backward compatibility

- **Opt-in per tenant.** Nothing runs until a tenant adds a log source. New
  sources start in **monitor**: detections are recorded and sent to the SIEM,
  and the blocklist endpoint returns nothing until the tenant switches to
  enforce.
- **Escape hatch:** `SHIELD_AGENT_IMPERSONATION=off` stops the worker and makes
  the routes return 404.
- **SIEM read credentials are sensitive** (they can read logs). Docs require a
  read-only account limited to the web and login indexes. Stored encrypted
  when the secret vault is enabled. **Existing gap, flagged:** today's SIEM
  export tokens are stored unencrypted in Redis; this spec doesn't make that
  worse for read credentials when the vault is on, and recommends a
  follow-up to encrypt export tokens too.
- **Blocklist safety:** entries expire; a network range is never listed on
  network evidence alone; allowlisted agents and accounts are never listed.
- **SaaS reaching an on-prem SIEM:** often not possible over the internet.
  Those customers use the push endpoint or run Shield on-prem.
- **Query injection:** the tenant writes the query, so it runs with their
  credential against their SIEM only; Shield adds the time filter and row cap
  as separate parameters, not by string concatenation where the API allows.

## 7. Packaging & deploy

- New package `core/agent_impersonation/` (connectors, field mapping, session
  builder, scorer, fleets, worker) and `api/routes_agent_impersonation.py`.
- **`Dockerfile.admin`:** add the route module and every
  `core/agent_impersonation/*.py` it imports; checked by
  `tests/test_admin_dockerfile_imports.py`.
- **Dependencies:** none new. Connectors use `httpx` (already in
  `requirements.txt` and `requirements-admin.txt`). Microsoft Sentinel uses an
  Entra app's client-credentials token over plain HTTP, no Azure SDK.
- **Worker:** a new process (Railway service; a Deployment in the OpenShift
  bundle, added in the same PR as the worker), same admin image, CPU only.
- **Env flags:** `SHIELD_AGENT_IMPERSONATION` (on/off),
  `SHIELD_AGENT_IMPERSONATION_HASH_SALT` (required when on),
  `SHIELD_AGENT_IMPERSONATION_MAX_ROWS` (per poll, default 200,000).
- **Datacenter and proxy ranges:** a bundled data file refreshed by a release
  step, so air-gapped installs work.

## 8. Failure modes & edge cases

| Case | Behavior |
|---|---|
| SIEM unreachable or slow | exponential backoff; cursor not advanced, so nothing is skipped within the SIEM's retention; portal shows the source as failing |
| More rows than the cap | process the newest window, mark the poll `truncated`, alert in the portal |
| Credential revoked or expired | source marked failing; no retries until updated |
| Field missing from logs (no session id, no ja4) | fall back to the next session key; skip checks that need the field; source test shows what's missing |
| Duplicate events across polls | dedupe on event hash at the cursor boundary |
| Clock skew between sources | each source has its own cursor; fleet windows tolerate 60 s skew |
| Redis down | worker pauses; blocklist endpoint returns the last list from an in-process copy for up to 5 minutes, then empty (fail open) |
| Office or carrier NAT | network sharing alone never forms a fleet |
| Accessibility tools | tripwires are `aria-hidden` and outside the tab order |
| Tenant's own automation | allowlist by IP range, user agent or account |
| Very large tenants | per-tenant time budget per cycle; tenants processed in rotation |

### Measurement targets (proposals; task 0 sets the operating point)
- Human sessions put on the blocklist: at most 0.1%.
- Agent sessions in fleets of 10 or more detected: at least 95%.
- Lone agent sessions detected: reported, no target in v1 (logs alone are
  weak here; phase 2 addresses it).
- Attack start to detection: under 5 minutes.

## 9. Test plan (Definition of Done)

- **Task 0 test set:** a small test web app with Nginx and login logs flowing
  into a local Elastic or Splunk; human sessions from staff on varied
  devices; agent sessions from open-source browser and computer-use agents in
  containers, VMs and Android emulators, 1 to 50 in parallel per controller;
  optionally a design partner's historical logs. Report per-signal and
  combined rates; go/no-go before task 2.
- Unit tests: each connector against recorded responses (no live SIEM in CI),
  field mapping, cursor and dedupe, every scorer rule, fleet formation
  including the NAT case, blocklist expiry and the monitor-mode empty list,
  every section 8 row.
- Accessibility test for tripwire snippets.
- Regression guards: Dockerfile imports test; a test that no new route mounts
  on the data plane app.
- Full suite green in a clean venv; CI `pytest` gate passes.

## 10. Tasks (one PR each, in order)

0. **Measurement gate:** test app, log pipeline, agent and human sessions,
   offline scorer, report, go/no-go.
1. **Log sources:** Splunk, Sentinel and Elastic connectors, NDJSON push,
   field mapping, test query, cursors, credential storage, portal Sources tab.
2. **Sessions and scorer:** session builder, per-session rules, monitor mode,
   portal Sessions and Detections, detections to the SIEM.
3. **Fleets:** correlation and fleet verdicts, portal Fleets tab.
4. **Actions:** blocklist endpoint (JSON, IP list, Nginx map), shadow report
   rows, Sigma rules pack, edge examples (Nginx, Envoy, CDN worker).
5. **Tripwires:** page snippets, detection from logs, accessibility test, docs.

**Phase 2 (separate spec):** the inline browser script and per-request
decision for real-time blocking and device signals (VM, emulator, mouse),
native mobile SDKs, a learned scorer.

## 11. Answering the customer today

- **Do you offer it?** Not yet as a product. Shield today governs AI a company
  runs itself. We are scoping detection of outside AI agents posing as users,
  working from the logs already in your SIEM, and can pilot it in monitor mode.
- **How is it different from bot management?** It looks for model-driven
  behavior (the think-and-act rhythm of agents, identical journeys) and links
  many sessions to one controller, rather than only checking whether each
  request is automated. It can run alongside an existing bot manager.
- **Sandbox, VM and emulator fleets at scale?** By correlating sessions that
  share paths, timing, start times, fingerprints and networks. Per-device VM
  and emulator checks need a browser or app SDK, which is a later phase.
- **Data and SDK?** Web, CDN, WAF and login logs from your SIEM, read-only. No
  front-end SDK in the first version; an optional hidden-link tripwire is a
  small page change.
- **False-positive and false-negative rates?** We will measure them on your
  traffic in monitor mode before anything is blocked. We don't quote numbers
  we haven't measured.
- **Customer cases?** None for this capability yet.
- **Deployment?** SaaS (needs network access to your SIEM, or log push) or
  on-premises, including air-gapped. No GPU needed.
- **Pricing?** To be set.
