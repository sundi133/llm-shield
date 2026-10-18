---
title: "Spec: AI discovery beyond Shield traffic"
layout: default
nav_exclude: true
permalink: /specs/ai-discovery/
description: One inventory of the AI apps, agents, MCP servers and AI services in use, including the ones that never call Shield, from the device agent, the proxy, network logs and code scans, with actions that bring each one under Shield.
---

# Spec: AI discovery beyond Shield traffic

> Status: **DRAFT, awaiting approval.** Branch `spec/ai-discovery`.
> Related: `docs/specs/agent-os-events.md` (approved; agent attribution on
> endpoints, server side built), `docs/spec-okta-parity-agent-identity.md`
> (draft; gap G1 and an identity-provider discovery source),
> `docs/specs/device-dlp-agent.md` (the device agent), `deploy/swg/` (the proxy),
> `storage/aibom.py` (the AI bill of materials).

## 1. Problem & outcome

Every source that sees AI usage today sees only part of it:

| Source | What it sees | What it misses |
|---|---|---|
| Guard path (`core/middleware.py` shadow agents, `unregistered:{tenant}`) | Agents that call Shield, registered or not | Everything that does not call Shield (the gap is written down as G1 in `docs/spec-okta-parity-agent-identity.md`) |
| Device agent (`packages/votal-device-agent`) | Prompts to the policy's `ai_hosts` (default 18 hosts, up to 200), routed to it by the PAC file | Installed AI apps, IDE assistants, MCP servers configured on the laptop, local model servers, CLI agents, AI hosts not on the list |
| Browser extension (`examples/browser-extension`) | Five chat sites | Every other AI site |
| Proxy (`deploy/swg/`, `icap/`) | POSTs with a body to the 18 hosts hard-coded in `squid.conf`, sent to `/guardrails/input`; Squid's access log goes to stdout | Any AI destination not on the list; who contacted what, as a record |
| MCP scanner (`packages/shield-mcp`) | A server someone names on the command line | MCP servers configured on machines |
| AIBOM (`storage/aibom.py`) | Registered and shadow agents, MCP gateway upstreams, CycloneDX ingest | Anything discovered elsewhere; provenance is only `registered`, `shadow`, `cyclonedx-ingest` |
| Agent OS events (approved spec, server built, collectors not built) | Process, file and network events of known coding agents on a laptop | Apps and connections in general; it attributes, it does not inventory |

Nothing answers the first question a security team asks: **what AI is in use
here, and which of it is not under Shield?**

**Outcome.** One AI inventory per tenant. Each entry is an AI app, agent, MCP
server or AI service, with the sources that saw it, where (devices, users,
services, repositories), first and last seen, whether it is **governed** (its
traffic passes through Shield) and a review status (unreviewed, sanctioned,
unsanctioned, ignored). From an entry, one action brings it under Shield:
inspect or block the destination, route the MCP server through the gateway,
register the agent. New ungoverned entries raise a webhook.

**Non-goals.**
- Crawling SaaS admin APIs for OAuth grants (Google Workspace, Microsoft 365).
  The identity-provider source designed in `docs/spec-okta-parity-agent-identity.md`
  (Okta System Log) writes into the same inventory when built.
- Cloud account discovery through cloud APIs (Bedrock, Azure OpenAI, Vertex).
  Covered here only through network logs and code scans; a connector is later.
- Blocking processes on endpoints (agent OS events, phase 2).
- Collecting app lists, browsing history or file contents. Collectors report
  only matches against the AI catalog (section 3.1).

## 2. Plane & latency contract

- **Off the guard path.** No change to `/guardrails/*`, `tool/check`,
  `cap/mint` or MCP `tools/call`, except one in-process "seen" mark for
  governed correlation (task 1), using the policy-learning buffer pattern
  (`core/policy_learning/observe.py`): no I/O on the request.
- **Data plane:** the device heartbeat (already there) carries a new
  `ai_inventory` field; a discovery ingest route receives proxy, log and scan
  batches. Both are management traffic: batched, rate-limited per source.
- **Admin plane:** the inventory, review and actions, and the portal tab.

## 3. Data model

### 3.1 The AI catalog

`core/discovery/catalog.py`, versioned, shipped with Shield; tenants add their
own entries (`discovery_catalog:{tenant}`, up to 500). One entry per AI thing,
with the signals that identify it:

| Field | Example |
|---|---|
| `id`, `name`, `vendor`, `kind` (`app`, `agent`, `mcp_server`, `ai_service`, `model_runtime`) | `cursor`, Cursor, Anysphere, app |
| `domains` | `api.openai.com`, `*.openai.azure.com`, `bedrock-runtime.*.amazonaws.com` |
| `app_ids` | macOS bundle ids, Windows executable names |
| `ide_extensions` | `github.copilot`, `continue.continue` |
| `binaries` | `claude`, `codex`, `aider`, `ollama` |
| `listen_ports` | `11434` (Ollama), `1234` (LM Studio) |
| `mcp_config_paths` | Claude Desktop, Cursor, VS Code, Windsurf, Claude Code (`~/.claude.json`), per OS |
| `packages` | `openai`, `anthropic`, `langchain`, `@modelcontextprotocol/sdk` |

About 200 entries at launch. The default `ai_hosts` lists in
`core/dlp/device_policy.py` and `deploy/swg/squid.conf` stay as they are (they
decide what is inspected); the catalog decides what is recognized.

### 3.2 The inventory

| Key | Shape | Notes |
|---|---|---|
| `discovery:{tenant}` | HASH `{entry_id}` → JSON entry | At most 5,000 entries |
| `discovery_seen:{tenant}:{entry_id}` | HASH `{subject}` → last seen | Per device, user, service or repository; at most 1,000 subjects per entry; TTL 90 days |
| `discovery_events:{tenant}` | capped LIST of new-entry and status-change events | For the portal's "new this week" and the webhook |

Entry: `{id, kind, name, vendor, catalog_id | null, signals: {domains, app_ids,
mcp: {server_name, command, url}, packages}, sources: [device_agent, proxy,
dns_log, repo_scan, shield, idp], subjects: {devices, users, services, repos},
first_seen, last_seen, governed: true | false | partial, governed_by: [...],
status: unreviewed | sanctioned | unsanctioned | ignored, owner, note}`.

`entry_id` is stable: `catalog:{id}` for catalog matches; `mcp:{sha256 of
url or command+package}` for MCP servers; `domain:{registrable domain}` for an
uncatalogued AI-looking destination reported by a source.

**What is never stored:** MCP server `env` values or arguments beyond the
package name and the command's base name; file contents; app lists beyond
catalog matches; URLs beyond the host; prompts. User identifiers are stored as
the source reports them unless `SHIELD_DISCOVERY_HASH_USERS=true` (then a
salted hash per tenant).

### 3.3 Governed

An entry is **governed** when its traffic demonstrably passes through Shield:
- an agent: registered and seen on the guard path in the window;
- an MCP server: its URL or command matches an MCP gateway route, and the
  gateway saw calls to it;
- an AI service domain: on the device policy's `ai_hosts` (inspected by the
  device agent) or the proxy's list, and Shield received guard calls for it
  (`X-Shield-Destination`);
- an app: its domains are governed.

`partial` when governed on some subjects (devices with the agent) and not
others. Governance is recomputed on each update, not trusted from a source.

## 4. API / interface

### 4.1 Sources (task order)

| Source | How it reports | What it can find |
|---|---|---|
| **Shield itself** | In-process: shadow agents, registry, MCP gateway routes, `X-Shield-Destination` on guard calls | Governed entries; correlation |
| **Device agent** | `ai_inventory` in the heartbeat, at most once an hour, only when changed | Installed AI apps, IDE extensions, MCP servers from config files, local model servers, CLI agents, AI destinations its proxy saw that are not on `ai_hosts` (host only) |
| **Proxy** | A log shipper next to Squid reads the access log, keeps catalog-matching hosts, aggregates per user and host for 5 minutes, posts a batch | AI services contacted by people and servers behind the proxy, including laptops without the agent |
| **Network logs** | Upload or post DNS or firewall logs (CSV or JSON: time, client, host) | AI services contacted from anywhere the customer logs, including cloud workloads |
| **Code scan** | `shield-mcp discover <path>` in CI or locally, posts a batch | LLM SDKs and agent frameworks in dependency files, MCP server definitions, model endpoints in config, hard-coded provider keys (reported as present, never sent) |
| **Identity provider** | Later, through `docs/spec-okta-parity-agent-identity.md` task 2 | AI apps granted access through Okta |

### 4.2 Routes

Data plane, discovery ingest (a tenant key; a dedicated `discovery`-scoped key
recommended for shippers and CI):

| Route | Body |
|---|---|
| `POST /v1/shield/discovery/batch` | `{source, observations: [{kind, catalog_id?, name?, domain?, mcp?, package?, subject: {type, id}, seen_at, count}]}`, at most 1,000 per batch, 60 batches per minute per tenant |

The heartbeat's `ai_inventory` field uses the same observation shape.

Admin plane, `/v1/tenant/me/discovery`:

| Route | Does |
|---|---|
| `GET /inventory?kind=&governed=&status=&source=&q=&cursor=` | Paged list and a summary (counts by kind, governed, status, new this week) |
| `GET /inventory/{entry_id}` | One entry with its subjects (paged) and sources |
| `PUT /inventory/{entry_id}` `{status, owner, note}` | Review (config write gate) |
| `POST /inventory/{entry_id}/actions/{action}` | Bring under Shield (section 4.3; config write gate) |
| `GET /catalog`, `PUT /catalog/custom` | The catalog; the tenant's own entries |
| `POST /import` | Upload a DNS or firewall log file (up to 20 MB, processed in the background) |

Webhook `ai_discovered` when a new ungoverned entry appears, and when an entry
marked unsanctioned is seen again.

### 4.3 Actions: bring it under Shield

| Entry | Action | Effect, through existing paths |
|---|---|---|
| AI service domain | `inspect` | Adds the domain to the device policy's `ai_hosts` (signed bundle, so laptops start inspecting it) and to the proxy's list (task 3 makes the proxy read it from Shield) |
| AI service domain | `block` | Adds it to a new `blocked_hosts` list in the device policy and the proxy (denied with a message naming the sanctioned alternative, if set) |
| MCP server | `route_through_gateway` | Opens the MCP server registration prefilled with the discovered URL or command; the entry becomes governed once traffic flows |
| Agent | `register` | Opens the Agent Registry form prefilled; then the policy-from-purpose draft |
| Any | `sanction`, `unsanction`, `ignore` | Status only; `unsanctioned` entries alert again when seen |

Nothing is changed by discovery alone; every action is a person's.

## 5. Security & backward compatibility

- **Privacy by construction.** Collectors match locally against the catalog and
  send matches only. The device agent never sends MCP `env` values, argument
  lists, file paths outside the known config locations, or app names outside
  the catalog. The code scanner reports that a provider key is present and
  where (repository-relative path and line), never the key.
- **Spoofing.** A batch is attributed to the key's tenant only. Device
  observations are trusted only from an enrolled device key (`vdk_`), as the
  heartbeat already is. A source can add sightings, not mark anything
  governed: governance is recomputed from Shield's own evidence (section 3.3).
- **Flooding.** Caps per batch, per minute and per inventory; uncatalogued
  domains need two independent sightings (two subjects or two sources) before
  they become entries.
- **Defaults.** Ingest and the inventory are new and off nothing. The device
  agent's collector ships disabled until the tenant turns it on in the device
  policy (`discovery: true`), because it reads more of the laptop than DLP
  does; the proxy shipper is a separate container the customer adds. No
  existing behavior changes. `inspect` and `block` change the device policy
  and proxy lists only when a person presses them, and are audited.

## 6. Packaging & deploy

- New: `core/discovery/{catalog.py, inventory.py, governed.py, logs.py}`,
  `api/routes_discovery.py` (admin, added to `Dockerfile.admin`) and
  `api/routes_discovery_ingest.py` (data plane).
- Device agent: a collector module in `packages/votal-device-agent` for macOS
  and Windows; release through the existing kit and bundle flow.
- Proxy: `deploy/swg/discovery-shipper/` (a small container that tails the
  Squid access log); `squid.conf` reads `ai_hosts` and `blocked_hosts` from
  files the shipper refreshes from Shield.
- Code scan: a `discover` subcommand in `packages/shield-mcp`, plus a GitHub
  Actions example.
- No new server dependencies. Env: `SHIELD_DISCOVERY` (on), `SHIELD_DISCOVERY_HASH_USERS`.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Redis down | Ingest returns 503; the device agent and shipper keep their batch and retry with backoff |
| A device without the agent | Seen only through the proxy, DNS logs or code scans; its entries are `partial` or ungoverned |
| The same app seen by several sources | One entry; sources and subjects merge |
| An MCP server config pointing at the gateway | Governed, with the gateway route named |
| A local model server (Ollama) | Entry of kind `model_runtime`; governed only if the device agent's DLP covers it (it already uses a local model) |
| Catalog update renames or merges an entry | Old ids map to new ones through the catalog's `replaces` field |
| A host used only by Shield itself | Excluded (Shield's own domains are never entries) |
| A huge DNS log | Processed in the background, matching only catalog domains; progress shown on the import |

## 8. Test plan (Definition of Done)

1. Catalog: matching by domain (wildcards), bundle id, extension id, binary,
   port, package; tenant entries; `replaces`.
2. Inventory: merge across sources, subjects, first/last seen, caps, the
   two-sighting rule for uncatalogued domains, stable ids.
3. Governed: each rule of section 3.3, including `partial`; a source cannot
   set it.
4. Ingest: shape, caps, rate limit, tenant attribution, device key only for
   device observations, 503 on store failure.
5. Device collector: on a fixture home directory, finds each catalog kind;
   never emits `env` values, argument lists or non-catalog apps; reports only
   on change.
6. Proxy shipper: from a fixture access log, aggregates catalog hosts per user;
   ignores the rest; `ai_hosts` and `blocked_hosts` files refresh.
7. Code scan: fixture repositories (Python, Node) find SDKs, frameworks, MCP
   definitions and a planted key, which is reported as present and never sent.
8. Actions: `inspect` and `block` update the device policy and proxy lists and
   are audited; the MCP and agent actions prefill; status changes and the
   webhook.
9. Portal: escaping; empty state; the route classification test covers the
   new write routes. Full suite green in a clean venv; CI passes.

## Tasks (one branch, one PR, one commit per task)

1. **Inventory and Shield's own evidence.** Catalog, inventory, governed rules,
   the ingest route, the admin routes (read, review), the portal tab, and the
   entries Shield already knows (registry, shadow agents, MCP gateway routes,
   guard-call destinations). Tests 1 to 4, 9.
2. **Device agent collector.** Apps, IDE extensions, MCP configs, local model
   servers, CLI agents, uncatalogued hosts its proxy saw; heartbeat field;
   opt-in in the device policy. Test 5.
3. **Network.** The proxy shipper and list files; DNS and firewall log import.
   Test 6.
4. **Code scan.** `shield-mcp discover` and a CI example. Test 7.
5. **Actions.** Inspect, block, route through gateway, register, review
   statuses, webhook. Test 8.
