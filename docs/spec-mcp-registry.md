# Spec: MCP registry with security ratings (Phase 3)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.
Builds on the shipped `shield-mcp` scanner (PR #263) and its distribution wrappers
(PR #264): the registry consumes the scanner's `ScanReport` JSON as its rating
input. The three design forks are **decided** (§9): static generation via GitHub
Pages, sandboxed-CI scanning of a curated list, and a **numeric 0–100** score.

## 1. Problem & outcome

Every security-conscious dev evaluating an MCP server googles "**[server name] MCP
security**" — and today there's nothing to rank for that query. A public directory
that scores well-known public MCP servers on their scan results is both a product
(a safety signal devs actually want) and the top of the funnel for the scanner: a
content/SEO play that ranks for thousands of long-tail "[server] MCP security"
searches and points readers at `npx @votal/mcp-scan` to check their own.

**Outcome.** A public, crawlable directory where each listed server has a page:
`Name — grade (A–F), what the scanner found, when it was scanned, and how to scan
it yourself`. Ratings are **generated deterministically** from a `shield-mcp scan`
of a curated list of public servers (tool-poisoning, encoded injections,
over-broad permissions, suspicious metadata). Success = a server-detail page per
listed server, an index/directory page, a `sitemap.xml`, each page carrying a
`<title>` and meta-description tuned for "[name] MCP security", regenerated on a
schedule — with **zero** impact on any guard path.

**Non-goals.**
- **Not** monetization (verified/paid/badge listings) — a later phase. v1 is free,
  public, read-only content.
- **Not** a live dynamic API or per-request scanning service. Ratings are
  pre-generated static content (see §2 / Open Q1).
- **Not** auto-crawling the entire MCP ecosystem. v1 rates a **curated,
  checked-in list** of public servers; discovery/expansion is later.
- **Not** maintainer-reputation scoring (stars, recency, provenance) in v1 — the
  grade is derived purely from the reproducible scan (Open Q3 covers the scheme).
  Maintainer signals are a documented v2 enhancement.
- **Not** a new detection engine — it *reuses* `shield-mcp`; no heuristics here.

## 2. Plane & latency contract

- **Off every plane (recommended, Open Q1a).** The registry is **static content
  generated offline** and served by the **existing GitHub Pages / Jekyll pipeline**
  (`.github/workflows/docs.yml` already builds `docs/**` → `docs.shield.votal.ai`).
  Generation runs in CI (or locally), not in the data (GPU/vLLM) or admin (CPU
  portal) plane. Nothing is mounted on a plane; nothing is served at request time
  by Shield.
- **Off the hot path — zero guarded-traffic impact.** No code runs in-line with
  `/guardrails/*`, `cap/mint`, or `tools/call`. The scanner is invoked as an
  offline batch step; readers hit static HTML on Pages.
- *(Alternative, Open Q1b — dynamic admin-plane serving — would add a public GET
  route + Redis reads on the CPU portal. Still off the hot path, but heavier; §4
  and §6 describe what that costs.)*

## 3. Data model

**No Redis, no tenant scoping** (in the recommended static design). The registry is
public, global content with two on-disk shapes:

- **Input (checked in):** `registry/servers.yaml` — the curated list. One entry per
  server:
  ```yaml
  - slug: github-mcp            # url-safe id; the page permalink
    name: "GitHub MCP Server"
    homepage: "https://github.com/..."
    repo: "github/github-mcp-server"
    target: "stdio:npx -y @modelcontextprotocol/server-github"  # how to scan it
    pinned: "1.2.0"             # version scanned (provenance)
    notes: ""
  ```
- **Generated (build artifacts, committed by the schedule job):**
  - `docs/registry/<slug>.md` — the SEO page (Jekyll front-matter + rendered rating).
  - `docs/registry/data/<slug>.json` — the machine-readable rating (the ScanReport
    plus the computed grade), so the data is reusable (badges, later API).
  - `docs/registry/index.md` — the directory (sorted table of all servers + grades).
  - `docs/registry/sitemap-registry.xml` (or fold into a site sitemap) + a note in
    `robots.txt`.

- *(Open Q1b only:)* if dynamic, follow the existing **global-key precedent**
  `tenants:index` — `mcp_registry:index` (a SET of slugs) + `mcp_registry:{slug}`
  (JSON rating doc). Non-tenant-scoped by design (public data); documented as the
  one global namespace, like `tenants:index`.

## 4. API / interface

No HTTP API (static design, decided). The "interface" is generated files served by
Pages, plus one CLI and the rating core:
- `python -m mcp_registry.generate [--only <slug>] [--out docs/registry]` — reads
  `servers.yaml`, scans each server, computes scores, writes the artifacts in §3.
- **Rating function (the reusable core):** `score(scan_report: dict) -> Rating`
  where `Rating = {score: int 0-100, band: str, reasons: [str], rating_version: str}`,
  a **pure, deterministic** function of the `ScanReport` `severity_counts` /
  `verdict` / `counts`. `rating_version` makes a scheme change visible in diffs.

  **Scoring rubric (numeric 0–100, decided §9.3).** Start at 100 and subtract a
  per-finding penalty by severity, floored at 0:
  `critical −80, high −25, medium −8, low −3, info 0` → e.g. one tool-poisoning
  (critical) = 20; one over-broad (high) = 75; one suspicious (medium) = 92; clean
  = 100. Display **band** for scannability: `90–100 clean`, `70–89 minor`,
  `40–69 review`, `0–39 high-risk`. Exact weights are finalized in Task 1 with the
  tests as the contract.
  - **Insufficient signal (edge, decided):** a server that **fails to scan** or
    exposes **zero** tools/resources/prompts is **not** scored 100 — it renders as
    a distinct `score: null, band: "unrated"` state with the reason, so an
    unscannable server can never masquerade as a perfect one.

## 5. Security & backward compatibility

- **Purely additive & non-breaking.** New generator + new `docs/registry/` content;
  no change to the scanner, any runtime path, or any default. Nothing that runs
  today behaves differently.
- **Untrusted-server execution is the central risk.** Rating a server means running
  `shield-mcp scan`, which for a `stdio:` target **executes third-party code**
  (`npx …`, `python …`) to complete the MCP handshake. Mitigations (hard
  requirements):
  - Generation runs **only** in an **ephemeral, network-restricted, sandboxed CI
    container** (or an explicitly-opted-in local run) — never on a Shield plane,
    never on a developer's primary machine by default.
  - The server list is **curated and version-pinned** (`pinned:`), and additions
    are code-reviewed. No auto-executing arbitrary user-submitted commands.
  - Per-scan `--timeout` and resource caps; a crashing/malicious server fails that
    one entry (marked "scan failed"), never the whole run, and never the CI host.
  - (Open Q2 chooses how far to go: sandboxed-exec vs HTTP/SSE-only vs
    community-submitted reports.)
- **Public content only** — no secrets, no tenant data, no credentials in any
  generated page or the input list. The scanner runs in **offline** mode for the
  registry (no `--shield-url`), so no keys are involved.
- **No new attack surface on a plane** in the static design (nothing served by
  Shield). The dynamic alternative (Open Q1b) adds public unauthenticated GET
  routes — those must be strictly read-only and rate-limited.

## 6. Packaging & deploy

- **Recommended (static):**
  - New package/module `packages/mcp-registry/` (or `mcp_registry/`) — the rating
    function + generator. Depends on `shield-mcp` (already published, PR #264
    Task 1) and `pyyaml` (already in `requirements-test.txt` and
    `requirements-admin.txt`). **Not** imported by `admin_app.py` ⇒ **no
    `Dockerfile.admin` change**; **no runtime image rebuild**.
  - New scheduled workflow `.github/workflows/mcp-registry.yml` (weekly cron +
    `workflow_dispatch`): sandboxed job installs `shield-mcp`, runs the generator,
    and **opens a PR** with the regenerated `docs/registry/**` (human-reviewed, so
    a bad scan can't auto-publish). The existing `docs.yml` then builds Pages on
    merge.
  - Jekyll: `docs/registry/` pages use the existing `just-the-docs` theme
    (`docs/_config.yml`); add a nav parent "MCP Registry". `sitemap`/`robots`:
    add the `jekyll-sitemap` plugin **or** emit a static `sitemap.xml` (Open Q also
    minor here; default = static file, no new plugin).
- **Alternative (Open Q1b — dynamic):** modules serving `/registry*` **are**
  imported by `admin_app.py` ⇒ each must be added to the `Dockerfile.admin` COPY
  allowlist (enforced by `tests/test_admin_dockerfile_imports.py`), and the admin
  image rebuilds. No Jinja2 today (`requirements-admin.txt`) — dynamic HTML would
  either add that dep or reuse the static-file pattern.
- **Env flags:** none required for the static design.

## 7. Failure modes & edge cases

- **A server scan fails** (unreachable, crashes, times out, bad target) → that entry
  is rendered as **"unrated — scan failed"** with the reason; generation continues.
  One bad server never breaks the directory.
- **Empty / zero-tool server** → valid page, grade reflects "nothing to flag"
  (Open Q3 decides if that's an `A` or "insufficient signal").
- **Malicious / heavy server** → sandbox + `--timeout` + resource cap; failure is
  contained to the CI job and that entry.
- **Stale ratings** → every page shows `scanned_at`, the `shield-mcp` version, and
  the `pinned` server version; the weekly job refreshes; a "last scanned" date is
  visible so readers can judge freshness.
- **Non-determinism** → offline scan is deterministic and `grade()` is pure, so
  identical inputs yield identical pages (clean diffs in the regeneration PR).
- **Huge `servers.yaml`** → generation is O(n) sequential scans; fine for a curated
  list; note the wall-clock in the workflow. No silent truncation — if a cap is
  added later, log what was skipped.
- **Fail policy:** generation is **fail-soft per entry** (one bad server → one
  "scan failed" card) but **fail-loud overall** (a broken generator/template fails
  the workflow rather than publishing empty pages).

## 8. Test plan (Definition of Done)

- **Rating function (pure, no network):**
  1. a ScanReport with a `critical` (tool-poisoning) → a low score in the
     `high-risk` band; `verdict: fail` reflected.
  2. only `high` (over-broad) → `review`/`minor` band; only `medium` → higher;
     clean (zero findings, ≥1 tool) → `100` / `clean`.
  3. deterministic: same input → same `{score, band, reasons}`; `rating_version`
     present; score floored at 0 (many findings never goes negative).
  4. **insufficient signal:** a scan-failed report OR a zero-tool/resource/prompt
     report → `score: null, band: "unrated"` (never 100).
- **Generator (fixtures, no live scanning):**
  5. given a recorded `ScanReport` per server (injected, not scanned live), emits
     `<slug>.md` (valid Jekyll front-matter + title/meta containing the server
     name + "MCP security"), `data/<slug>.json`, and an `index.md` listing all
     servers sorted by grade.
  6. a "scan failed" entry renders the unrated card, and the run still succeeds.
  7. `servers.yaml` schema validation: bad/duplicate `slug` → a clear error.
  8. generated pages are stable (byte-identical) for identical inputs (diff guard).
- **SEO plumbing:** `sitemap` lists every server page; each page has a unique
  `<title>` and `description`; `robots` allows crawling.
- **Isolation guard:** assert the registry package imports **nothing** from
  `core/` / `guardrails/` / `admin_app` (keeps it off-plane and out of the admin
  image graph) — mirrors the scanner's guard test.
- Clean-venv: `pip install` the registry package + `shield-mcp`, run the generator
  on a fixture list, pages build under `jekyll build`. Full `pytest tests -q` green;
  CI `pytest` gate passes.

## Invariant risk flags
- ✅ **Off the hot path** — static generation + Pages; the scanner runs offline in
  CI, never in-line with any guard endpoint (§2).
- ✅ **No `admin_app` import ⇒ no `Dockerfile.admin` change** in the static design
  (guarded by an import-isolation test). *(The dynamic alternative would change
  this — flagged in §6.)*
- ✅ **No new runtime dep** on any served image (`pyyaml` already present; scanner
  is a separate package). Validate in a clean venv.
- ⚠️ **Untrusted-server execution** — rating scans run third-party code; **must** be
  sandboxed + curated + pinned (§5, §7). The single biggest risk.
- ⚠️ **Auto-publish guard** — the schedule job opens a **PR**, it does not push to
  `main`; a bad scan can't silently ship.
- ✅ **Non-breaking** — additive content + a new package; scanner unchanged.

## Task breakdown (one branch, ordered — committed per task, one PR)
1. **Rating core** — `grade(scan_report) -> {grade, score, reasons, rating_version}`,
   pure + deterministic, with the taxonomy mapping documented. Unit tests 1–4.
2. **`servers.yaml` + generator** — schema + a seed list of ~10 well-known public
   servers; `python -m mcp_registry.generate` emitting `<slug>.md` / `data/<slug>.json`
   / `index.md`. Fixture-driven tests 5–8 (no live scanning). Import-isolation guard.
3. **SEO pages + Jekyll wiring** — page/index templates with tuned title/meta, nav
   parent, `sitemap` + `robots`; build under `jekyll build` in CI.
4. **Scheduled regeneration** — `.github/workflows/mcp-registry.yml` (sandboxed,
   network-restricted, weekly cron + dispatch) that regenerates and **opens a PR**.
   Docs: how to add a server (one `servers.yaml` entry + review).

## Resolved decisions (locked)
1. **Serving = static generation via the existing Jekyll/GitHub Pages pipeline.**
   Off every plane, no `Dockerfile.admin` change, best SEO. The dynamic admin-plane
   alternative is dropped for v1 (a live JSON/badge API can reuse the generated
   `data/<slug>.json` later without a plane change).
2. **Generation = sandboxed CI scanning a curated, version-pinned list.** `stdio:`
   servers run in an ephemeral, network-restricted CI container; one bad server
   fails only its own entry. The schedule job opens a PR (never auto-pushes).
3. **Rating = numeric score 0–100** with a display band (`clean/minor/review/
   high-risk`), and a distinct `unrated` state for scan-failed / zero-surface
   servers (never scored 100). Rubric in §4; weights finalized in Task 1.

## Maintainer-only / follow-up notes
- Curating `servers.yaml` (which public servers to list, and their pinned versions)
  is a human-reviewed step; the seed list ships in Task 2.
- A later phase may add verified/badge listings (monetization) and a live badge API
  over the generated `data/<slug>.json` — both out of scope here.
