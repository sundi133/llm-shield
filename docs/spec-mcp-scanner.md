# Spec: MCP server scanner CLI (`shield-mcp scan`)

Status: **APPROVED (design locked) — ready to implement Task 1.** Spec-first per
`CLAUDE.md`. Open questions resolved 2026-07-11 (see resolutions inline + at end).

**Locked decisions:** (1) package lives at `packages/shield-mcp/`; (2) offline
heuristics are fresh patterns written in the package (no import of `adversarial.py`);
(3) default `--fail-on` = `critical`, and **confirmed tool-poisoning is classified
`critical`** so the default gate still catches it (over-broad-permission = `high`,
advisory, does not fail CI by default); (4) the runtime import-bug fix ships as
Task 1 of this same branch.

## 1. Problem & outcome

Developers add third-party MCP servers to Claude Desktop / Cursor / their agents
with no way to know if a server is safe *before* connecting. The known attack is
**tool poisoning**: hidden prompt-injection embedded in tool/resource/prompt
**metadata** (descriptions, arg docs), which the agent reads and obeys. There is
also **over-broad permission** surface (a "read weather" server that also exposes
`exec`, `wire_transfer`, filesystem-write tools). Shield already detects injection
at *runtime* through the gateway — but there is no **pre-connect, standalone**
audit an indie dev can run in 10 seconds from a terminal or CI.

**Outcome:** `pipx install shield-mcp && shield-mcp scan <target>` connects to any
MCP server (stdio / SSE / HTTP), enumerates its tools, resources, and prompts,
audits every piece of metadata, and prints a findings report (+ `--json`). It
**exits non-zero when findings meet/exceed a severity threshold** — the hook that
makes it a CI gate (Phase 2). This is the top-of-funnel "npm audit for MCP": free
offline scan for reach, connected mode (calls Shield's data plane) for the strong
model verdict — that split is the free→paid line.

**Non-goals.**
- Not runtime enforcement — that's the gateway (`core/mcp/gateway.py`), already
  built. The scanner is *pre-flight, static*; it does not proxy or block calls.
- Not the GitHub Action or `npx` wrapper — Phase 2, separate spec. This spec is the
  Python core + `pipx` entry point only.
- Not the public registry / SEO ratings site — Phase 3, downstream of this.
- The scanner does **not** import the guardrail model stack (no torch/vLLM on a
  laptop) — see §2, §6.

## 2. Plane & latency contract

- **Off the hot path.** The scanner is a **standalone CLI**, not a plane. In
  connected mode it is a *client* of the data-plane endpoint `POST /guardrails/input`
  — one request per scanned description, initiated by the developer, never inline
  with anyone else's guarded traffic. It adds **zero** latency to `/guardrails/*`,
  `cap/mint`, or `tools/call`.
- **No model in-process.** `AdversarialGuardrail` (`guardrails/input/adversarial.py`)
  is model-backed and requires vLLM — it cannot run on the target's machine.
  Therefore:
  - **Offline mode (default, free):** static heuristics only — no network, no model.
  - **Connected mode (`--shield-url` + key):** POSTs each description to
    `/guardrails/input`; the data plane runs `AdversarialGuardrail` and returns the
    verdict. Same detection the gateway uses, reached over HTTP — the free→paid line.

## 3. Data model

The scanner is **stateless** and writes **no Redis keys**. It reads from the target
MCP server over the MCP protocol and (optionally) POSTs to the data plane.

- **Input:** a target — `stdio:` command, `sse:`/`http:` URL — plus optional
  `--shield-url`, `--api-key` (or `SHIELD_URL` / `SHIELD_API_KEY` env).
- **In-memory report object** (serialized to stdout, human or `--json`):
  ```
  ScanReport {
    target, transport, scanned_at,        # scanned_at from the OS clock at run time
    counts: { tools, resources, prompts },
    findings: [ Finding {
      severity: critical|high|medium|low|info,
      # severity map: tool-poisoning=critical, encoded-content=critical,
      #   over-broad-permission=high, suspicious-metadata=medium, shadow-capability=info
      category: tool-poisoning | over-broad-permission | suspicious-metadata
              | encoded-content | shadow-capability,
      subject: { kind: tool|resource|prompt, name },
      detail, evidence,                    # evidence = the offending snippet
      source: heuristic | model            # model only in connected mode
    } ],
    verdict: pass|fail, exit_code
  }
  ```
- **No tenant scoping** in offline mode (no Shield contact). In connected mode the
  API key resolves the tenant server-side exactly as any `/guardrails/input` call;
  the scanner sends only the descriptions being scanned, never target credentials.

## 4. API / interface

**CLI (the product surface):**
```
shield-mcp scan <target> [options]
  <target>                 stdio:'<cmd> <args>' | sse:<url> | http:<url>
  --json                   machine-readable report to stdout
  --fail-on <severity>     min severity that sets non-zero exit (default: critical;
                           tool-poisoning is critical, so it gates by default)
  --shield-url <url>       enable connected mode (model verdict)
  --api-key <key>          tenant API key for connected mode (or SHIELD_API_KEY)
  --timeout <s>            per-target / per-request timeout
  --offline                force heuristics only even if --shield-url given
Exit codes: 0 = clean/below threshold; 2 = findings >= threshold;
            3 = target unreachable / protocol error; 4 = usage error.
```

- **Consumes** (connected mode only): `POST {shield-url}/guardrails/input`, body
  `{"message": "<description text>"}`, auth via `X-API-Key`. Reuses the existing
  route (`api/routes_classify.py:198`) — **no new server endpoint is added by this
  spec.** Response `GuardrailResult{passed, action, guardrail_name, message, ...}`
  → mapped to a `Finding` when `passed is False`.
- **Mounts no router on any plane.** Pure client + CLI.

## 5. Security & backward compatibility

- **Purely additive.** New standalone package; no change to any existing runtime
  path, route, or default. Nothing that runs today behaves differently.
- **Default is offline & network-free** — safest default; a scan never phones home
  unless the developer passes `--shield-url`.
- **Connected mode sends only description text** (tool/resource/prompt metadata) to
  the data plane — never the target server's credentials, env, or call arguments.
  Document this explicitly in `--help`.
- **Untrusted input.** The scanner ingests attacker-controlled tool descriptions.
  It only ever *pattern-matches and reports* them (or forwards as a `message` field
  to the guard) — it never executes target tools, never renders descriptions into a
  shell, and connects to the target read-only (`initialize`, `*/list`, `*/get`,
  `resources/read` only if `--read-resources` is later added; **not** in v1).
- **Companion fix (same feature area, flag for inclusion):** the runtime scan
  `core/mcp/proxy_server.py::_scan_for_poisoning` imports
  `guardrails.input.adversarial_detection` (nonexistent) and references
  `AdversarialDetectionGuardrail` (nonexistent). The real module is
  `guardrails/input/adversarial.py`, class `AdversarialGuardrail`. The bad import is
  swallowed by `except Exception: return tools`, so **tool-poisoning scanning at the
  gateway is silently a no-op today.** See §8 / Task 1.

## 6. Packaging & deploy

- **New standalone Python package** under `packages/shield-mcp/`
  with its **own** `pyproject.toml` declaring a `console_scripts` entry point
  `shield-mcp = shield_mcp.cli:main`. Installed via `pipx install shield-mcp`.
- **Deps (declare, keep light):** `mcp` (client SDK — currently only in
  `requirements-test.txt`; the scanner package declares it in its own
  `pyproject.toml`, so the repo runtime images are unaffected), `httpx` (already
  present). **The package must NOT depend on `guardrails/`, `core/`, torch, or
  vLLM** — that is the whole point of offline heuristics + HTTP connected mode.
- **No `admin_app.py` import** ⇒ **no `Dockerfile.admin` change.** Add a regression
  assertion that the scanner package is not in the admin import graph (§8).
- **No image rebuild.** The scanner ships as a pip package, not a service image.
- **Env flags:** `SHIELD_URL`, `SHIELD_API_KEY` (connected mode only). No new server
  env flags.

## 7. Failure modes & edge cases

- **Target unreachable / bad transport / handshake fails** → exit 3 with a clear
  message; never hang (respect `--timeout`).
- **Target exposes zero tools/resources/prompts** → valid empty report, exit 0.
- **Huge / thousands of tools or huge descriptions** → cap per-description bytes
  before heuristics/POST (mirror the size caps in `shield_guard`); stream, don't
  buffer the whole catalog in one string.
- **Malformed / null descriptions** → treated as empty (no finding), never crash.
- **Connected mode: Shield unreachable / 5xx / auth fail** → **do not fail the
  scan**; degrade to offline heuristics, emit an `info` finding noting the model
  pass was skipped, and (default) keep exit code from heuristics only. Fail-open on
  the *model augmentation*, because a network blip must not turn a clean scan into a
  CI failure. (Heuristic findings still gate normally — fail-closed on what we can
  determine locally.)
- **Encoded payloads** (base64/ROT13/hex hiding an injection in a description) →
  offline heuristic decodes-then-checks common encodings; connected mode also
  benefits from the guard's own decode step.
- **Non-UTF8 / binary junk in metadata** → decode defensively, flag as
  `suspicious-metadata`.

## 8. Test plan (Definition of Done)

- **Task 1 (companion bug fix) regression:** a test that `_scan_for_poisoning`
  actually annotates a poisoned description (i.e., the import resolves and the guard
  runs) — this test **fails on `main` today**, proving the no-op, and passes after
  the import fix.
- **Scanner unit tests (fake MCP server / recorded catalog):**
  1. tools/resources/prompts enumeration across stdio, sse, http transports.
  2. clean server → zero findings, exit 0.
  3. planted injection in a tool description → `tool-poisoning` finding, exit 2.
  4. over-broad tool (`exec`, `wire_transfer`, fs-write) → `over-broad-permission`.
  5. base64/ROT13-encoded injection → `encoded-content` finding.
  6. `--fail-on` threshold gates exit code correctly (low finding + `--fail-on high`
     → exit 0).
  7. `--json` output validates against the `ScanReport` shape.
  8. target unreachable → exit 3, no traceback.
  9. **connected mode:** stub `/guardrails/input` returning `passed:false` →
     merges a `source: model` finding; stub returning 5xx → degrades to offline +
     `info` note, exit code unchanged (fail-open on augmentation).
  10. connected mode sends only `{"message": <desc>}` — assert no credentials/args
      leave the process.
- **Packaging guard:** assert the scanner package imports **nothing** from
  `core/`, `guardrails/`, `admin_app` (keeps it laptop-light and out of the admin
  image graph).
- Clean-venv install of the scanner package (`python -m venv /tmp/x`), `shield-mcp
  scan --help` works; full `pytest tests -q` green; CI `pytest` gate passes.

## Invariant risk flags
- ✅ **Off the hot path** — standalone CLI; connected mode is a *client* of
  `/guardrails/input`, never inline (§2).
- ✅ **No `admin_app` import** ⇒ no `Dockerfile.admin` change — guarded by a test.
- ⚠️ **New dep `mcp`** — declared in the scanner package's own `pyproject.toml`,
  NOT pulled into repo runtime images. Validate in a clean venv.
- ✅ **Non-breaking** — purely additive; no existing default changes.
- ⚠️ **Companion fix** — the latent `_scan_for_poisoning` import bug is in the same
  feature area; include it (Task 1) rather than stranding it.

## Task breakdown (one branch, ordered — one PR each)
1. **Fix `_scan_for_poisoning` import** (`adversarial.py` / `AdversarialGuardrail`)
   + regression test proving it annotates. Tiny, self-contained.
2. **Scanner core (offline):** package skeleton + `pyproject.toml`, MCP connect
   (stdio/sse/http), catalog enumeration, static heuristics (poisoning patterns,
   over-broad-permission list, encoded-content decode-and-check),
   `ScanReport` + human/`--json` output + exit codes. Tests 1–8.
3. **Connected mode:** `--shield-url`/`--api-key`, POST to `/guardrails/input`,
   merge model findings, fail-open degradation. Tests 9–10.
4. **Packaging & docs:** `pipx` install path, README, `--help` privacy note, the
   import-isolation guard test, clean-venv validation.

*(Phase 2, out of scope here: GitHub Action + `npx @votal/mcp-scan` wrapper.)*

## Resolutions (2026-07-11)
1. **Offline heuristics source** → **fresh lightweight patterns in the scanner
   package.** No import of `adversarial.py`; the package stays dependency-free and
   laptop-light. It reimplements only the encoding decode-and-check idea.
2. **Package location** → **`packages/shield-mcp/`** — unambiguous pip-package
   boundary, clearly separate from server code.
3. **`--fail-on` default** → **`critical`.** To keep the headline attack gated by
   default, **confirmed tool-poisoning and encoded-injection findings are classified
   `critical`**; over-broad-permission is `high` (advisory, does not fail CI by
   default). A dev can tighten with `--fail-on high`.
4. **Task 1 (runtime import bug)** → **included as the first commit of this branch**
   (single ordered branch per repo convention).
