# Spec: MCP scanner deep-scan (agentic reasoning pass)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.
Builds on the shipped `packages/shield-mcp` (the deterministic scanner). This adds
an **optional** `shield-mcp scan --deep` that layers an LLM reasoning pass on top
of the deterministic heuristics. The default scan is unchanged and stays
deterministic + CI-safe. Decisions locked (§9): **two providers** (OpenAI-compatible
+ native Anthropic) via `--deep-provider`; a **hard usage error** when `--deep` is
set with no backend; a **multi-step agent** (bounded loop), not a single call.

## 1. Problem & outcome

The deterministic scan (`heuristics.py`) is per-description: regex + decode checks
on each tool/resource/prompt in isolation. It cannot see **holistic** risk:
- **cross-tool privilege escalation** — `read_file` + `http_post` combine into an
  exfiltration path even though neither description is individually poisoned;
- **dangerous capability combinations** — a "read config" tool plus a "send
  message" tool;
- **semantic over-reach** — a tool named `get_status` whose description quietly
  allows writes;
- **data-exfiltration paths** across the whole surface.

**Outcome.** `shield-mcp scan --deep` sends the deterministic report **plus** the
full catalog (tool names, descriptions, inputSchemas, resources, prompts) to a
configured LLM in **one holistic reasoning call**, and merges its structured
findings into the report as `source="agent"`. These findings are **advisory**:
they are shown and included in `--json`, but they **do not change the exit code**
(the CI gate stays on the deterministic result) unless the user opts in with
`--deep-fail <severity>`.

Success = on a server whose individual descriptions are clean, `--deep` surfaces a
cross-tool exfil path as an advisory `agent` finding, while `shield-mcp scan`
(no `--deep`) behaves exactly as today.

**Non-goals.**
- **Not** replacing the deterministic scan — `--deep` is additive and off by
  default. The deterministic scan remains the CI gate.
- **Not** a multi-step agent that **executes** the target's tools to probe it.
  That would run attacker-controlled tools; explicitly out of scope for safety.
  v1 is a single reasoning pass over metadata only.
- **Not** gating CI on a non-deterministic verdict by default (see §5).
- **Not** a new server endpoint, plane, or Redis usage.

## 2. Plane & latency contract

- **Off every plane.** A client-side CLI feature. It is a *client* of an external
  LLM endpoint (the user's OpenAI-compatible / configured backend), initiated by
  the developer, opt-in via `--deep`. It touches no Shield plane and adds **zero**
  latency to `/guardrails/*`, `cap/mint`, or `tools/call`.
- **Latency/cost is opt-in and the user's.** One LLM call per scan (only with
  `--deep`); the default scan makes no network call at all.

## 3. Data model

**Stateless. No Redis, no tenant scoping.** The only "data" is transient:
- **Sent** to the configured LLM: a system prompt + the catalog metadata (names,
  descriptions, inputSchemas, resource/prompt descriptions) + the deterministic
  findings, as JSON. Never the target server's credentials, env, tool arguments,
  or `--header` values.
- **Received**: a schema-validated list of findings, mapped to `Finding(
  source="agent", confidence=…)` and appended to the in-memory `ScanReport`.

## 4. API / interface

**CLI (additive flags on `scan`):**
```
shield-mcp scan <target> [existing flags]
  --deep                    run the agentic reasoning pass (opt-in)
  --deep-provider <name>    openai | anthropic  (default: openai)
  --deep-url <url>          openai: base URL (or $SHIELD_DEEP_URL)
  --deep-model <name>       model id (or $SHIELD_DEEP_MODEL; anthropic default
                            claude-opus-4-8)
  --deep-api-key <key>      key (or $SHIELD_DEEP_API_KEY; anthropic also honors
                            $ANTHROPIC_API_KEY, openai $OPENAI_API_KEY)
  --deep-max-steps <n>      agent step budget (default: 4)
  --deep-fail <severity>    also gate CI on agent findings >= severity (default: off)
```
`--deep` with **no resolvable backend** (no url/model/key for the chosen provider)
is a **hard usage error (exit 4)** before any scan work — a misconfigured CI fails
loudly, never silently no-ops (decided §9.2).

**Provider abstraction.** `deep.py` defines a small `LLMClient` protocol
(`complete(system, user, schema) -> dict`) with two implementations:
- **openai** — one POST to `{deep-url}/chat/completions` via the `httpx` already
  in the package (no SDK), `response_format` = json_schema.
- **anthropic** — the official `anthropic` SDK (`client.messages.create`,
  `output_config.format` json_schema, `thinking: {type: "adaptive"}`), model
  default `claude-opus-4-8`. Optional dep (§6); imported lazily.

**The multi-step agent (decided §9.3).** Not a single call — a **bounded loop**
(`--deep-max-steps`, default 4) over metadata only:
1. **plan** — from the catalog + deterministic findings, list candidate holistic
   risk hypotheses (cross-tool chains, capability combos, semantic over-reach);
2. **investigate** — for each hypothesis, one focused reasoning step that confirms
   or drops it, citing the specific tools/params involved;
3. **synthesize** — consolidate confirmed hypotheses into findings.
Each step is one `LLMClient.complete` with a strict JSON schema. The loop **never
executes the target's tools** — it only reasons over metadata (a hypothesis is
confirmed by argument, not by probing). Total calls are capped at
`--deep-max-steps`; the cap is logged as a note if hit.

Each returned finding becomes `Finding(severity, category="agent-<category>",
subject_kind="tool"|…, subject_name=<joined subjects>, detail, evidence="",
source="agent")` with a new optional `confidence` field.

**Report / exit semantics (the crucial change).** Today `gating_findings(fail_on)`
counts every finding at/above `fail_on` regardless of source. This spec changes it
so **`source="agent"` findings never gate by default**; they gate only when
`--deep-fail <severity>` is set (and then only at/above that severity). The
deterministic exit code (0/2) is unaffected by `--deep` unless the user asks.

## 5. Security & backward compatibility

- **Additive & non-breaking.** New `deep.py` + new opt-in flags. Default `scan`
  is byte-for-byte unchanged (no network, deterministic). The `gating_findings`
  change is non-breaking: no `source="agent"` findings exist today, so existing
  scans gate identically. Regression-pinned (§8).
- **Advisory by default (secure-by-default for CI).** A non-deterministic LLM
  verdict must never silently fail someone's build. Agent findings are advisory;
  `--deep-fail` is the explicit opt-in.
- **Privacy (document loudly, like connected mode).** `--deep` sends the tool
  metadata (names, descriptions, schemas, resource/prompt text) to the configured
  LLM endpoint. It never sends target credentials, `env`, `--header` values, or
  tool-call arguments. State this in `--help` and the docs.
- **Indirect prompt injection (the real risk).** Scanning a poisoned server means
  feeding attacker-controlled descriptions to *our* deep-scan LLM. Mitigations:
  (a) the system prompt frames all catalog text as untrusted data to analyze, not
  instructions; (b) we accept **only** schema-validated structured findings and
  **never execute** anything the model returns (no tool calls, no shell, no
  follow-on requests); (c) the model's output can only ever become advisory
  findings text in a report. The blast radius of a successful injection is a
  misleading advisory line, not code execution.
- **Untrusted LLM output** is treated as data end to end.

## 6. Packaging & deploy

- **New module** `packages/shield-mcp/src/shield_mcp/deep.py` + a `confidence`
  field on `Finding`. **No new *required* dependency:**
  - the **openai** provider uses the `httpx` already declared (lazy import);
  - the **anthropic** provider needs the `anthropic` SDK, declared as an
    **optional extra** (`pip install shield-mcp[deep]`), imported lazily with a
    clear error if `--deep-provider anthropic` is used without it installed.
  The default scan still needs neither `httpx`, `anthropic`, nor a network.
- **No `admin_app` import ⇒ no `Dockerfile.admin` change.** No image rebuild
  (ships in the pip package). Not on the data/admin plane.
- **Env flags:** `SHIELD_DEEP_URL`, `SHIELD_DEEP_MODEL`, `SHIELD_DEEP_API_KEY`
  (client-side only). No new server env.

## 7. Failure modes & edge cases

- **LLM unreachable / 5xx / auth fail / timeout** → **fail-open**: the deep pass
  is skipped, a `note` records why, and the deterministic report + exit code
  stand. A network blip never fails a scan. (Mirrors connected-mode fail-open.)
- **Malformed LLM output** (not JSON, or fails the schema) → skip with a note; no
  crash, no partial findings.
- **`--deep` without a configured backend** (no url/model/key for the chosen
  provider) → clear **usage error (exit 4) before any scan work** (decided §9.2).
- **`--deep-provider anthropic` without the `anthropic` SDK installed** → usage
  error naming `pip install shield-mcp[deep]`.
- **Step budget exhausted** (`--deep-max-steps` hit before synthesis) → synthesize
  from what was gathered, add a note that the budget was hit; never loop forever.
- **Huge catalog** (many tools / giant descriptions) → cap the metadata bytes sent
  (reuse the scanner's size caps) and note truncation; never silently drop.
- **Non-determinism** → agent findings carry `source="agent"` + `confidence`; the
  human/JSON output labels them advisory; exit code unaffected unless
  `--deep-fail`.
- **Empty catalog / clean server** → deep pass may return zero findings; valid.

## 8. Test plan (Definition of Done)

- **Report changes (pure):**
  1. a `source="agent"` finding at `critical` does **not** gate by default
     (`exit_code` stays 0 when only agent findings exist); a deterministic
     `critical` still gates.
  2. `--deep-fail high` makes agent findings >= high gate (exit 2); below it does
     not.
  3. `confidence` round-trips through `to_dict` / `--json`.
- **Deep core (injected fake LLM client, no network):**
  4. a fake client returning valid structured findings → merged as `source="agent"`
     with the mapped severity/category/subjects/confidence.
  5. LLM error / 5xx → fail-open: no agent findings, a note added, deterministic
     result unchanged.
  6. malformed / non-schema output → skipped with a note, no crash.
  7. **privacy:** the request body contains only catalog metadata + deterministic
     findings — assert it carries no `--header` value, no env, no credentials.
  8. indirect-injection framing: the system prompt is present and the pipeline
     never executes model-returned content (structured-parse-only path asserted).
- **CLI:**
  9. `--deep` off → no LLM client constructed, byte-identical to today.
  10. `--deep` with a fake backend → agent findings appear in human + `--json`;
      `--deep-fail` flows to the exit code.
- **Regression:** existing scanner tests unchanged; `gating_findings` default
  behavior pinned. Clean-venv green; full `pytest tests -q` green; CI passes.

## Invariant risk flags
- ✅ **Off every plane** — client-side CLI; a client of an external LLM, never in
  Shield's guard path.
- ✅ **No new dependency** — OpenAI-compatible call via the existing `httpx`
  (lazy import); default scan still network-free.
- ✅ **Non-breaking** — additive flags + module; default `scan` unchanged; the
  `gating_findings` change is inert until agent findings exist (regression-pinned).
- ⚠️ **Secure-by-default exit semantics** — non-deterministic agent findings are
  advisory; gating is explicit opt-in (`--deep-fail`).
- ⚠️ **Privacy + indirect injection** — `--deep` sends metadata to an LLM;
  attacker-controlled descriptions reach that LLM. Contained by
  structured-output-only + no execution; documented in `--help`.

## Task breakdown (one branch, ordered — one PR each)
1. **Report: advisory findings** — add `confidence` to `Finding`; make
   `gating_findings`/`exit_code`/`verdict` exclude `source="agent"` by default and
   accept a `deep_fail` threshold. Tests 1-3. (Pure; no LLM.)
2. **Provider abstraction** — `LLMClient` protocol + `OpenAIClient` (httpx) and
   `AnthropicClient` (SDK, lazy/optional); structured-output request builders;
   backend-resolution + hard-error-when-unconfigured. Injected/fake-client tests.
3. **Multi-step agent core** — `deep.py`: plan → investigate → synthesize loop
   (bounded by `--deep-max-steps`), schema-validated parse into agent Findings,
   fail-open on any provider error. Injected-client tests 4-8 (no network).
4. **CLI wiring** — `--deep`, `--deep-provider`, `--deep-url/-model/-api-key`,
   `--deep-max-steps`, `--deep-fail` (+ env); `--help` privacy note; human/JSON
   render labels agent findings advisory. Tests 9-10.
5. **Docs** — `--deep` in the scanner README + the "Test your own MCP server"
   guide; the heuristics-vs-model-vs-agent framing; privacy + injection caveat.

## Resolved decisions (locked)
1. **Two providers via `--deep-provider`** — `openai` (OpenAI-compatible chat via
   the existing `httpx`; works with OpenAI, Ollama, vLLM, Together) and
   `anthropic` (native Messages API via the `anthropic` SDK, optional extra,
   default model `claude-opus-4-8`). Default provider `openai` (no new required
   dep; matches the repo's `LLM_BACKEND_URL` convention).
2. **Hard usage error (exit 4)** when `--deep` is set with no resolvable backend —
   a misconfigured CI fails loudly, never a silent no-op.
3. **Multi-step agent** — a bounded plan → investigate → synthesize loop
   (`--deep-max-steps`, default 4), metadata-only, never executing the target's
   tools. Deeper than a single call; cost/latency bounded by the step budget.
