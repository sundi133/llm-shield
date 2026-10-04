# Red-team corpus

The attack corpus for `scripts/redteam_tenant.py`, which runs it against a live
Shield tenant and scores what that tenant's deployed config catches, per threat
class. Spec: [docs/specs/redteam-tenant-harness.md](../docs/specs/redteam-tenant-harness.md).

## Run it

```bash
SHIELD_URL=https://<data-plane> TENANT_KEY=<test-tenant-key> \
  python scripts/redteam_tenant.py --sample 50 --report redteam-report.json
```

- `--sample N` keeps at most N cases per class (seeded, repeatable). The full
  corpus is about 27,400 cases; at roughly half a second per model-backed call
  and 8 at a time that is close to half an hour, so sample for a deploy gate and
  run the whole set on a schedule.
- `--classes prompt-injection,excessive-agency` and `--stages input,hook` narrow it.
- `--validate` checks the corpus files and makes no calls.
- Use a **test** tenant. Every call is tagged `X-Shield-User: redteam-check` and
  session `redteam-<time>`, so its audit rows are easy to tell apart.

Exit status: 0 the gate passed, 1 it did not, 2 bad usage or a malformed corpus.
The gate fails when a class is under its threshold in `thresholds.json`, when
more benign probes are blocked than `max_false_positive_rate` allows, or when
any case is inconclusive (no answer, timeout, non-200): coverage that could not
be measured is not counted as coverage.

## Reading a miss

Every attack that got through is labelled with what to fix:

| label | meaning | fix |
|---|---|---|
| `dormant` | none of the guards that should catch it ran (input/output: none of them in the response's `guardrail_results`; hook: the agent has no runtime profile) | enable a guard |
| `unenforced` | a guard flagged it, but monitor mode or a `warn`/`log` action let it through | switch to enforce, or set the action to block |
| `failed_open` | a guard that should catch it could not check it and allowed by default ("LLM call failed, allowing by default") | the model backend; it is waving everything through |
| `missed` | the guards that should catch it ran and did not flag it | a detection gap |

All four count against the class score. A guard that reports passing without
checking (failed open, or "No ... configured" / "... skipping") does not count
as having run. When any guard fails open, in any response, the report adds a
note naming them. `dormant` is only claimed on evidence;
if the harness cannot see what ran, the miss stays `missed`. Which guards
"should catch" a case comes from `guard_map.json` (by stage and threat class),
plus the case's own `guards` and `guards_hint`.

## The cap and gateway stages

Both are off by default (`--stages` defaults to `input,output,hook`) because
their cases name a tenant's own agents and tools. `examples/bank-demo.jsonl` is
a worked example for the MCP gateway bank demo's `customer-service-agent`; copy
it and use your own tool names.

```bash
AGENT_TOKEN=<signed agent token> SHIELD_URL=... TENANT_KEY=... \
  python scripts/redteam_tenant.py --corpus redteam/examples/bank-demo.jsonl \
    --stages cap,gateway --gateway-route <sandbox-route>
```

- `cap` posts to `/v1/shield/cap/mint` and needs `AGENT_TOKEN` (mint one with
  `POST /v1/tenant/me/agent-auth/agent-token`). Allowed cases mint a
  short-lived, single-use capability.
- `gateway` sends JSON-RPC `tools/call` to `/gateway/<route>/mcp`. **When Shield
  allows a call, the real upstream tool runs**, so use a route whose upstream is
  a sandbox.

## Case format

One JSON object per line:

```json
{"id": "tp-001", "threat_class": "tool-poisoning", "stage": "output", "expect": "block",
 "payload": {"output": "...", "context": {"tool_name": "calculator"}}}
```

| field | meaning |
|---|---|
| `stage` | `input` -> `POST /guardrails/input` (`payload.message`); `output` -> `POST /guardrails/output` (`payload.output`, optional `context`); `hook` -> `POST /v1/shield/hooks/claude-code` (`payload.tool_name`, `payload.tool_input`); `cap` -> `POST /v1/shield/cap/mint` (`payload.tool`, `payload.resource`); `gateway` -> `tools/call` on `/gateway/<route>/mcp` (`payload.name`, `payload.arguments`). |
| `expect` | `block` / `redact` (input, output), `deny` (hook, cap, gateway), or `allow`: a benign probe that must not be blocked. |
| `agent_key`, `user_role` | optional; sent as `X-Agent-Key` (`X-Agent-ID` on output) and `X-User-Role`. Hook and gateway cases default to `--agent` (`claude-code`). |
| `route` | gateway only; overrides `--gateway-route`. |
| `guards`, `guards_hint` | guards that can catch this case (request-style or runtime names); widen the set used to tell `dormant` from `missed`. |
| `technique`, `section`, `source`, `note` | metadata for the report; not sent. |

A payload must not carry per-request guard settings (an `input` block). The
server honours those only when the tenant has no config of its own, so they
would switch on the very guard whose absence the harness exists to find. The
loader refuses them.

## Where the cases come from

| file | cases | source |
|---|---|---|
| `suite-<industry>.jsonl` (13 files) | 2,100 each: 1,850 `prompt-injection` + 250 `benign` | `guardrails-red-team-suite/NN_<industry>.sh`, converted |
| `advbench.jsonl` | 60 `harmful-content` | AdvBench subset (MIT), from `scripts/fetch_benchmark.py` |
| `harmbench.jsonl` | 40 `harmful-content` | HarmBench subset (MIT), from `scripts/fetch_benchmark.py` |
| `seed.jsonl` | 20 | hand-written: `tool-poisoning`, `sensitive-disclosure`, `excessive-agency`, `benign`. All values are synthetic or published test values. |

The suite files are generated. After changing the suite scripts, regenerate:

```bash
python redteam/convert_corpora.py
```

`tests/test_redteam_tenant.py` fails if the committed suite files no longer
match the scripts. The AdvBench/HarmBench source JSON is not in the repo; to
refresh those two files, pass them with `--benchmark <file>`.
