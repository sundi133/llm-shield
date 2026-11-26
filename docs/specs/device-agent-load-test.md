# Spec: device agent load test (POC AG-60)

Status: **draft, awaiting approval.** Branch `spec/poc-phase1-quick-wins`.

Roadmap item R6 from the POC gap analysis. Builds on `docs/specs/device-dlp-agent.md`
(§2.6 the latency gates, §4 the capture budget), `dlp-bench/` (the model benchmark)
and the end-to-end proxy fixture in `tests/test_device_capture.py`.

## 1. Problem & outcome

**Problem.** POC test AG-60 asks for "no unacceptable endpoint performance
degradation during high-volume AI usage". Nothing measures that today:

- `dlp-bench/` measures the decision model alone, one prompt at a time. Its
  latest report has Tev1 0.8B at p95 670 ms and 921 ms on Apple Silicon, against a
  300 ms gate (`dlp-bench/reports/SUMMARY.md`).
- `tests/test_device_capture.py` drives the real mitmproxy addon over TLS, but
  for correctness, one request at a time. mitmproxy is not in
  `requirements-test.txt`, so CI skips it (`pytest.importorskip`).
- `tests/test_device_fleet_scale.py` covers the server (enrollment index), not
  the laptop.

The code also points at places that could degrade under load. These are
hypotheses for the test to confirm or clear, not established facts:

1. **Response streaming.** `proxy.py` sets neither `stream_large_bodies` nor
   `flow.response.stream`. mitmproxy buffers response bodies by default, so a
   streamed chat answer may reach the browser all at once, at the end.
2. **Model queueing.** `screen_http` runs in `asyncio.to_thread`. With the model
   inline, one request can hold a thread for up to `model_timeout_ms` (1500 ms)
   per chunk, and up to `MAX_CHUNKS` (4) chunks. The agent does not set Ollama's
   parallelism, so concurrent tabs may queue on one model.
3. **After-send backlog.** When the gate keeps the model off the send path,
   `Engine._after_send` queues work on `ThreadPoolExecutor(max_workers=1)` with
   an unbounded queue. If prompts arrive faster than the model answers, the
   backlog and memory grow.
4. **Audit backlog.** `sync.push_audit` uploads at most 200 records per sync,
   and syncs run every 300 s, which caps uploads at 2,400 records an hour. Each
   sync re-reads the whole chain (`audit.records()`). In monitor mode every
   allow is recorded (`Engine._should_record`).
5. **Large bodies.** A body up to `MAX_BODY` (1 MiB) is decoded, extracted and
   run through the rules under `RULES_BUDGET_S` (250 ms).

**Outcome.** A load-test harness that drives a scripted, realistic AI workload
through the real `LocalProxy` and `Engine` against a local fake AI service, with
either a fake or the real model. It produces a report: JSON plus Markdown, every
budget marked pass or fail, and the hardware class. It runs in three ways:

- a CI smoke run on every PR (fake model, proxy path only);
- a full run on reference laptops, with the report kept as POC evidence;
- a saturation run that shows what happens past model capacity.

**Non-goals.**
- Fixing what the test finds. Each failure becomes a follow-up with its own
  change. This spec builds the measurement only.
- Model accuracy (that is `dlp-bench`), server-side fleet scale, real AI
  providers, browser rendering time, Linux.
- Measuring an installed agent service in place (attach mode). That is a
  follow-up (see Follow-ups).

## 2. Plane & latency contract

- **Plane:** endpoint only. The harness runs on a laptop or a CI runner. No
  data-plane or admin-plane code changes. Sync is off during a run (no Shield
  URL), so nothing is sent to Shield.
- **Guard path:** untouched (`/guardrails/*`, `cap/mint`, `tools/call`). It is off
  the hot path, with no impact on guarded traffic.
- **Agent runtime:** no change to `votal_device_agent/`. The harness imports and
  starts the agent's own classes.

## 3. Data model

No Redis keys. Files only, under `packages/votal-device-agent/loadtest/`:

- `profiles/*.json`: one workload each, with duration, ramp, concurrent tabs,
  request mix, prompt sources, fake model latency, and budgets.
- `reports/<hardware>-<profile>-<date>.json` and `.md`, kept only for laptop runs.
  The JSON holds:
  - `meta`: agent version, git SHA, profile, `model.hardware_class()`, CPU model,
    RAM, OS, power source, model name and mode (`fake` / `real`), gate state
    (`inline` or `after_send`, plus p95 at the end).
  - `classes`: per request class (prompt S/M/L, upload, WebSocket frame,
    streamed response, non-AI tunnel), each with count, errors, and added
    latency p50/p95/p99 in ms. Streams also get TTFB delta and total delta.
  - `resources`: agent CPU % (mean, p95 of 1 s samples), RSS (start, peak, end),
    thread count, and Ollama CPU and RSS.
  - `queues`: after-send queue depth (max, end), audit records written, and
    upload headroom (records per hour divided by the 2,400 ceiling).
  - `budgets`: one entry per budget: `{name, limit, measured, pass}`.
  - `valid`: false when the load generator could not keep up (§7).

Prompts come from `dlp-bench/dlp_eval.jsonl`, benign and sensitive mixed, so the
rules and the model see realistic text and some requests are redacted or
blocked. The report counts outcomes but grades nothing on accuracy.

## 4. API / interface

```bash
python packages/votal-device-agent/loadtest/run_load.py \
  --profile smoke|poc|saturate --model fake|real [--model-latency-ms 50] \
  [--out packages/votal-device-agent/loadtest/reports]
```

Three processes, so the load generator's CPU never counts against the agent:

1. **Agent under test** (`agent_runner.py`): starts `LocalProxy` and `Engine` with
   a test policy (`ai_hosts: ["localhost"]`, enforce mode) and a per-run device
   CA in a temp dir, as the e2e fixture does. Model: the scripted fake (as
   `FakeOllama` in `tests/test_device_agent.py`, with a latency knob) or the real
   local Ollama. Writes one stats line per second: the after-send queue
   depth, engine counters, gate p95, and audit records.
2. **Fake AI service** (`fake_upstream.py`): TLS on localhost. Serves:
   - JSON chat replies;
   - SSE streams (N chunks over T seconds);
   - a WebSocket chat endpoint;
   - an upload sink;
   - a non-AI echo host reached through a CONNECT tunnel, which must pass
     byte-for-byte untouched.
3. **Load generator** (`load.py`): N concurrent "tabs" by profile. Every
   request is sent once through the proxy and once directly, interleaved;
   added latency is the difference. A sampler records CPU and RSS of
   processes 1 and the Ollama server.

**Profiles (proposals):**

| Profile | Duration | Tabs | Mix | Model |
|---|---|---|---|---|
| `smoke` (CI) | 60 s | 4 | 60 % short prompts (0.2-2 KB), 15 % long (10-30 KB), 10 % WS frames, 10 % SSE, 5 % non-AI tunnel | fake, 50 ms |
| `poc` (laptop) | 10 min, ramp 1 to 8 tabs | 8 | smoke mix plus uploads 256 KiB to 1 MiB, and some over 1 MiB (must pass unscreened) | real |
| `saturate` | 5 min load, 5 min idle | 16 | short prompts at 2x the measured model rate | real or fake 400 ms |

**Budgets (proposals for approval; all numbers are ours, not a standard).**
The reasoning: chat services take one or more seconds to first token, so the
proxy should add well under 10 % of that. Rule and gate limits reuse what the
agent already enforces (`RULES_BUDGET_S`, spec §2.6).

| Budget | Limit | Applies |
|---|---|---|
| Added latency, prompts up to 32 KB, model off the send path | p95 ≤ 50 ms, p99 ≤ 150 ms | all profiles |
| Added latency, bodies up to 1 MiB | p95 ≤ 250 ms | poc |
| Added latency, model inline | p95 ≤ gate + 50 ms (Apple Silicon 350 ms, x86 850 ms) at 1 tab; ≤ 2x gate at 8 tabs | poc, only where the gate passes |
| Streamed response, time-to-first-byte delta | ≤ 100 ms | all |
| WebSocket frame delay | p95 ≤ 50 ms | all |
| Non-AI tunnel | added p95 ≤ 10 ms, bytes identical | all |
| Proxy-caused failures (reset, timeout, non-policy 5xx) | 0 | all |
| Agent CPU | mean ≤ 15 % of one core, p95 ≤ 50 % | poc |
| Agent RSS | peak ≤ 250 MB; growth ≤ 20 MB over the last 8 min | poc |
| Ollama RSS | ≤ 1.2 GB (spec measured about 0.9 GB resident) | poc, real model |
| After-send backlog | back to 0 within 2 min of load stopping; agent RSS within 10 % of pre-load | saturate |
| Audit headroom | records/hour ≤ 50 % of the 2,400 ceiling | poc |

**Hardware tiers.** The tiers match the spec's reference hardware:

- Apple Silicon M1 or later, 16 GB.
- An x86 Windows laptop without a GPU: Intel Core i5 or Ryzen 5, 16 GB.

Each report names its tier. A POC customer can run the `poc` profile on their
own laptop image.

**CI.** The main `pytest` job runs the harness unit tests, which do not use
mitmproxy (§8). The smoke run gets a separate job, `device-agent-load-smoke`, in
`.github/workflows/test.yml`, the same way the browser tests get their own job:
- It installs `requirements-test.txt`, `requirements-ws.txt` and the harness's
  requirements, then runs `--profile smoke --model fake`.
- Shared runners are noisy, so it only enforces four things:
  - zero proxy-caused failures;
  - the non-AI tunnel passes bytes identical;
  - added latency p95 for short prompts ≤ 200 ms (four times the laptop budget);
  - the report validates against the schema.
- It uploads the report as an artifact. Streaming and resource budgets are
  reported but do not fail the CI job.

## 5. Security & backward compatibility

- No change to agent behavior, defaults or packaging. The installers do not
  include the harness: PyInstaller collects only `votal_device_agent`, `icap`,
  `shield_mavlink` and `mitmproxy` (`packaging/macos/build_pkg.sh`).
- **TLS.** The run's device CA and the fake service's CA are generated in a temp
  directory and trusted only by the harness's own clients. Nothing is added to
  the laptop's trust store.
- **Clients.** The harness's clients set an explicit proxy and clear
  `HTTPS_PROXY` / `HTTP_PROXY` from their environment, so an installed agent or a
  corporate proxy on the laptop is not in the path.
- **Network.** No real provider or Shield is contacted. Everything binds to
  127.0.0.1 on port 0.
- **Data.** Prompts are the existing evaluation set: fictional people,
  documentation-example keys. No customer data.

## 6. Packaging & deploy

- **Location:** `packages/votal-device-agent/loadtest/`, repo only. It holds
  `run_load.py`, `agent_runner.py`, `fake_upstream.py`, `load.py`, `report.py`,
  `profiles/` and `reports/`.
- **Dependencies:** `loadtest/requirements.txt` holds `psutil` (CPU and RSS of
  other processes on macOS and Windows) and `websockets` (the WS client and
  server), plus `-r ../requirements.txt` for mitmproxy.
  - Nothing is added to `requirements.txt` or `requirements-admin.txt`: no
    plane imports these.
  - **Invariant risk:** the unit tests run in the main CI job without these
    packages. The harness imports `psutil`, `websockets` and `mitmproxy` lazily,
    and the unit tests cover only the pure modules (`report.py` budgets,
    percentiles, profile parsing, schema). A test pins that importing
    `report.py` pulls none of the three.
- **Packaging:** no `Dockerfile.admin` change, no image rebuild, no env flags.
- **CI:** one new job in `test.yml`, added in the same PR as the harness (§9,
  task 2).

## 7. Failure modes & edge cases

- **Generator bottleneck.** If the load generator's CPU goes over 80 %, or the
  achieved rate is under 90 % of the target, the run is marked `valid: false`
  and no budget is graded.
- **Real model.** With `--model real` and no Ollama or `tev1` model, the run
  aborts before load with the `DecisionModel.health` state. It is not graded as
  a pass.
- **Gate.** The gate needs 20 samples before the model can go inline, and the
  first minute of `poc` is warm-up and excluded. The report states whether the
  gate ended `inline` or `after_send`. Inline budgets apply only when it ended
  inline.
- **Laptop conditions.** Thermal throttling or battery power skew results. The
  report records the power source and refuses to grade a laptop run on battery
  unless `--allow-battery` is given.
- **Expected responses.** Bodies over 1 MiB should pass unscreened (`engine.note`
  monitor). Blocked requests return a policy 403 or WS close 4403. Both are
  expected outcomes, not failures.
- **Crashes and hangs.** If the agent process dies, the run fails and its stderr
  goes into the report. A request with no response in 30 s counts as a
  proxy-caused failure.
- **Ports.** Port 0 everywhere, so parallel runs never collide.
- **Windows.** psutil reads the agent and `ollama.exe`. Real-time antivirus
  scanning of the temp CA directory is recorded as part of the environment, not
  excluded.

## 8. Test plan (Definition of Done)

Unit tests in `tests/test_device_load_harness.py`, main CI job, no mitmproxy:

- Percentiles match a known series; added latency is computed against paired
  direct requests.
- Every budget passes and fails at its boundary; an invalid run grades nothing.
- Profiles load and validate: unknown keys, an empty mix, or weights that don't
  sum to 100 are refused.
- The report JSON validates against the schema, and the Markdown renders every
  budget row.
- Importing `report.py` loads none of `psutil`, `websockets`, `mitmproxy`.
- Prompt sampling from `dlp_eval.jsonl` is deterministic with a seed.

The CI smoke job:

- passes its four enforced checks on `main`;
- shows a deliberately slowed fake model (`--model-latency-ms 2000`) as
  `after_send` with the proxy budgets still passing, which proves the gate keeps
  the model off the send path.

The full suite is green in a clean venv, and the CI `pytest` gate and the
smoke job both pass.

## 9. Tasks (one PR each, in order)

| # | Task | Size |
|---|---|---|
| 1 | Harness: fake service (JSON, SSE, WS, upload, non-AI tunnel), agent runner with fake/real model and stats, load generator, sampler, report and budgets; unit tests | M |
| 2 | CI smoke job in `test.yml`, report artifact, the slowed-model check | S |
| 3 | Laptop runs: `poc` and `saturate` on Apple Silicon and an x86 Windows laptop; commit the reports; update AG-60 in the POC sheet with the result | S |

## Follow-ups (not in this spec)

- Fix whatever fails, each as its own change. Likely candidates:
  - response streaming through the proxy (hypothesis 1);
  - a bounded after-send queue that records "not judged" when full (3);
  - audit upload batch size and cadence under load (4).
- Attach mode: measure an installed agent service in place. This needs a test
  host in the POC fleet's `ai_hosts`.
- Linux, once a Linux agent exists (roadmap R19).
