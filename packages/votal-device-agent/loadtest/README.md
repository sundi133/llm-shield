# Device agent load test

Measures what the Votal device agent adds to AI traffic on a laptop under
heavy use (POC test AG-60). Spec: `docs/specs/device-agent-load-test.md`.

It runs the agent's own proxy and decision engine against a local fake AI
service, sends every request once through the agent and once directly, and
reports the difference, plus the agent's CPU, memory and queues. Nothing is
sent to a real AI provider or to Shield, and nothing is added to the laptop's
certificate store.

## Run it

```bash
python -m venv /tmp/lt && /tmp/lt/bin/pip install -r packages/votal-device-agent/loadtest/requirements.txt
/tmp/lt/bin/python packages/votal-device-agent/loadtest/run_load.py --profile smoke --model fake
```

| Profile | What it does | Time |
|---|---|---|
| `smoke` | 4 tabs, fake model (50 ms); the CI check | 1 min |
| `poc` | 8 tabs ramping up, uploads to 1 MiB and over; real model by default | 10 min |
| `saturate` | 16 tabs faster than the model can answer, then 5 min idle to watch the backlog drain | 10 min |

Options:

- `--model fake|real`: `real` uses the local Ollama (`--ollama-url`, default
  `http://127.0.0.1:11434`) with the model the policy pins (`tev1:0.8b`); the
  run stops if it is not there.
- `--model-latency-ms N`: how slow the fake model is.
- `--duration-s N`: shorten or lengthen a profile.
- `--allow-battery`: grade a laptop run on battery (refused by default, since
  battery power and heat skew the numbers).
- `--expect-gate after_send|inline`: fail unless the model gate ended this way.

Each run writes `reports/<hardware>-<profile>-<model>-<date>.json` and `.md`.
The exit code is 0 when every enforced budget passes, 1 when one fails or the
run is invalid, 2 for a harness error.

## Reading the report

- **Added latency** per request class: p50, p95 and p99 of (through the agent)
  minus (direct).
- **Budgets**: every limit with its measured value. Budgets marked "reported
  only" never fail the run. A run is invalid, and grades nothing, when the load
  generator itself uses more than 80 % of a core.
- **Model gate**: `inline` means the model judged prompts before they were sent;
  `after_send` means it was too slow for the gate and judged them afterwards.
- Blocked prompts (the evaluation set includes sensitive ones) are counted as
  outcomes, not failures.

The budgets are our own proposals from the spec, not an industry standard.
