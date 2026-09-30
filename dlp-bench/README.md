# DLP benchmark for on-device decision models

Measures whether a local decision model is good enough to enforce DLP on
laptops. Spec: [docs/specs/device-dlp-agent.md](../docs/specs/device-dlp-agent.md),
task 1. Nothing is enforced on the strength of a model until it passes here on
the hardware it will run on.

## The set

`dlp_eval.jsonl`, built by `build_eval.py` (the source of truth; a test fails if
they drift). 345 prompts, all written by hand:

| Group | Count | What it is |
|---|---|---|
| Positives, 6 categories | 151 | credentials, personal data, customer data, source code, financial, health: the data is really there |
| Near misses, 6 categories | 144 | looks like the category but is not sensitive: public code, fictional people, documentation example keys, general questions |
| Exfiltration intent | 20 | the user is trying to move company data out |
| Exfiltration look-alikes | 10 | offboarding, backups and sharing done the approved way |
| General | 20 | ordinary questions |

False positives are counted on every benign prompt (near misses, look-alikes
and general), because a model that flags near misses has learned to refuse
work, not to find data.

Every credential is a documentation example or an obviously fake value, and
every person is fictional. A test rejects any token shape secret scanners treat
as live.

Split: one third `calibration` (used only to choose thresholds), two thirds
`test` (used only to report).

## Run it

Needs an Ollama build with decision-model support (`/v1/systemone`) and the
model pulled:

```bash
ollama pull tev1:0.8b
python dlp-bench/run_dlp_bench.py --model tev1:0.8b
```

Standard library only; runs on macOS and Windows. Writes
`reports/<model>-<hardware class>.md` (summary) and `.json` (every answer, for
re-analysis without re-running the model).

## Gates

From the spec, measured on the test split with thresholds chosen on the
calibration split:

| Gate | Target |
|---|---|
| Recall per category | at least 0.80 |
| False positives on benign prompts | at most 3 % |
| Decision latency p95, Apple Silicon | 300 ms |
| Decision latency p95, x86 laptop CPU | 800 ms |

A hardware class that misses the latency gate runs the model after sending
(monitor), with rules still blocking inline.
