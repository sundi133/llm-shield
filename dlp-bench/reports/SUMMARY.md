# Task 1 result: Tev1 0.8B for on-device DLP

Measured 2026-09-30 on an Apple M3 (16 GB, macOS 14.5), Ollama 0.35.0,
`tev1:0.8b` (digest d45e875d63fe, 811 MB, runs on the GPU in 893 MB with a
2,050-token context). 345 hand-written cases; thresholds chosen on the
calibration split (120) only; everything below is the test split (225), which
influenced no choice. Spec: docs/specs/device-dlp-agent.md §2.6.

## Verdict

**Tev1 0.8B can enforce four of the six categories with the right question
wording, cannot enforce source code or financial data, and misses the latency
gate on this Mac.** It is usable as a second tier behind rules, per category, not
as a general DLP model.

| Gate (test split) | Target | Topic wording | Actual-data wording |
|---|---|---|---|
| Recall: credentials | 0.80 | 1.00 | **0.82** pass |
| Recall: personal data | 0.80 | 1.00 | **0.88** pass |
| Recall: customer data | 0.80 | 0.94 | **0.94** pass |
| Recall: health | 0.80 | 1.00 | **0.81** pass |
| Recall: source code | 0.80 | 0.75 | 0.38 **fail** |
| Recall: financial | 0.80 | 0.81 | 0.44 **fail** |
| False positives on benign prompts | 3 % | 46 % **fail** | **2.6 %** pass (3 of 115) |
| Exfiltration intent recall | (none set) | 0.54 | 0.31 |
| Latency p50 / p95 | p95 300 ms | 345 / 670 ms **fail** | 659 / 921 ms **fail** |

Reports: `tev1-0.8b-apple_silicon-q1-topic.md` and `-q2-actual-data.md`, with
every answer in the matching `.json`.

## What we learned

1. **The model recognises topics, not the presence of data.** Asked "which
   sensitive category", it scores a question *about* passwords almost as high as
   a pasted password (median 0.55 vs 0.88 of probability away from "none"). No
   threshold separates them: 46 % false positives.
2. **Wording is the lever.** Asking whether the text *contains actual* data from
   a real system or person (`questions_v2.json`) drops benign scores to a median
   of 0.03 and keeps false positives at 2.6 %. It also costs recall on the two
   categories where "actual" is hardest to judge from text alone: proprietary
   code and non-public financials.
3. **Use 1 - P(none) as the signal.** With careful wording the model often still
   *chooses* "none" on real data while moving probability away from it. The
   harness and spec now use the mass away from "none", labelled by the most
   likely category (spec §3.2 updated).
4. **Latency is not driven by the question text; it tracks machine load.**
   (Corrected by the follow-up below.) The first full runs suggested the longer
   wording doubled latency; an interleaved measurement showed that was
   run-to-run variance. On a quiet M3 the 0.8B answers in about 350 ms at p50;
   under a busy desktop's load, about 580 ms at p50 and 1.3 s at p95, whatever
   the wording. Nimble's published 91 ms was a 9B model on an M5 Max.
5. **Exfiltration intent is weak** (0.31 recall at the chosen threshold). It
   should not drive blocking.

Together AI states Tev1 has not been fully tested on prompt injection,
non-English text, calibration or unfamiliar inputs; these results agree that it
needs careful wording and per-category limits.

## Recommendation for the agent (tasks 2 to 5)

- **Ship `questions_v2.json` as the bundle default** and the 1 - P(none) signal.
- **Per-category enforcement.** The model may `justify` for credentials, personal
  data, customer data and health; source code, financial and exfiltration
  intent are **monitor only** (recorded, not blocked) until a model passes them.
  This needs one field per category in the DLP policy (spec §5.1).
- **Rules stay first.** Credential leaks with a known shape are caught by rules
  in microseconds; the model's job is what rules cannot see.
- **Latency on this hardware class means monitor mode by the spec's own rule**
  (§2.6): the model runs after sending, rules block inline. Before accepting
  that, try in this order: (1) shorter question text with the same meaning,
  (2) `tev1:4b` (4.5 GB) on Apple Silicon for accuracy, (3) caching the
  instruction prefix if Ollama exposes it.

## Limits of this measurement

- One machine. **The x86 laptop gate is unmeasured**: run
  `python dlp-bench/run_dlp_bench.py --questions dlp-bench/questions_v2.json`
  on a Windows or Intel laptop.
- 16 or 17 positives per category in the test split, so each recall figure moves
  in steps of about 0.06; treat differences under 0.1 as noise.
- English only, hand-written prompts, no attachments, single-turn prompts.
- Latency is sequential, one request at a time, model warm.
- The Tev1 weights' licence is not stated on the model page (only the dataset
  builders and training scripts are MIT). Confirm before shipping to customers.

## Follow-up: shorter wording (2026-09-30)

Tried because the first runs suggested wording drove latency. Two shorter
wordings with the same meaning (`questions_v3a.json`, `questions_v3b.json`),
compared on the **calibration split only** (the test split was not touched):

| Wording | Input tokens | Recall at <= 3 % false positives (macro) | Exfil recall |
|---|---|---|---|
| v2 (current default) | 807 | **0.69** | 0.14 |
| v3a (short) | 609 | 0.24 | 0.00 |
| v3b (shortest) | 555 | 0.37 | 0.00 |

Latency, interleaved over the same 30 prompts for three rounds (90 calls per
wording, randomised order, load average 8 to 11):

| Wording | p50 | p95 |
|---|---|---|
| topic (v1) | 590 ms | 1338 ms |
| v2 | 582 ms | 1342 ms |
| v3a | 595 ms | 1294 ms |
| v3b | 562 ms | 1296 ms |

**Result:** shorter wording loses most of the accuracy (the explicit "not a
question, example, template or fiction" criteria are what separate real data
from look-alikes) and saves no measurable time. **v2 stays the default.** The
latency gate is a property of the hardware and its load, not the question: on an
M3 the 0.8B model runs after sending (monitor), rules block inline, as the spec
already provides.
