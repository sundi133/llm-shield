# Device agent load test: poc (fake model)

- Hardware: apple_silicon (Apple M3, 16.0 GB, Darwin 27.0.0)
- Agent 0.2.0, git 767f925, 2026-11-26 21:19
- Model gate at the end: inline (p95 60.6 ms)
- Valid run: yes

## Budgets

| Budget | Limit | Measured | Result |
|---|---|---|---|
| short_prompt_added_p95_ms | <= 50 | 67.05 | FAIL |
| short_prompt_added_p99_ms | <= 150 | 78.52 | pass |
| large_body_added_p95_ms | <= 250 | 242.46 | pass |
| stream_ttfb_delta_p95_ms | <= 100 | 593.38 | FAIL |
| ws_frame_added_p95_ms | <= 50 | 65.08 | FAIL |
| tunnel_added_p95_ms | <= 10 | 3.46 | pass |
| tunnel_bytes_identical | = True | True | pass |
| proxy_failures | = 0 | 0 | pass |
| agent_cpu_mean_pct | <= 15 | 13.11 | pass |
| agent_cpu_p95_pct | <= 50 | 17.4 | pass |
| agent_rss_peak_mb | <= 250 | 158.79 | pass |
| agent_rss_growth_mb | <= 20 | 16.43 | pass |
| ollama_rss_peak_mb | <= 1200 | None | not graded |
| audit_headroom_pct | <= 50 | 750.97 | FAIL |

## Request classes

| Class | Count | Errors | Added p50 ms | p95 | p99 | Outcomes |
|---|---|---|---|---|---|---|
| prompt_s | 4719 | 0 | 59.13 | 67.05 | 78.52 | blocked 175, ok 4544 |
| prompt_l | 1661 | 0 | 224.13 | 241.08 | 253.73 | blocked 806, ok 855 |
| ws | 1109 | 0 | 58.09 | 65.08 | 68.95 | ok 1109 |
| sse | 1063 | 0 | 21.49 | 44.27 | 69.59 | ok 1063 |
| tunnel | 527 | 0 | 0.64 | 3.46 | 7.45 | ok 527 |
| upload | 1363 | 0 | 226.73 | 242.46 | 260.21 | blocked 337, ok 1026 |
| upload_over | 324 | 0 | 11.09 | 23.84 | 37.05 | ok 324 |

## Resources and queues

- agent_cpu_mean_pct: 13.11
- agent_cpu_p95_pct: 17.4
- agent_rss_start_mb: 96.7
- agent_rss_peak_mb: 158.79
- agent_rss_end_mb: 132.89
- agent_threads_peak: 12
- agent_rss_growth_mb: 16.43
- after_send_max: 0
- after_send_end: 0
- backlog_drained_s: 0.0
- audit_records: 3009
- audit_headroom_pct: 750.97
