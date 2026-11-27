# Device agent load test: smoke (fake model)

- Hardware: apple_silicon (Apple M3, 16.0 GB, Darwin 27.0.0)
- Agent 0.2.0, git 767f925, 2026-11-26 21:09
- Model gate at the end: inline (p95 55.2 ms)
- Valid run: yes

## Budgets

| Budget | Limit | Measured | Result |
|---|---|---|---|
| proxy_failures | = 0 | 0 | pass |
| tunnel_bytes_identical | = True | True | pass |
| short_prompt_added_p95_ms | <= 200 | 64.83 | pass |
| short_prompt_added_p99_ms | <= 150 | 193.15 | FAIL (reported only) |
| stream_ttfb_delta_p95_ms | <= 100 | 633.7 | FAIL (reported only) |
| ws_frame_added_p95_ms | <= 50 | 63.6 | FAIL (reported only) |
| tunnel_added_p95_ms | <= 10 | 11.7 | FAIL (reported only) |
| agent_cpu_mean_pct | <= 15 | 5.96 | pass |
| agent_rss_peak_mb | <= 250 | 68.6 | pass |

## Request classes

| Class | Count | Errors | Added p50 ms | p95 | p99 | Outcomes |
|---|---|---|---|---|---|---|
| prompt_s | 314 | 0 | 57.85 | 64.83 | 193.15 | blocked 9, ok 305 |
| prompt_l | 79 | 0 | 220.44 | 234.72 | 251.67 | blocked 35, ok 44 |
| ws | 64 | 0 | 57.18 | 63.6 | 85.79 | ok 64 |
| sse | 68 | 0 | 21.89 | 78.41 | 198.41 | ok 68 |
| tunnel | 34 | 0 | 0.63 | 11.7 | 24.31 | ok 34 |

## Resources and queues

- agent_cpu_mean_pct: 5.96
- agent_cpu_p95_pct: 8.71
- agent_rss_start_mb: 59.97
- agent_rss_peak_mb: 68.6
- agent_rss_end_mb: 56.75
- agent_threads_peak: 7
- agent_rss_growth_mb: -3.21
- after_send_max: 0
- after_send_end: 0
- backlog_drained_s: 0.0
- audit_records: 100
- audit_headroom_pct: 246.73
