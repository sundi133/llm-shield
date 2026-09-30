# DLP benchmark: `tev1:0.8b`

Hardware: Apple M3, 16 GB, Darwin 23.5.0 (apple_silicon). Cases: 345, errors: 0.

## Gates (test split, calibrated thresholds)

| Gate | Target | Result | |
|---|---|---|---|
| recall: credentials | >= 0.80 | 0.824 | pass |
| recall: personal_data | >= 0.80 | 0.875 | pass |
| recall: customer_data | >= 0.80 | 0.938 | pass |
| recall: source_code | >= 0.80 | 0.375 | **FAIL** |
| recall: financial | >= 0.80 | 0.438 | **FAIL** |
| recall: health | >= 0.80 | 0.812 | pass |
| false positives | <= 3% | 2.6% of 115 | pass |
| latency p95 | <= 300 ms | 920.9 ms | **FAIL** |

## Detail

| | Default thresholds | Calibrated |
|---|---|---|
| macro recall | 0.258 | 0.71 |
| exfil recall | 0.077 | 0.308 |
| false positive rate | 0.0 | 0.026 |
| uncertain (allowed) | 1 | 0 |

Category named correctly (test split): credentials 1.0, personal_data 0.625, customer_data 0.812, source_code 0.562, financial 0.75, health 0.875

Latency: p50 658.9 ms, p95 920.9 ms, p99 1073.4 ms over 345 calls.

Calibrated thresholds (chosen on the calibration split only): `{"block_categories": ["credentials", "customer_data"], "block_p": 0.471, "justify_p": 0.3, "exfil_intent": 0.25, "min_confidence": 0.0}`

False positives (test split): credentials-near-009, customer_data-near-006, health-near-002
