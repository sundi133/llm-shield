# DLP benchmark: `tev1:0.8b`

Hardware: Apple M3, 16 GB, Darwin 23.5.0 (apple_silicon). Cases: 345, errors: 0.

## Gates (test split, calibrated thresholds)

| Gate | Target | Result | |
|---|---|---|---|
| recall: credentials | >= 0.80 | 1.0 | pass |
| recall: personal_data | >= 0.80 | 1.0 | pass |
| recall: customer_data | >= 0.80 | 0.938 | pass |
| recall: source_code | >= 0.80 | 0.75 | **FAIL** |
| recall: financial | >= 0.80 | 0.812 | pass |
| recall: health | >= 0.80 | 1.0 | pass |
| false positives | <= 3% | 46.1% of 115 | **FAIL** |
| latency p95 | <= 300 ms | 669.6 ms | **FAIL** |

## Detail

| | Default thresholds | Calibrated |
|---|---|---|
| macro recall | 0.917 | 0.917 |
| exfil recall | 0.538 | 0.538 |
| false positive rate | 0.461 | 0.461 |
| uncertain (allowed) | 0 | 0 |

Category named correctly (test split): credentials 1.0, personal_data 0.938, customer_data 0.812, source_code 0.875, financial 0.812, health 0.25

Latency: p50 345.2 ms, p95 669.6 ms, p99 954.3 ms over 345 calls.

Calibrated thresholds (chosen on the calibration split only): `{"block_categories": ["credentials", "customer_data"], "block_p": 0.9, "justify_p": 0.6, "exfil_intent": 0.8, "min_confidence": 0.3}`

False positives (test split): credentials-near-002, credentials-near-003, credentials-near-005, credentials-near-008, credentials-near-009, credentials-near-011, credentials-near-015, credentials-near-017, credentials-near-018, credentials-near-020, credentials-near-021, credentials-near-023, credentials-near-024, personal_data-near-002, personal_data-near-003, personal_data-near-005, personal_data-near-012, personal_data-near-018, personal_data-near-021, personal_data-near-023, customer_data-near-002, customer_data-near-003, customer_data-near-006, customer_data-near-008, customer_data-near-009, customer_data-near-012, customer_data-near-014, customer_data-near-015, customer_data-near-018, customer_data-near-020, financial-near-003, financial-near-005, financial-near-008, financial-near-009, financial-near-011, financial-near-014, financial-near-015, financial-near-017, financial-near-020, financial-near-021, financial-near-023, financial-near-024, health-near-002, health-near-003, health-near-005, health-near-006, health-near-009, health-near-012, health-near-015, health-near-018, health-near-020, health-near-023, general-014
