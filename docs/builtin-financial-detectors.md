---
title: Built-in financial detectors
layout: default
nav_order: 78
permalink: /builtin-financial-detectors/
description: Validated card numbers, IBANs, routing and account numbers, SWIFT/BIC codes and US Social Security numbers, found in prompts even when spaced out or base64, hex or URL encoded, on laptops, at the web gateway and on the API.
---

# Built-in financial detectors
{: .no_toc }

Shield finds payment and banking identifiers in prompts without any rules
from you, checks that each one is real (a checksum, not just a pattern), and
also finds them when they have been disguised by spacing or encoding.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What is detected

| Detector | Id | How a match is confirmed |
|---|---|---|
| Card numbers | `card_number` | 13 to 19 digits, a known issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay) and the Luhn checksum |
| IBAN | `iban` | The country's IBAN length and the mod-97 check digits |
| US routing numbers | `aba_routing` | 9 digits, a valid Federal Reserve prefix and the ABA checksum, with a word such as "routing" or "ABA" just before it |
| SWIFT / BIC | `swift_bic` | 8 or 11 characters with a real country code, written right after "SWIFT" or "BIC" |
| Bank account numbers | `bank_account` | 8 to 17 digits right after "account number", "acct" or "a/c" |
| US Social Security numbers | `us_ssn` | Valid area, group and serial numbers, written as `123-45-6789` or after the word "SSN" |

Order, invoice, ticket, tracking, IMEI and ISBN numbers are not reported as
cards, even when their digits pass the checksum.

## Disguised values are found too

Before matching, Shield undoes the common ways a value is hidden:

- spaces, dots or dashes between digits (`4 1 1 1 ...`), and invisible
  zero-width characters;
- fullwidth and other non-Latin digits;
- base64 (standard and URL-safe), hex (`\x34`, `0x34`, plain), percent
  encoding (`%34`) and HTML entities (`&#52;`), including one inside another,
  such as base64 inside a URL.

A value found inside encoded text is redacted together with the whole encoded
fragment.

## Where it runs

| Where | How to turn it on | Actions |
|---|---|---|
| Laptops (device agent) | On by default in monitor. Change each detector under **Endpoint DLP > Policy > Built-in detectors** | off, monitor, redact, block |
| Web gateway (ICAP) | Follows the same Endpoint DLP policy | off, monitor, block. The gateway cannot rewrite requests, so use block there. |
| API (`/guardrails/input`) and the browser extension | **Input & Output Guardrails > Add guardrail > Financial Identifiers & SSNs** | Any guardrail action. Redact returns the masked text in `redacted_text`. |

On laptops, **monitor** records a finding and changes nothing. **Block** and
**redact** act only in fleets whose mode is enforce.

## Test values

Published test values such as `4111 1111 1111 1111`, `123-45-6789` and the
example IBAN `GB82 WEST 1234 5698 7654 32` are detected so that a POC shows
the detectors working. Findings mark them as test values. In production, tick
**Ignore published test values** (or set `ignore_test_values: true`) so they
are skipped.

## Privacy

A finding records which detector matched, how many times, which encodings were
undone and whether the value was a published test value. The value itself is
never logged, counted, exported or sent to Shield.

## Limits

- Text is scanned up to 256 KiB per prompt. Encoded text is decoded two levels
  deep, at most 32 fragments and 128 KiB per prompt.
- Numbers written as words ("four one one one") and look-alike letters from
  other alphabets are not decoded.
- Images and scanned documents are not read.
- Business information such as revenue figures or budgets is not an
  identifier. Use a custom policy for that.
- On the API, a scan that runs past 25 ms passes the prompt and reports
  `timeout: true` rather than holding it.

## Turning it off

Set `SHIELD_BUILTIN_DETECTORS=off` on the data plane to remove the detectors
from every laptop and gateway bundle. Agents go back to your rules only on
their next policy sync. The API guardrail is off unless a tenant enables it.
