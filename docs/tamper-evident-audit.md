---
title: Tamper-Evident Audit
layout: default
nav_order: 17
permalink: /tamper-evident-audit/
---

# Tamper-Evident Audit

Shield's audit stores (`audit:{tenant}`, `decisions:{tenant}`,
`admin_audit:{tenant}`) are append-only, but by default nothing stops someone
with Redis/backup access from altering or deleting entries **undetectably**.
Enabling tamper-evidence links every record into a per-scope **hash chain** and
signs the chain head into periodic **Ed25519 checkpoints**, so any alteration,
deletion, or truncation becomes provable — and pinpointable to the exact record.

Design rationale and threat model: [spec-tamper-evident-audit.md](spec-tamper-evident-audit.md).

## Enable

Opt-in, off by default. Set on the data-plane and admin-plane:

```bash
export SHIELD_AUDIT_TAMPER_EVIDENT=1
# A stable Ed25519 signing key (32-byte hex). Generate once, store as a secret.
export SHIELD_AUDIT_SIGNING_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
# Optional cadence (defaults shown):
export SHIELD_AUDIT_CHECKPOINT_N=100     # checkpoint every N records per scope
```

> Use a **real** key in production. Without `SHIELD_AUDIT_SIGNING_KEY` an
> ephemeral key is generated and checkpoints can't be verified across restarts.
> Roll out in staging first, confirm `/audit/verify` is green, then production.

Chaining runs on a background writer, so the guard path (`/guardrails/*`,
`tool/check`) is unaffected (**+0 ms**). A lost write (Redis blip) surfaces as a
chain gap on verify rather than blocking any request.

## Verify

```bash
# Tenant key -> own tenant; master/admin key -> any tenant or global.
curl -H "X-API-Key: $KEY" \
  "https://<shield>/v1/shield/audit/verify?store=audit"
```
```json
{ "valid": true, "checked": 1423, "break_at_seq": null,
  "reason": null, "last_checkpoint": {"seq": 1400, "ts": 1751990400.0} }
```
`store` is `audit` | `decisions` | `admin_audit`. On tamper, `valid` is `false`
and `break_at_seq` is the first altered/missing record.

## Export + verify offline (for auditors)

```bash
curl -H "X-API-Key: $KEY" \
  "https://<shield>/v1/shield/audit/export?store=audit" > bundle.json

# Auditor verifies WITHOUT Shield or its private key (only needs `cryptography`):
python3 scripts/verify_audit_bundle.py bundle.json
# -> VALID: OK — 1423 records, 14 checkpoints verified   (exit 0)
```

The bundle carries the records, the signed checkpoints, and the **public** key.
`scripts/verify_audit_bundle.py` is self-contained (stdlib + `cryptography`), so
an auditor can re-run it on their own machine.

## What it does and doesn't do

- **Detects** any modification, deletion, reordering, or truncation of audited
  records since they were written — pinpointed to a sequence number.
- **Does not prevent** deletion (Redis can't) — it makes deletion *evident*.
- **Coverage:** the three audit stores above. Token/cap mint/verify events are a
  planned addition (see the spec's open questions).
