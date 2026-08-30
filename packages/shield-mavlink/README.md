# shield-mavlink

Policy enforcement for aircraft, decided on the aircraft.

The network is not in the decision path. A signed policy bundle is cached on the
companion computer, verified against a pinned key, and evaluated locally. The
cloud distributes policy and collects audit, both asynchronously and both
optional. An air-gapped install sets a bundle by hand, never sets a URL, and
works.

Spec: [docs/spec-mavlink-arm-authorization.md](../../docs/spec-mavlink-arm-authorization.md)

## Prove it rather than believe it

```bash
python packages/shield-mavlink/prove.py
```

Runs from anywhere, by absolute path, with no `PYTHONPATH`. The only requirement
is `cryptography`; if it is missing the script says so rather than raising.

Seven attacks, executed rather than described, with no network:

| # | Attempt | Result |
|---|---|---|
| 2 | Edit the altitude ceiling in the bundle on disk | signature fails, aircraft will not arm |
| 3 | Generate your own key and sign a permissive policy | pinned key rejects it |
| 4 | Install a genuinely signed bundle from another fleet | binding rejects it |
| 5 | Keep flying on a bundle that has lapsed | expiry rejects it |
| 6 | Fly offline, then change a denial to an approval in the log | detected, and the record number is named |
| 7 | Delete the inconvenient record entirely | detected as a sequence break |

Every one is reproducible by hand in the temp directory the script prints.

## What it does not prove

Stated because a proof that overclaims is worth less than a narrow one.

- It does **not** prove the aircraft recorded every decision it made. Nothing
  running only on that aircraft can; a compromised process could decide and stay
  silent. Central checkpointing on sync closes it.
- It does **not** authenticate MAVLink. An attacker on the same network can spoof
  the authorizer, because unsigned MAVLink permits that. MAVLink 2 signing is the
  separate answer.

## Modules

| Module | Needs | Purpose |
|---|---|---|
| `shield_mavlink/bundle.py` | `cryptography` | sign, verify, pin, expire |
| `shield_mavlink/audit.py` | stdlib only | hash-chained decision log |

Neither imports `mavsdk`, so both run on a machine with no drone SDK installed.
