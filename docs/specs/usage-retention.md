# Spec: usage retention → "unused N days" hygiene (not auto-revoke)

Status: in progress. Task 1 (storage) shipped with this doc; Tasks 2–4 follow.

## 1. Problem & outcome
Today usage is a bounded ~50-event, tenant-wide buffer, so governance can only
say "not seen lately," never a trustworthy time-based signal. Add per-(agent,
tool) **last-used** retention so the screen can show **"unused N days"** as an
**access-hygiene** signal a human recertifies. Idleness is surfaced, never
auto-revoked, and Shield does **not** emit a `revoke` recommendation from
idleness.
Non-goals: auto-revoke; a `revoke` recommendation derived from idleness;
analytics charts.

## 2. How security actually works (framing)
Three distinct things — keep them separate:
1. **Enforcement** — authorize at the moment of action (RBAC + single-use
   capabilities). Already shipped. This is the control.
2. **Detection (Security findings)** — used-but-not-granted (drift),
   over-privilege, anomaly. High-signal; act now. → `investigate`.
3. **Hygiene (recertification)** — idle grants and dormant agents; right-size
   over time. Advisory; human decides. → `review` (+ `days_since_use`).

"Unused → revoke" is bucket 3 (hygiene), not a security verdict. Matches AWS IAM
Access Analyzer "unused access" and Entra access reviews: surface last-used, let
a human recertify; never auto-stamp revoke.

## 3. Recommendation taxonomy
| Bucket | Trigger | Type | Recommendation |
|---|---|---|---|
| `keep` | used recently | — | keep |
| `investigate` | used-but-not-granted, over-privilege | Security | flag (act) |
| `review` | granted, idle ≥ N days **or** never seen | Hygiene | review for right-sizing (carries `days_since_use`) |

No `revoke` recommendation value exists. Revoke is the reviewer's decision only.

## 4. Plane & latency
- Reads on the admin plane (off hot path).
- Write: one fire-and-forget `HSET` (+TTL) inside the existing
  `agent_auth_stats.record()` — already an inline write on cap-mint/verify.
  Marginal; never raises; not on `/guardrails/*`.

## 5. Data model
- `shield:usage:lastseen:{tenant}` → field `"{agent_id}\x1f{tool}"` → `last_ts`.
- TTL refresh on write (`SHIELD_GOVERNANCE_LASTSEEN_TTL_DAYS`, default 120).
- Written on positive-use events (`cap_minted`, `cap_verified`) carrying both
  `agent_id` and `tool`. In-process fallback mirrors the existing stats store.

## 6. Security & backward compatibility
- `SHIELD_GOVERNANCE_UNUSED_DAYS` (default 30) only affects labeling/sorting in
  the hygiene view — never an action.
- Empty index (pre-rollout) → everything is `keep`/`review`; no surprises.
- Tenant-scoped. No change to enforcement, decisions, or apply.

## 7. Packaging & deploy
- Lives in `storage/agent_auth_stats.py` (Task 1) + `api/routes_governance.py`
  (Task 2). Both already in `Dockerfile.admin`/`core/app.py`. No new module,
  no new dependency. Env vars optional with safe defaults.

## 8. Failure modes
- Redis down → last-seen skipped (record() already tolerant); falls back to
  recent buffer + `review`.
- New/dormant agent → `review`, never an action.
- Rare-but-critical tools → stay `review`; human decides.
- Clock: server `time.time()` only. Separator `\x1f` avoids id/tool collisions.
- Large tenants → one hash read per call; paginate if huge.

## 9. Test plan (DoD)
- last-seen recorded on `cap_minted`/`cap_verified`; not on non-usage events or
  when tool/agent missing; `get_last_seen` merges redis+fallback.
- (Task 2) `days_since_use` math; `keep`/`review`/`investigate` mapping; idle≥N
  and never-seen → `review` (never `revoke`); env override; empty-index back-compat.
- Full suite green in a clean venv; CI passes.

## Task breakdown (one PR each)
1. **Storage** — last-seen write in `record()` + `get_last_seen()` reader (+ tests). ← this PR
2. **Governance API** — surface `last_used`/`days_since_use`; taxonomy stays
   `keep|review|investigate`; idle≥N stays `review`.
3. **UI** — split Governance into **Security findings** vs **Access hygiene**
   (days-since column, dormant-agent flag).
4. **Docs** — `agent-governance.md`: enforcement vs detection vs hygiene.
