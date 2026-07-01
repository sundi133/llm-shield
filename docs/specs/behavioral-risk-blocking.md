# Spec: real-time behavioral risk blocking (baseline + deviation)

Status: approved in session 2026-07-01 (build all three). Feature 3 of 3.

## 1. Problem & outcome

- Shield blocks on FIXED rules (RBAC, resource scope, revocation, clearance).
  An agent that stays inside its granted scope but behaves abnormally — a
  never-before-seen tool, a call-rate spike, off-hours activity — sails
  through. Detection-after-the-fact is a governance-tool posture; Shield is
  inline and can stop the next action.
- Outcome: per-agent behavioral baselines, deviation scoring with
  explainable signals, and an enforcement gate on `cap/mint` that costs the
  hot path ZERO additional I/O. Observable success: in `enforce` mode a
  flagged agent's next mint is denied with an explainable reason; clearing
  the flag (human step-up) restores minting.
- Non-goals: ML/anomaly models (v1 is explainable statistics — an auditor
  must be able to read the reason); background schedulers (evaluation is
  operator-driven: portal button / cron hitting the endpoint); per-instance
  baselines; auto-revocation of live instances (flag + deny-next-mint only).

## 2. Plane & latency contract

- Detection/scoring: portal/governance plane (`routes_governance.py`
  Phase 5 + new pure-logic module `core/behavioral_risk.py`).
- Guard path: **gate on `cap/mint` only, zero added I/O.** The scorer
  persists a compact flag INTO the agent's registry entry
  (`behavioral_risk` key); `_decide_authz` already loads that entry
  (`_load_agent_entry`, uncached, fresh each call — verified), so the gate
  is a dict `.get()` on data already in memory. Behind
  `SHIELD_BEHAVIORAL_RISK=enforce`; in the default mode the hot path reads
  nothing and behaves exactly as today.
- Latency budget: enforce-mode adds two dict lookups + one int compare
  (~ns) to `cap/mint`. `tools/call` and `/guardrails/*` untouched.

## 3. Data model

- `governance:baselines:{tenant}` → `{agent_id: {tools: {tool: n},
  resources: {r: n}, hours: {"0".."23": n}, rate_per_hour: float,
  events_analyzed: int, computed_at: ts}}` (kv, no TTL; rebuilt on demand).
- Registry entry key `behavioral_risk` (written only for medium/high):
  `{score: 0-100, level: low|medium|high, signals: ["new_tool:x", ...],
  evaluated_at: ts, expires_at: ts}` — expires_at = evaluated_at +
  SHIELD_RISK_FLAG_TTL_SECONDS (default 3600). **Expired flags fail safe
  to allow** (a stale block is worse than a monitoring gap); low level
  removes an existing flag.
- `governance:risk:{tenant}:last` → last evaluation report (audit).
- HONESTY CONSTRAINT: baselines derive from the bounded auth-event buffer
  (RECENT_BUFFER_MAX=50 events) — "recent behavior", not history.
  Mitigations: SHIELD_RISK_MIN_BASELINE_EVENTS (default 20) refuses to
  score thin baselines (no cold-start false blocks); every flag embeds its
  signals; longer-retention baselining shares the usage-retention roadmap.

## 4. API / interface

Under `/v1/governance` (X-API-Key, both planes, like the rest):
- `POST /risk/baselines/rebuild` → recompute + persist baselines for all
  registered agents seen in the buffer. Returns summary.
- `GET /risk/baselines` → stored baselines.
- `POST /risk/evaluate` → score each baselined agent's activity in the
  last SHIELD_RISK_WINDOW_SECONDS (default 900) against its baseline;
  write/clear flags (medium/high write, low clears); persist + return the
  report. Mode `off` → `{mode: off, evaluated: false}`, no writes.
- `GET /risk` → current flags per agent (from registry entries).
- `POST /risk/{agent_id}/clear` → human step-up approval: remove the flag
  (404 if none). Registry write mirrors trim/campaign convention.
- Scoring (v1 constants, explainable): new_tool +40, rate_spike +30
  (current > SHIELD_RISK_RATE_MULTIPLIER × baseline rate, floor 0.5/h),
  new_resource +15, odd_hours +15 (hour bucket empty in baseline). Level:
  <40 low, 40-69 medium (step-up), ≥70 high (block).
- Enforcement (`_decide_authz`, only when `SHIELD_BEHAVIORAL_RISK=enforce`
  and flag unexpired): medium → deny `"behavioral risk: step-up approval
  required"`; high → deny `"behavioral risk block (high): <signals>"`.
  Reuses the existing deny path (`public_denial_payload`, EVENT_CAP_DENIED
  audit) — no new enforcement primitive.

## 5. Security & backward compatibility

- Mode flag `SHIELD_BEHAVIORAL_RISK` = `off` | `monitor` (default) |
  `enforce`. Default `monitor`: evaluation endpoints work and flags are
  visible in the portal, but the hot path NEVER consults them — zero
  behavior change for existing deployments. `enforce` is the explicit
  opt-in; `off` disables even evaluation writes (escape hatch).
- Blocking is deny-next-mint: live caps (≤60 s) expire naturally —
  consistent with how registry revokes already propagate.
- A malicious tenant caller can only flag/clear its OWN agents (tenant key
  scoping identical to trim/campaigns); flagging is availability-only
  (deny), never privilege-widening.
- False-positive control: min-baseline gate, flag TTL, one-click clear,
  monitor-default. Signals are embedded so a human can adjudicate.

## 6. Packaging & deploy

- New module `core/behavioral_risk.py` imported by `routes_governance.py`
  (admin plane) and `routes_agent_auth.py` (mode check) → **added to
  Dockerfile.admin COPY list** (invariant; guarded by
  tests/test_admin_dockerfile_imports.py). No new pip deps. Env flags:
  SHIELD_BEHAVIORAL_RISK, SHIELD_RISK_RATE_MULTIPLIER (5),
  SHIELD_RISK_MIN_BASELINE_EVENTS (20), SHIELD_RISK_FLAG_TTL_SECONDS
  (3600), SHIELD_RISK_WINDOW_SECONDS (900). Rebuild both images.

## 7. Failure modes & edge cases

- No baseline / thin baseline (< min events) → agent skipped
  (`insufficient_baseline`), never flagged; no cold-start blocks.
- Redis down → kv/registry fall back in-process (existing posture);
  evaluation in that state is non-durable, enforcement gate simply reads
  whatever entry loads — fail-open by inheritance, stated explicitly.
- Expired flag → gate ignores it (fail-safe allow). Clock skew tolerated
  by TTL granularity (3600 s default).
- Agent with flag gets deleted / re-registered → flag rides the entry;
  re-registration without the key starts clean.
- Buffer churn between rebuild and evaluate (baseline includes current
  events): a tool used before rebuild is IN the baseline — evaluation
  detects post-baseline novelty only. Operator cadence: rebuild daily,
  evaluate frequently. Documented.
- Empty tenant / no activity → empty report, no writes.
- Concurrent flag writes vs manual registry edits: same read-modify-write
  convention as trim/campaign close (accepted, documented there).

## 8. Test plan (Definition of Done)

`tests/test_behavioral_risk.py`: baseline aggregation math; each signal
fires and abstains correctly (new_tool, rate_spike, new_resource,
odd_hours); level thresholds; insufficient-baseline skip; rebuild+evaluate
endpoints write medium/high flags and clear on low; `off` mode no-op;
clear endpoint (step-up) removes flag; hot-path gate via `_decide_authz`
(pattern of test_cap_mint_clearance.py): enforce+high → denied with
"behavioral risk" reason, monitor default → allowed, expired flag →
allowed. Dockerfile invariant test passes (new COPY line). Full suite
green in clean venv; CI pytest gate.
