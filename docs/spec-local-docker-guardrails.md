---
title: "Spec: Local Docker guardrails testing stack"
layout: default
nav_order: 99
permalink: /spec-local-docker-guardrails/
description: CPU-only docker compose stack that runs both guardrail tiers on a laptop against the real Votal guardrail model, with a seed/smoke script and a shareable setup doc.
---

# Spec: Local Docker guardrails testing stack

Status: **APPROVED** (model choice resolved: llama.cpp + `votal-ai/Qwen3.5-9B-guardrailed-v3-GGUF`, public repo, no HF token)

## 1. Problem & outcome

Today there is no way to exercise **both** guardrail tiers on a laptop.

| Existing | What it gives you | Why it is not enough |
|---|---|---|
| `docker-compose.yml` | Full data plane | Requires an NVIDIA GPU (`deploy.resources.devices`) |
| `docker-compose.dev.yml` | CPU app + Redis | No LLM backend configured, so every slow-tier guardrail errors |
| `docker-compose.admin.yml` | Admin portal + Redis | Admin plane only, no guard path |
| `examples/langchain/docker-compose.local.yml` | Keycloak/LDAP identity lab | Identity-focused, still no LLM backend |

**Two modes** (added after the first live run, at the reviewer's request):

| Mode | Command | Download | Covers |
|---|---|---|---|
| Fast tier only | `up -d` | none | guard path, tenant policy, deterministic guardrails |
| Both tiers | `--profile model up -d` | 5.2GB | the above plus content judgement |

The model service sits behind a Compose profile rather than being always-on,
because a `llama` container with no weights is the worst of both worlds: it
answers nothing, every LLM guardrail fails open with `passed=True`, and the stack
reports every prompt clean while judging none. `FAST_ONLY=1` on the smoke script
matches that mode and, crucially, seeds a policy containing **no LLM guardrails at
all** - so the configuration never claims enforcement it cannot deliver.

**Outcome.** `docker compose -f docker-compose.guardrails.yml up -d` followed by
`./scripts/smoke_local_guardrails.sh` gives a green/red result proving that:

- fast-tier guardrails run (keyword, regex, PII, length),
- slow-tier LLM guardrails run *for real* (adversarial, toxicity, topic, bias),
- a tenant policy configured in the portal is what actually enforces.

Observable success condition: the smoke script exits 0 and prints a per-guardrail
table, on a GPU-less machine, with no API key required.

**Non-goals**
- Not a production deployment path (`docs/on-premises-deployment-guide.md` owns that).
- No new guardrails, no changes to guardrail logic or scoring.
- **Not a benchmark rig.** CPU inference on a 9B model is one to two orders of
  magnitude slower than the GPU data plane. Latency numbers from this stack are
  meaningless; `BENCHMARKS.md` owns that question.
- Does not replace `docker-compose.dev.yml`; that stays for admin/UI work.

## 2. Plane & latency contract

Both planes are started, as separate containers, exactly as in production:

- **Data plane** - slim CPU image (`Dockerfile.cloud`), `SKIP_VLLM=true`, with
  `LLM_BACKEND_URL` pointed at a sibling llama.cpp container. Serves
  `/guardrails/*`, `cap/mint`, `tools/call`.
- **Admin plane** - `Dockerfile.admin`, serves `static/tenant.html` on :8080.
  Owns tenant seeding, so the guard path is never used to set itself up.

**Guard path impact: none.** This task adds no application code. It adds compose
files, a shell script, and docs. No module is imported by `core/app.py` or
`admin_app.py`, no route is added, no middleware changes. The guard path in the
container is byte-identical to the one that ships - that is the point, since a
testbed that runs different code proves nothing.

### Why llama.cpp and not Ollama

`core/llm_backend.py:568` documents `_build_payload` as building "the request
payload for llama-server, LiteLLM, Ollama, or OpenRouter". The **default**
`LLM_BACKEND_TYPE=vllm` branch posts plain OpenAI-compatible
`/v1/chat/completions` with no `model` field - which is exactly what a
single-model llama.cpp server expects. Consequences:

1. **The real model.** `votal-ai/Qwen3.5-9B-guardrailed-v3-GGUF`
   (`Qwen3.5-9B-guardrailed-Q4_K_M.gguf`, ~5.2GB) is the shipped guardrail model
   in CPU-runnable form - see `core/llm_backend.py:218,425-426` and
   `docs/installation-guide.md:697-710`. Verdicts are representative, not a
   stand-in.
2. **The default code path.** Ollama mode takes a different branch
   (`/api/chat`, `think:false`, native `format` schemas). Testing that branch
   locally would not be testing what production runs.
3. **Matches on-prem.** `docs/installation-guide.md` Phase 7 already runs
   llama-server against this exact GGUF, so the local stack is a shrunk version
   of a documented topology rather than a fourth way to run Shield.
4. `VLLM_NOTHINK_SUFFIX` stays at its default `true`, correctly, because the
   model is Qwen-family (`core/llm_backend.py:456`).

`votal-ai/vai35-4B-v2` (the `Dockerfile:45` default) is **not** usable here: it
ships as HF safetensors for vLLM, and no 4B GGUF exists in the repo.

## 3. Data model

No new Redis keys. The stack uses what already exists:

| Key | Written by | Purpose here |
|---|---|---|
| `tenant:{tenant_id}` | `POST /v1/admin/tenants` | The seeded local tenant |
| `apikey:{api_key}` | `POST /v1/admin/tenants/{id}/api-keys` | Runtime key the smoke script sends as `X-API-Key` |
| `guardrail_metrics:*` | `storage/guardrail_metrics.record_results_batch_bg` | Lets the portal's Guardrail Metrics tab show local traffic |

**Tenant scoping.** The seed script creates one tenant and one key. Resolution
follows the existing path in `storage/tenant_store.resolve_request_tenant_id`
(`request.state.tenant_id` -> `X-Tenant-ID` -> `X-API-Key` lookup). The script
deliberately uses a **real minted key**, not an `sk-test-` sandbox key, so the
local run exercises the same resolution branch as production rather than the
`test-tenant-001` shortcut at `storage/tenant_store.py:473` and
`core/auth.py:169`.

## 4. API / interface

No new endpoints. The script consumes existing ones:

| Method | Path | Plane | Auth | Used for |
|---|---|---|---|---|
| `GET` | `/health` | data | none (public path) | readiness gate |
| `GET` | `/health` | llama.cpp | none | model-ready gate |
| `POST` | `/v1/admin/tenants` | admin | `X-Admin-Key` | seed tenant |
| `POST` | `/v1/admin/tenants/{id}/api-keys` | admin | `X-Admin-Key` | mint runtime key |
| `POST` | `/guardrails/input` | data | `X-API-Key` | fast + slow input assertions |
| `POST` | `/guardrails/output` | data | `X-API-Key` | output assertions |

New surface is operator-facing only:

- `docker-compose.guardrails.yml` - the stack.
- `.env.guardrails.example` - copy-to-`.env.guardrails`, all non-secret defaults.
- `scripts/smoke_local_guardrails.sh` - seed + assert, exit 0/1.
- `docs/local-docker-guardrails.md` - the shareable doc.

## 5. Security & backward compatibility

- **Additive, with one companion fix.** No existing compose file changes:
  `docker-compose.yml`, `docker-compose.dev.yml` and `docker-compose.admin.yml`
  are untouched. The exception is a new `.gitattributes` - see section 6, it is
  required for this stack to boot at all on Windows and it fixes the shipped
  images too.
- **No default change**, so no escape-hatch flag or migration note is owed.
- **Local credentials are local.** `SHIELD_ADMIN_KEY` defaults to
  `local-dev-admin-key` and is marked local-only in the compose file and the doc.
  No real key, token, or endpoint is committed. `.env.guardrails` (the filled
  copy) is added to `.gitignore`; only `.env.guardrails.example` ships.
- **Ports bind `127.0.0.1` explicitly** (`127.0.0.1:8000:80`), not `0.0.0.0`, so
  a laptop on an untrusted network is not serving an admin plane to the LAN.
  Deliberately stricter than the existing dev compose files.
- **Data egress: none.** Every prompt stays on the machine. The model is pulled
  once from Hugging Face; after that the stack runs offline. The doc mentions the
  hosted overrides (ollama.com / OpenRouter, per `docs/ollama-backend.md`) and
  repeats their egress warning, but they are not the default and not required.
- `VOTAL_ES_ENABLED=false` is set explicitly - `Dockerfile.cloud` defaults it to
  `true`, and a local testbed must not attempt to ship telemetry anywhere.
- **`SHIELD_API_KEYS` must be non-empty.** `core/auth.py:146-150` returns HTTP 500
  on *every* request when auth is enabled with an empty key list, before any
  tenant lookup happens. The compose file therefore sets one throwaway bootstrap
  key. The smoke script does **not** use it - it authenticates with the minted
  tenant key so the Redis-backed branch at `core/auth.py:163-167` is what runs.

## 6. Packaging & deploy

- **`.gitattributes` (new, required).** The repo has none, so a Windows clone with
  Git's default `core.autocrlf=true` checks every `.sh` out with CRLF. Docker
  copies them in verbatim and the kernel then tries to exec `/bin/bash\r`, giving:

  ```
  exec /start-services.sh: no such file or directory
  ```

  naming a file that is demonstrably present. This is **not specific to this
  task**: `Dockerfile` and `Dockerfile.cloud` both install
  `scripts/start_vllm.sh` as their entrypoint, so on a Windows host neither image
  has ever been able to boot. Git already stores these files with LF, so the fix
  pins checkout behavior and changes no file's content. It ships here because
  without it this stack cannot start (repo invariant: don't strand companion
  fixes).
- **`Dockerfile.admin` COPY list: no change.** Nothing new is imported by
  `admin_app.py`. `tests/test_admin_dockerfile_imports.py` stays green unchanged.
- **New pip dependencies: none.** The script is POSIX `sh` + `curl` + `python3`
  (stdlib `json` only). No `requirements*.txt` edits.
- **Images:** reuses `Dockerfile.cloud` (data) and `Dockerfile.admin` (admin)
  as-is, plus the upstream `ghcr.io/ggml-org/llama.cpp:server` and
  `redis:7-alpine`. No new Dockerfile.
- **Rollout:** none - nothing deploys. Merging changes no running system.

## 7. Failure modes & edge cases

The one that matters most, and the reason the smoke script exists at all:

**A dead LLM backend silently reads as "pass."** `core/pipeline.py:18-27` catches a
guardrail exception and returns `passed=False, action="log"`. `log` is not `block`,
so the top-level `action` on a prompt that *should* be blocked comes back `pass`
while `guardrail_results[]` carries `"message": "Guardrail error: ..."`. Someone
curling by hand and reading only the top-level verdict would conclude the
guardrails work when the entire slow tier is down. **The script therefore asserts
that no result carries a `Guardrail error:` message, and fails loudly if one does.**

| Case | Behavior | Decision |
|---|---|---|
| Model still downloading (~5.2GB, minutes) | llama.cpp not serving; guarded calls error | Script polls llama.cpp `/health` with a long budget *before* asserting, and says what it is waiting for |
| CPU inference slow (tens of seconds/call) | Default curl timeout would abort mid-check | Script sets an explicit generous `--max-time`; doc states expected latency so slowness is not misread as breakage |
| Redis down | Tenant resolution fails; seeding 500s | Script fails at the seed step with a clear message, before any assertion runs |
| `SHIELD_API_KEYS` empty | Every request 500s (`core/auth.py:146-150`) | Compose always sets a bootstrap key; test asserts it is set |
| Ports 8000/8080/8081/6379 taken | Compose bind error | Ports parameterized via `.env.guardrails`; doc has a remap section |
| Re-running the script | Tenant already exists | Seed is idempotent: reuse the key cached in `.shield-local-seed` if present, else create |
| <8GB RAM free | llama.cpp OOMs or thrashes | Doc states the RAM floor and the disk floor up front |
| Host is ARM/Apple Silicon | Upstream image is multi-arch; slower without Metal passthrough | Doc notes it works but is slower in Docker than native llama.cpp |

**Fail-open vs fail-closed:** unchanged from production - the pipeline's existing
fail-open-to-`log` behavior is preserved, and the script's job is to make that
state *visible* rather than to alter it.

## 8. Test plan (Definition of Done)

Because this ships no application code, the DoD is split:

**Automated (pytest, runs in CI with no Docker):**
1. `tests/test_local_guardrails_compose.py`
   - compose file parses as YAML and declares exactly the expected services
   - the data-plane service sets `SKIP_VLLM=true` and an `LLM_BACKEND_URL`
     pointing at the in-network `llama` service - **not** `localhost`, the
     regression already commented in
     `examples/langchain/docker-compose.local.yml` (inside a container,
     `localhost` is the container's own loopback)
   - `LLM_BACKEND_TYPE` is **not** left at the image's baked `ollama`
     (`Dockerfile.cloud:62`); the compose file must override it, or the stack
     silently takes the wrong branch and fails the `LLM_MODEL_NAME` guard in
     `scripts/start_vllm.sh:20-23`
   - `SHIELD_API_KEYS` is non-empty (guards the 500-on-every-request trap)
   - `VOTAL_ES_ENABLED=false`
   - every published port binds `127.0.0.1`
   - `.env.guardrails.example` documents every variable the compose file reads
     (drift guard: a new var in compose with no example entry fails the test)
2. `scripts/smoke_local_guardrails.sh` passes a `sh -n` syntax check.

**Manual (documented in the doc, run once before sharing):**
3. Clean machine, Docker running: `up -d`, wait for the model pull, smoke exits 0.
4. Stop the `llama` container, re-run: script exits **non-zero** citing
   `Guardrail error` - proves the false-pass trap in section 7 is actually caught.

**Gates:** full suite green in a clean venv (`python -m venv /tmp/x && /tmp/x/bin/pip
install -r requirements-test.txt`); CI `pytest` gate passes.

## 9. Task breakdown (one PR each)

| # | Task | Deliverable |
|---|---|---|
| 1 | Compose stack + env example | `docker-compose.guardrails.yml`, `.env.guardrails.example`, `.gitignore` entry, `tests/test_local_guardrails_compose.py` |
| 2 | Seed + smoke script | `scripts/smoke_local_guardrails.sh`, `sh -n` test |
| 3 | Shareable doc | `docs/local-docker-guardrails.md` + nav/index wiring |

Tasks 1 and 2 are self-contained (each green on its own). Task 3 depends on 1+2
existing so the doc describes real commands.

## 10. Live verification log

Run on Windows 11 / Docker Desktop 27.4.0, 12 CPUs, 15.5GB available to Docker.
The live run changed the design; these are the findings in the order they surfaced.

| # | Finding | Fix |
|---|---|---|
| 1 | `shield` crash-looped: `exec /start-services.sh: no such file or directory`, on a file that exists. CRLF checkout put `\r` on the shebang. Affects `Dockerfile` and `Dockerfile.cloud` equally, so **no Windows host could build either image**. | New `.gitattributes` pinning `*.sh` (and `.env*`, `Dockerfile*`, `*.yml`) to LF |
| 2 | Model cache volume was mounted at `/root/.cache/llama.cpp`; `-hf` actually writes the Hugging Face layout under `/root/.cache/huggingface/hub/`. Nothing failed visibly, the 5.2GB would simply have been re-downloaded on every `up`. | Mount the shared parent `/root/.cache`; test now asserts the mount target, not just that a volume exists |
| 3 | **The fail-open detection was wrong.** The script matched `"Guardrail error:"` (the `core/pipeline.py` path). The real path is the handler *inside* each guardrail, e.g. `guardrails/input/adversarial.py:611`, which returns `passed=True, action="pass"` and only says so in `message`. A blatant prompt injection came back `{"safe": true, "action": "pass"}` with the whole LLM tier down, and the script called it a pass. | Match `failed, allowing` as well; four new tests, one running the captured response through the helper |
| 4 | Script inherited `TENANT_API_KEY` from the shell. This repo's own `.env` sets it to a **real deployment's key**, so seeding was skipped and that credential was sent to the local stack, which answered 403 and blamed the seed file. | All script variables namespaced (`SHIELD_LOCAL_TENANT_ID`, `SEED_KEY`); the key is read only from the seed file, never the environment |
| 5 | `/guardrails/output` returned HTTP 400 `"error parsing the body"`. An em dash in the test payload is mangled by Git Bash on Windows, producing invalid JSON. | Payloads kept ASCII; troubleshooting entry added |
| 6 | Model-ready gate exited before running any assertion, so the documented negative test ("stop the model, expect red") reported a timeout instead of exercising the trap it exists for. | Gate downgraded to a warning; assertions always run |
| 7 | `pii_leakage` blocked an SSN in 0.17ms with `"source": "regex"` - it never called the model. The assertion was labelled slow-tier and proved nothing about it. | Step relabelled "Output path (fast tier: regex PII)"; tier table corrected |
| 8 | Hugging Face throttles a single connection from ~8MB/s to ~0.4MB/s after a few hundred MB. A fresh connection is immediately fast again, so it is per-connection, not per-client. First diagnosis (Docker's network stack) was wrong and was corrected. | Troubleshooting entry recommending `hf_transfer`: 0.4MB/s to ~13MB/s |
| 9 | **A corrupt model does not fail, it fails open.** A hand-rolled parallel byte-range download produced a file of exactly the right length (5,629,108,640 bytes) with a valid `GGUF` header whose sha256 did not match. llama.cpp loaded and served it without complaint; `adversarial_detection` returned `{"is_adversarial": "GGGGGGGGGGGGGGGGGGGG", "confidence": ""}`, which Shield read as "not adversarial" and passed the injection through. Nothing anywhere reported an error. | Doc now recommends only the checksum-verifying `huggingface-cli` path, publishes the expected sha256, and adds a troubleshooting entry for garbage verdict details. The earlier hand-rolled advice was removed as unsafe |
| 10 | Related: the chunk validator checked only byte *length*, so a ranged request answered with a different offset could pass validation. Length is not integrity. | Checksum verification is the only accepted check |

**Verified green:** stack builds and boots; both planes healthy; tenant seeding via
the admin plane; fast-tier enforcement; output-path enforcement; the negative test
(model down) correctly exits 1 naming the fallen-back guardrail; fast-tier-only
mode (`FAST_ONLY=1`, 3 passed, exit 0, no model, all checks under 3ms).

**Verified green (second pass, model loaded):** llama.cpp loads the GGUF and
serves it; the data plane reaches it over the in-network OpenAI-compatible path;
guardrail calls take real model time (15s to 108s per LLM-tier check on 12 CPU
threads) with no fallback reported. The `LLM_BACKEND_TYPE=vllm` -> llama.cpp
wiring is therefore proven end to end.

**Fully verified (third pass, checksum-verified weights).** `4 passed, 0 failed`,
exit 0:

```
==> Baseline (full configured pipeline)
  PASS  benign prompt passes               action=pass 97685.68ms
==> Fast tier (CPU, deterministic)
  PASS  keyword_blocklist blocks           action=block 0.21ms
==> Slow tier (LLM - expect seconds per call on CPU)
  PASS  adversarial_detection blocks       action=block 47791.32ms
==> Output path (fast tier: regex PII)
  PASS  pii_leakage blocks SSN             action=block 0.84ms
```

The corrupt model returned `pass` on that same injection prompt and the verified
one returns `block`, so the assertion discriminates on exactly what it claims to.
Every number in the doc is now measured rather than illustrative.

`huggingface-cli` with `hf_transfer` fetched the 5.2GB in about six minutes and
the sha256 matched, which is the download path the doc now recommends.

**Performance note for the doc's non-goals:** 48s for a single LLM-tier check and
98s for the full-pipeline baseline, on 12 CPU threads. The script's default
`LLM_TIMEOUT` was raised from 300s to 600s as a result. This reinforces that the
stack is for correctness, never latency.
