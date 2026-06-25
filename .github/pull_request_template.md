<!-- Spec-first: link or paste the spec before the diff. See docs/spec-template.md -->

## Spec
<!-- Link to the spec (issue/doc) or paste the filled template. Required for non-trivial changes. -->

## What & why
<!-- One-paragraph summary of the change and the outcome it delivers. -->

## Checklist (see docs/spec-template.md)
- [ ] **Spec written/linked** before coding; this PR is one scoped task.
- [ ] **Plane & latency** — states data vs admin plane; if it touches the guard path (`/guardrails/*`, `cap/mint`, `tools/call`), the latency impact is justified (otherwise: off hot path).
- [ ] **Packaging** — any new module imported by `admin_app.py` is added to `Dockerfile.admin`'s COPY list.
- [ ] **Dependencies** — new pip deps added to `requirements.txt` (runtime) and `requirements-test.txt` (and `requirements-admin.txt` if admin uses it).
- [ ] **Backward compatibility** — no breaking default change; or it's opt-in / behind an escape-hatch flag with a migration note.
- [ ] **Security** — auth + tenant isolation considered for any new endpoint; no secrets committed.
- [ ] **Tests** — unit tests for happy path + edge cases; full suite passes in a **clean venv**; CI `pytest` gate green.
- [ ] **Self-contained** — any dependency/Dockerfile/CI change needed to pass is in *this* PR (no stranded companion fixes).
