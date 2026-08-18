"""The guard path must not answer an anonymous caller.

Reproduced against production before this existed:

    POST /guardrails/input   no key    -> 200 {"safe": true, "action": "pass"}
    POST /guardrails/input   bad key   -> 200 (identical)
    GET  /v1/tenant/me       no key    -> 401

810ms of adversarial detection ran for a caller with no credential. The
unmetered compute is the lesser problem. The real one is that an integrator who
ships a broken key sees `200 {"safe": true}` and concludes they are protected:
a guardrail that fails open while reporting success is worse than none, because
it gets trusted. That is the finding a partner security review leads with.

Two exemptions here are load-bearing rather than oversights, and both have a
test that will fail loudly if someone "tightens" them:

  * /v1/shield/cap/verify is unauthenticated BY DESIGN - tool servers verify
    capabilities on behalf of agents and the cap token IS the credential.
    Requiring a tenant key there breaks the enforcement point the entire
    capability model rests on.
  * /v1/shield/ssf/events carries its own token, closed by default.

Spec: docs/spec-guard-path-auth.md
"""
import pytest
from types import SimpleNamespace

import core.middleware as mw

ENFORCED = "/guardrails/input"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("SHIELD_GUARD_REQUIRE_KEY", raising=False)


def _request(path=ENFORCED, client_host="10.0.0.1"):
    return SimpleNamespace(
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=client_host),
        headers={}, state=SimpleNamespace(),
    )


def _refuse(path=ENFORCED, key_presented=False):
    """The refusal decision in isolation: a JSONResponse, or None to allow."""
    return mw._guard_key_refusal(path, key_presented, _request(path))


def _body(resp) -> dict:
    import json
    return json.loads(bytes(resp.body).decode())


# ── the ladder ───────────────────────────────────────────────────────────


def test_off_is_todays_behaviour(monkeypatch):
    """Merging must change nothing. off has to stay byte-identical to before
    this control existed, or the rollout is a breaking change wearing a flag."""
    assert _refuse() is None


def test_warn_allows_but_records(monkeypatch, caplog):
    """The rung that makes the rollout safe: say who would break, break nobody.
    Anonymous guard traffic may exist in a demo or an internal script today."""
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "warn")
    with caplog.at_level("WARNING"):
        assert _refuse() is None
    assert any("would be refused" in r.message or "would be refused" in r.getMessage()
               for r in caplog.records)


def test_enforce_refuses_a_missing_key(monkeypatch):
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    resp = _refuse(key_presented=False)
    assert resp is not None and resp.status_code == 401
    assert _body(resp)["error"] == "missing_tenant_key"


def test_enforce_distinguishes_a_bad_key_from_no_key(monkeypatch):
    """Different fixes: nothing sent is a wiring problem, something wrong is a
    credential problem. One generic 401 leaves an integrator guessing."""
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    assert _body(_refuse(key_presented=True))["error"] == "invalid_tenant_key"
    assert _body(_refuse(key_presented=False))["error"] == "missing_tenant_key"


def test_unknown_mode_reads_as_off(monkeypatch):
    """A typo must not start refusing production traffic."""
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enfroce")
    assert mw.guard_key_mode() == "off"
    assert _refuse() is None


def test_mode_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "ENFORCE")
    assert mw.guard_key_mode() == "enforce"


# ── what is covered, and what must not be ────────────────────────────────


@pytest.mark.parametrize("path", sorted(mw.ShieldMiddleware._REQUIRE_TENANT_KEY))
def test_every_enforced_path_refuses_under_enforce(monkeypatch, path):
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    assert _refuse(path).status_code == 401


def test_the_content_guards_are_covered():
    """The endpoints in the finding. If one leaves this set, the bug is back."""
    s = mw.ShieldMiddleware._REQUIRE_TENANT_KEY
    for p in ("/guardrails/input", "/guardrails/output", "/guardrails/file"):
        assert p in s, p


def test_the_tool_guards_are_covered():
    s = mw.ShieldMiddleware._REQUIRE_TENANT_KEY
    assert "/v1/shield/tool/check" in s
    assert "/v1/shield/tool/output" in s


def test_cap_verify_is_never_enforced():
    """THE regression guard. /cap/verify is unauthenticated by design: tool
    servers call it on behalf of agents and the cap token is the credential.
    Adding it here would make every Shield-aware tool fail closed, and it would
    look like a capability bug rather than an auth change."""
    assert "/v1/shield/cap/verify" not in mw.ShieldMiddleware._REQUIRE_TENANT_KEY


def test_ssf_receiver_is_never_enforced():
    """It has its own credential (SHIELD_SSF_RECEIVER_TOKEN, closed by default).
    Requiring a tenant key too would break IdP and EDR pushed revocation, which
    is the one path that must work while everything else is on fire."""
    assert "/v1/shield/ssf/events" not in mw.ShieldMiddleware._REQUIRE_TENANT_KEY


def test_already_protected_paths_are_not_double_covered():
    """cap/mint refuses without a verified agent token; /v1/tenant/* refuses in
    _require_tenant. Adding them would not be wrong, but it would put the
    refusal in two places and the second one would rot."""
    s = mw.ShieldMiddleware._REQUIRE_TENANT_KEY
    assert "/v1/shield/cap/mint" not in s
    assert not any(p.startswith("/v1/tenant") for p in s)


def test_health_and_docs_are_not_enforced():
    s = mw.ShieldMiddleware._REQUIRE_TENANT_KEY
    for p in ("/health", "/ping", "/docs", "/openapi.json"):
        assert p not in s


# ── the refusal must not become an oracle ────────────────────────────────


def test_refusal_names_no_tenant(monkeypatch):
    """A 401 that leaked which tenants exist would turn this control into an
    enumeration endpoint."""
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    for presented in (True, False):
        body = _body(_refuse(key_presented=presented))
        assert set(body) == {"error", "detail"}
        for leaky in ("tenant", "acme", "hr-helpdesk"):
            assert leaky not in body["detail"].lower() or leaky == "tenant"


def test_refusal_shape_matches_the_middlewares_other_errors(monkeypatch):
    """agent_blocked and agent_disabled already use {error, detail}. A third
    shape would mean a client handles three."""
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    body = _body(_refuse())
    assert "error" in body and "detail" in body


# ── source-level guards ──────────────────────────────────────────────────


def test_enforcement_reads_the_process_not_the_request():
    """A caller must not be able to turn its own enforcement off."""
    import inspect
    src = inspect.getsource(mw.guard_key_mode)
    assert "os.environ" in src
    assert "request" not in src


def test_fail_open_when_the_store_is_degraded():
    """A caller who DID present a key must not be refused for our outage. The
    opposite choice is defensible; this one is deliberate, so it is pinned:
    a store outage should degrade to unauthenticated screening, not to a total
    outage of the customer's application."""
    import inspect
    src = inspect.getsource(mw.ShieldMiddleware.dispatch)
    assert "store_degraded" in src
    assert "if not store_degraded" in src
