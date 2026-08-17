"""GET /v1/tenant/me/posture — what this deployment is actually enforcing.

The endpoint exists because Shield ships almost everything off by default. That
is a defensible engineering choice and an indefensible product one if nobody can
see the result, so the value of this surface is entirely in it being RIGHT: a
posture page that reports "enforcing" when nothing is enforcing is worse than no
posture page, because it converts an unknown into a false assurance.

Two failure directions, both tested here:

  * reporting a control as ON when it is off      -> false assurance
  * reporting a control as OFF when it enforces   -> operator turns it "on"
                                                     twice, or distrusts the page

The third risk is drift: this endpoint reports modes that other modules decide.
If it re-implemented the env parsing it would eventually disagree with the code
that acts on it, so the accessors are shared and a source-level test pins that.

Spec: docs/spec-findings-first-overview.md section 4.1 and section 8
"""
import inspect
import re

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import api.routes_tenant_self as rts

CONTROL_IDS = {"registry_write", "auto_revoke", "agent_token_pop",
               "role_binding", "portal_sso"}

# Every env var this endpoint reports on. Cleared before each test so a variable
# left set in the developer's shell cannot make a failing assertion pass.
POSTURE_ENVS = ("SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_ENABLE_AUTO_REVOKE",
                "SHIELD_AGENT_TOKEN_POP", "SHIELD_ROLE_BINDING",
                "SHIELD_PORTAL_REQUIRE_SSO")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in POSTURE_ENVS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def client(monkeypatch):
    """A client whose tenant always resolves — auth is covered separately."""
    from fastapi import FastAPI

    monkeypatch.setattr(rts, "_require_tenant", lambda request: "acme")
    app = FastAPI()
    app.include_router(rts.router)
    return TestClient(app)


def _controls(client) -> dict:
    body = client.get("/v1/tenant/me/posture").json()
    return {c["id"]: c for c in body["controls"]}


# ── the shape ────────────────────────────────────────────────────────────


def test_every_control_is_reported(client):
    """A control missing from the response is a control nobody will turn on."""
    assert set(_controls(client)) == CONTROL_IDS


def test_unset_env_reads_as_off_and_not_enforcing(client):
    for cid, c in _controls(client).items():
        assert c["mode"] == "off", cid
        assert c["enforcing"] is False, cid


def test_off_count_matches_the_controls(client):
    body = client.get("/v1/tenant/me/posture").json()
    assert body["off_count"] == sum(
        1 for c in body["controls"] if not c["enforcing"])
    assert body["off_count"] == len(CONTROL_IDS)


def test_scope_names_the_process_limit(client):
    """In a split deployment this reports the ADMIN process's environment. The
    field exists so a reader does not assume it covers the guardrail server."""
    assert client.get("/v1/tenant/me/posture").json()["scope"] == "process"


# ── enforcing is computed per control, not guessed ───────────────────────


@pytest.mark.parametrize("env,value,cid", [
    ("SHIELD_REGISTRY_WRITE_SCOPE", "enforce", "registry_write"),
    ("SHIELD_ENABLE_AUTO_REVOKE", "1", "auto_revoke"),
    ("SHIELD_AGENT_TOKEN_POP", "required", "agent_token_pop"),
    ("SHIELD_ROLE_BINDING", "strict", "role_binding"),
    ("SHIELD_PORTAL_REQUIRE_SSO", "1", "portal_sso"),
])
def test_enforcing_when_at_the_enforcing_rung(client, monkeypatch, env, value, cid):
    monkeypatch.setenv(env, value)
    assert _controls(client)[cid]["enforcing"] is True


@pytest.mark.parametrize("env,value,cid", [
    # The middle rungs. Each of these records or observes without refusing, and
    # calling any of them "enforcing" is the false-assurance failure.
    ("SHIELD_REGISTRY_WRITE_SCOPE", "warn", "registry_write"),
    ("SHIELD_AGENT_TOKEN_POP", "optional", "agent_token_pop"),
    ("SHIELD_ROLE_BINDING", "prefer", "role_binding"),
])
def test_middle_rungs_are_not_enforcing(client, monkeypatch, env, value, cid):
    monkeypatch.setenv(env, value)
    c = _controls(client)[cid]
    assert c["mode"] == value
    assert c["enforcing"] is False


def test_strict_proxy_is_reported_as_enforcing(client, monkeypatch):
    """strict_proxy refuses a caller with no vouched role, so it enforces — it
    is simply not a rung on the ladder. Reporting it as off would tell every
    trusted-proxy deployment it has no role binding, which is the reverse of
    true and the exact topology the demo ships with."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "strict_proxy")
    c = _controls(client)["role_binding"]
    assert c["enforcing"] is True
    assert c["next"] is None      # nothing to recommend; it is not on the ladder


# ── the ladder: next is the FOLLOWING rung, never a jump ─────────────────


def test_next_from_off_is_the_middle_rung_not_enforce(client):
    """off -> enforce in one click is how a rollout becomes an outage. Every one
    of these controls has a declare-then-enforce step for a reason, and this
    endpoint must not offer a way around it."""
    c = _controls(client)
    assert c["registry_write"]["next"] == "warn"
    assert c["agent_token_pop"]["next"] == "optional"
    assert c["role_binding"]["next"] == "prefer"


def test_next_advances_one_rung(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "warn")
    assert _controls(client)["registry_write"]["next"] == "enforce"


def test_next_is_none_at_the_top(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert _controls(client)["registry_write"]["next"] is None


def test_boolean_controls_go_straight_to_on(client):
    """auto_revoke and portal_sso have no middle rung — there is no 'warn' for
    them — so their ladder is two rungs and next is 'on'."""
    c = _controls(client)
    assert c["auto_revoke"]["next"] == "on"
    assert c["portal_sso"]["next"] == "on"


# ── hostile / malformed input ────────────────────────────────────────────


def test_unknown_value_normalises_to_off(client, monkeypatch):
    """Same convention as /me/key-scope. A typo must not read as enforcing."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "banana")
    c = _controls(client)["role_binding"]
    assert c["mode"] == "off"
    assert c["enforcing"] is False


def test_posture_ignores_the_request(client, monkeypatch):
    """A caller must not be able to influence the reported posture. If headers
    or query params could reach it, a tenant could make their own deployment
    look compliant to anyone reading this endpoint."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "off")
    spoofed = client.get(
        "/v1/tenant/me/posture?enforcement=enforce&registry_write=true",
        headers={"X-Registry-Write-Scope": "enforce",
                 "SHIELD_REGISTRY_WRITE_SCOPE": "enforce"},
    ).json()
    assert {c["id"]: c["enforcing"] for c in spoofed["controls"]}["registry_write"] is False


# ── nothing secret leaks ─────────────────────────────────────────────────


def test_response_carries_no_credential_material(client, monkeypatch):
    """The response names env VARS, never their secret siblings. A posture page
    that grew a 'here is the configured issuer/key' field would turn a low-risk
    disclosure into a real one."""
    for env in POSTURE_ENVS:
        monkeypatch.setenv(env, "off")
    raw = client.get("/v1/tenant/me/posture").text
    for pattern in (r"sk-[A-Za-z0-9]", r"AKIA", r"BEGIN [A-Z ]*PRIVATE KEY",
                    r"ghp_", r"xox[baprs]-"):
        assert not re.search(pattern, raw), pattern
    for leaky in ("SHIELD_ADMIN_KEY", "client_secret", "UPSTASH", "REDIS_URL"):
        assert leaky not in raw, leaky


# ── auth ─────────────────────────────────────────────────────────────────


def test_requires_a_tenant(monkeypatch):
    """Whatever _require_tenant refuses, this endpoint refuses too — it is not a
    public status page."""
    from fastapi import FastAPI

    def _refuse(request):
        raise HTTPException(status_code=403, detail="no tenant")

    monkeypatch.setattr(rts, "_require_tenant", _refuse)
    app = FastAPI()
    app.include_router(rts.router)
    assert TestClient(app).get("/v1/tenant/me/posture").status_code == 403


# ── regression guards ────────────────────────────────────────────────────


def test_modes_come_from_the_deciding_modules_not_a_local_copy():
    """The drift guard. If this handler ever parses the env itself, its answer
    can disagree with the code that acts on it — and the disagreement is silent,
    because both look correct in isolation.

    Asserted at source level rather than behaviourally: a behavioural test only
    catches drift once the two implementations already differ, which is after
    someone has trusted the wrong answer.
    """
    src = inspect.getsource(rts._posture_modes)
    assert "registry_write_mode" in src
    assert "agent_token_pop_mode" in src
    assert "role_binding_mode" in src
    assert "auto_revoke" in src
    # The tell for a second copy: reading the reported vars directly here.
    for env in ("SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_AGENT_TOKEN_POP",
                "SHIELD_ROLE_BINDING"):
        assert env not in src, f"{env} parsed locally instead of via its module"


def test_sso_check_and_sso_reporting_share_one_reader():
    """_require_tenant enforces SSO; posture reports it. Two truthy sets would
    let the portal say 'not required' on a deployment that refuses keys."""
    assert "_require_sso_enabled()" in inspect.getsource(rts._require_tenant)
    assert "_require_sso_enabled()" in inspect.getsource(rts._posture_modes)


def test_posture_touches_no_store():
    """Off the hot path AND off the store: this must not become a Redis read on
    a page the portal loads on every visit."""
    src = inspect.getsource(rts.get_my_posture)
    for forbidden in ("get_redis", "redis", "kv_get", "tenant_store"):
        assert forbidden not in src, forbidden
