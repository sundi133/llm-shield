"""Baseline: the existing role-binding modes must not move.

`strict_proxy` (docs/spec-proxy-trusted-role-header.md) adds a mode that reads
the trusted-proxy boundary. The whole safety argument for that change is
"it adds a mode, it does not modify one" — so that claim needs a test that
existed *before* the change, or it is just an assertion in a PR description.

Two properties are locked here:

  1. `off`, `prefer` and `strict` produce byte-identical ResolvedIdentity output
     whether the trusted-proxy boundary is configured or not. None of them may
     grow a dependency on proxy trust.
  2. The concrete resolution each mode performs, per scenario, as of today.

Property 1 is the one that matters. Property 2 catches an accidental rewrite of
the precedence chain while someone is in the file adding the new branch.
"""

from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core.identity_resolution import (SOURCE_HEADER, SOURCE_NONE, SOURCE_OIDC,
                                      clear_role_binding_cache_for_tests,
                                      resolve_identity)

BASELINE_MODES = ("off", "prefer", "strict")

PROXY_SECRET = "baseline-proxy-secret"

#: Every env var that could plausibly steer resolution. Cleared before each
#: case so a developer's shell cannot make this suite pass locally and fail in
#: CI — the failure mode this repo has hit before with polluted environments.
_ENV_KEYS = (
    "SHIELD_ROLE_BINDING",
    "SHIELD_TRUSTED_PROXY_ONLY",
    "SHIELD_TRUSTED_PROXY_SECRET",
    "SHIELD_TRUSTED_PROXY_IPS",
    "SHIELD_TOKEN_BINDING",
    "SHIELD_DELEGATION",
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


def _request(*, role_header=None, proxy_token=None, claimed_roles=None):
    """A request shaped like the ones resolve_identity() sees in the routes."""
    headers = {"X-Agent-Key": "bot"}
    if role_header is not None:
        headers["X-User-Role"] = role_header
    if proxy_token is not None:
        headers["X-Shield-Proxy-Token"] = proxy_token

    identity = None
    if claimed_roles is not None:
        identity = SimpleNamespace(
            agent_id="bot", roles=tuple(claimed_roles),
            identity_method="oidc", trust_level="high")

    return SimpleNamespace(
        headers=headers,
        state=SimpleNamespace(identity=identity),
        client=SimpleNamespace(host="10.0.0.9"),
        method="POST",
        url="https://shield.local/guardrails/input",
    )


#: (id, request kwargs, body_user_role)
SCENARIOS = (
    ("header_only", {"role_header": "doctor"}, None),
    ("body_only", {}, "admin"),
    ("body_and_header", {"role_header": "doctor"}, "admin"),
    ("neither", {}, None),
    ("verified_claim", {"role_header": "doctor"}, None),
    ("verified_claim_and_body", {"role_header": "doctor"}, "admin"),
)


def _scenario_request(scenario_id, kwargs, proxy_token=None):
    kw = dict(kwargs)
    if scenario_id.startswith("verified_claim"):
        kw["claimed_roles"] = ("nurse",)
    return _request(proxy_token=proxy_token, **kw)


def _resolve(monkeypatch, mode, scenario_id, kwargs, body_role, *, proxy):
    """Resolve one scenario under one mode, with the proxy boundary on or off.

    When `proxy` is True the boundary is fully configured AND the request
    carries a valid secret — the strongest possible "a trusted proxy is
    present" signal. If a baseline mode were to consult proxy trust, this is
    the setup under which it would show.
    """
    monkeypatch.setenv("SHIELD_ROLE_BINDING", mode)
    token = None
    if proxy:
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
        token = PROXY_SECRET
    else:
        monkeypatch.delenv("SHIELD_TRUSTED_PROXY_ONLY", raising=False)
        monkeypatch.delenv("SHIELD_TRUSTED_PROXY_SECRET", raising=False)

    clear_role_binding_cache_for_tests()
    return resolve_identity(
        _scenario_request(scenario_id, kwargs, proxy_token=token),
        body_user_role=body_role,
    )


# ── Property 1: proxy configuration must not reach the baseline modes ────────


@pytest.mark.parametrize("mode", BASELINE_MODES)
@pytest.mark.parametrize("scenario_id,kwargs,body_role", SCENARIOS,
                         ids=[s[0] for s in SCENARIOS])
def test_baseline_modes_ignore_the_proxy_boundary(
        monkeypatch, mode, scenario_id, kwargs, body_role):
    """off / prefer / strict resolve identically with the boundary on or off.

    This is the regression guard for docs/spec-proxy-trusted-role-header.md.
    If adding `strict_proxy` changes any of these three, the change was not
    additive and the spec's core safety claim is false.
    """
    without = _resolve(monkeypatch, mode, scenario_id, kwargs, body_role,
                       proxy=False)
    with_proxy = _resolve(monkeypatch, mode, scenario_id, kwargs, body_role,
                          proxy=True)

    assert asdict(without) == asdict(with_proxy), (
        f"mode={mode!r} scenario={scenario_id!r} changed when the trusted-proxy "
        f"boundary was configured. Baseline modes must not consult proxy trust."
    )


# ── Property 2: today's concrete resolution, per mode ────────────────────────


#: (scenario_id, expected_role, expected_source) as resolved TODAY.
_OFF = {
    "header_only": ("doctor", SOURCE_HEADER),
    "body_only": ("admin", "body"),
    "body_and_header": ("admin", "body"),
    "neither": ("", SOURCE_NONE),
    "verified_claim": ("doctor", SOURCE_HEADER),
    "verified_claim_and_body": ("admin", "body"),
}

_PREFER = {
    "header_only": ("doctor", SOURCE_HEADER),
    "body_only": ("admin", "body"),
    "body_and_header": ("admin", "body"),
    "neither": ("", SOURCE_NONE),
    # A verified claim outranks both body and header.
    "verified_claim": ("nurse", SOURCE_OIDC),
    "verified_claim_and_body": ("nurse", SOURCE_OIDC),
}

_STRICT = {
    "header_only": ("", SOURCE_NONE),
    "body_only": ("", SOURCE_NONE),
    "body_and_header": ("", SOURCE_NONE),
    "neither": ("", SOURCE_NONE),
    "verified_claim": ("nurse", SOURCE_OIDC),
    "verified_claim_and_body": ("nurse", SOURCE_OIDC),
}

_EXPECTED = {"off": _OFF, "prefer": _PREFER, "strict": _STRICT}


@pytest.mark.parametrize("mode", BASELINE_MODES)
@pytest.mark.parametrize("scenario_id,kwargs,body_role", SCENARIOS,
                         ids=[s[0] for s in SCENARIOS])
@pytest.mark.parametrize("proxy", (False, True), ids=("no_proxy", "proxy"))
def test_baseline_resolution_is_unchanged(
        monkeypatch, mode, scenario_id, kwargs, body_role, proxy):
    """Snapshot of what each mode resolves, so a precedence rewrite is loud."""
    r = _resolve(monkeypatch, mode, scenario_id, kwargs, body_role, proxy=proxy)
    expected_role, expected_source = _EXPECTED[mode][scenario_id]
    assert (r.user_role, r.role_source) == (expected_role, expected_source)


def test_strict_never_reports_a_verified_role_it_did_not_verify(monkeypatch):
    """role_verified must track the source, not the mode.

    `strict` refusing a header is not the same as `strict` proving one. If
    role_verified were ever true for a self-asserted role, every audit built on
    it would be wrong.
    """
    r = _resolve(monkeypatch, "strict", "header_only", {"role_header": "doctor"},
                 None, proxy=True)
    assert r.role_verified is False
    assert r.user_role == ""


def test_header_overridden_only_fires_on_a_real_override(monkeypatch):
    """The escalation signal must not fire when nothing was overridden."""
    plain = _resolve(monkeypatch, "prefer", "header_only",
                     {"role_header": "doctor"}, None, proxy=False)
    assert plain.header_overridden is False

    overridden = _resolve(monkeypatch, "prefer", "verified_claim",
                          {"role_header": "doctor"}, None, proxy=False)
    assert overridden.header_overridden is True
