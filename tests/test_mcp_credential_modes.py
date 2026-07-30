"""All eight upstream credential modes (docs/spec-mcp-credential-modes.md).

No network: strategies take an injected client. The point of the shared frame is
that the timer, lock, single-flight and status model exist once, so the tests that
matter most are the SHARED ones — a bug there is a bug in all five dynamic modes.

The single-flight test is the load-bearing one. Most providers invalidate the old
refresh token when it is used, so two concurrent renewals can destroy a working
credential: one succeeds, the other presents a dead token and strands the route.
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from core import mcp_credentials as cred
from storage import mcp_oauth_store as ostore

_PREFIXES = ("mcp_oauth:", "mcp_gateway:", "mcp_cred:", "vault:")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIXES)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


class _Client:
    """Records calls; returns queued responses."""

    def __init__(self, *responses):
        self._responses = list(responses) or [_Resp(200, {"access_token": "AT"})]
        self.calls: list = []

    async def post(self, url, **kw):
        self.calls.append((url, kw.get("data"), kw.get("headers")))
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


def _ctx(mode, **over):
    rec = {
        "mode": mode,
        "token_endpoint": "https://example.com/oauth2/token",
        "client_id": "cid",
        "scopes": ["mcp.invoke"],
        "status": ostore.STATUS_CONNECTED,
    }
    rec.update(over)
    return cred.CredentialContext(tenant_id="acme", route="payments", record=rec,
                                  upstream_url="https://api.example.com/mcp")


def _captured_store():
    """Patch persistence so a strategy can be tested without a live vault."""
    seen = {}

    def _store(ctx, *, token, expires_at, refresh_token=""):
        seen.update({"token": token, "expires_at": expires_at,
                     "refresh_token": refresh_token})
        return {"expires_at": expires_at}

    return seen, patch.object(cred, "store_credential", _store)


# ── the eight modes are all registered ───────────────────────────────


def test_all_eight_modes_are_supported():
    assert len(cred.supported_modes()) == len(cred.ALL_MODES) == 8


@pytest.mark.parametrize("mode", cred.STATIC_MODES)
def test_static_modes_have_no_provider(mode):
    """Modes 1-3 need no acquisition. The ABSENCE of a provider is the mode, which
    is what leaves every already-configured route untouched."""
    assert cred.get_provider(mode) is None
    assert cred.is_static(mode) is True
    assert cred.due_for_renewal({"mode": mode, "status": "connected"}) is False


def test_absent_mode_is_treated_as_static():
    """An existing route predates this feature and has no mode at all."""
    assert cred.is_static(None) is True
    assert cred.get_provider(None) is None


@pytest.mark.parametrize("mode", [cred.MODE_AUTH_CODE, cred.MODE_DEVICE_CODE,
                                  cred.MODE_CLIENT_CREDENTIALS,
                                  cred.MODE_GITHUB_APP, cred.MODE_CAPABILITY])
def test_dynamic_modes_have_a_provider(mode):
    p = cred.get_provider(mode)
    assert p is not None and p.mode == mode


def test_only_two_modes_need_a_human():
    interactive = [m for m in cred.ALL_MODES
                   if (cred.get_provider(m) or None) and cred.get_provider(m).interactive]
    assert sorted(interactive) == sorted([cred.MODE_AUTH_CODE, cred.MODE_DEVICE_CODE])


def test_non_interactive_modes_refuse_the_browser_flow():
    """Routing a machine mode through connect would hand an operator a dead
    authorize URL to sit waiting on."""
    for mode in (cred.MODE_CLIENT_CREDENTIALS, cred.MODE_GITHUB_APP,
                 cred.MODE_CAPABILITY):
        p = cred.get_provider(mode)
        with pytest.raises(cred.CredentialError) as ei:
            run(p.begin(_ctx(mode)))
        assert ei.value.status == 422 and ei.value.permanent


# ── shared frame: expiry, errors, scheduling ─────────────────────────


def test_expiry_falls_back_when_the_provider_omits_expires_in():
    """Assuming a credential is eternal is how you get a dead one in production
    with no signal."""
    now = int(time.time())
    assert cred.expiry_from({}) > now
    assert cred.expiry_from({"expires_in": "not-a-number"}) > now
    assert cred.expiry_from({"expires_in": 0}) > now
    assert cred.expiry_from({"expires_in": "7200"}) >= now + 7000


def test_permanent_oauth_errors_are_not_retried():
    """invalid_grant means the grant is gone; retrying hammers the provider and
    buries the one state a human must act on."""
    for code in ("invalid_grant", "invalid_client", "unauthorized_client"):
        c = _Client(_Resp(400, {"error": code}))
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.post_token_endpoint(c, "https://example.com/t", {},
                                         purpose="t"))
        assert ei.value.permanent is True, code


def test_transient_errors_stay_retryable():
    c = _Client(_Resp(503, {"error": "temporarily_unavailable"}))
    with pytest.raises(cred.CredentialError) as ei:
        run(cred.post_token_endpoint(c, "https://example.com/t", {}, purpose="t"))
    assert ei.value.permanent is False


def test_token_endpoint_errors_do_not_echo_the_body():
    c = _Client(_Resp(400, {"error": "invalid_grant",
                            "error_description": "SENSITIVE-INTERNAL-DETAIL"}))
    with pytest.raises(cred.CredentialError) as ei:
        run(cred.post_token_endpoint(c, "https://example.com/t", {}, purpose="t"))
    assert "SENSITIVE" not in ei.value.message


def test_token_endpoint_is_ssrf_guarded():
    from core.url_safety import UnsafeURLError

    c = _Client()
    with patch("core.url_safety.validate_outbound_url",
               side_effect=UnsafeURLError("blocked")):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.post_token_endpoint(c, "http://169.254.169.254/t", {}, purpose="t"))
    assert ei.value.status == 400 and c.calls == []


def test_response_without_access_token_is_an_error():
    c = _Client(_Resp(200, {"token_type": "bearer"}))
    with pytest.raises(cred.CredentialError):
        run(cred.post_token_endpoint(c, "https://example.com/t", {}, purpose="t"))


def test_renewal_is_single_flighted():
    """THE test. Providers rotate refresh tokens; two concurrent renewals can
    invalidate the good one, so the second caller must be turned away."""
    with patch("storage.tenant_store._get_redis") as gr:
        holder = {}

        class _R:
            def set(self, k, v, nx=False, ex=None):
                if nx and k in holder:
                    return False
                holder[k] = v
                return True

            def delete(self, k):
                holder.pop(k, None)

        gr.return_value = _R()
        assert cred.acquire_renewal_lock("acme", "payments") is True
        assert cred.acquire_renewal_lock("acme", "payments") is False   # blocked
        cred.release_renewal_lock("acme", "payments")
        assert cred.acquire_renewal_lock("acme", "payments") is True    # freed


def test_lock_failure_does_not_skip_a_needed_renewal():
    """A lock we cannot take is not a reason to let a credential expire."""
    class _Broken:
        def set(self, *a, **k):
            raise RuntimeError("redis down")

    with patch("storage.tenant_store._get_redis", return_value=_Broken()):
        assert cred.acquire_renewal_lock("acme", "payments") is True


def test_renew_route_never_raises_and_reports_outcomes():
    """It runs from a background sweep; an exception would kill every other
    route's renewal."""
    assert run(cred.renew_route("acme", "missing"))["renewed"] is False

    ostore.set_broker("acme", "static-route", {"mode": cred.MODE_STATIC_BEARER})
    assert run(cred.renew_route("acme", "static-route"))["status"] == "static"

    ostore.set_broker("acme", "weird", {"mode": "not-a-mode",
                                        "status": ostore.STATUS_CONNECTED})
    assert run(cred.renew_route("acme", "weird"))["status"] == "unsupported"


def test_permanent_failure_marks_needs_consent_not_error():
    """The distinction the console depends on: one needs a human, one retries."""
    ostore.set_broker("acme", "payments", {
        "mode": cred.MODE_CLIENT_CREDENTIALS, "status": ostore.STATUS_CONNECTED,
        "token_endpoint": "https://example.com/oauth2/token", "client_id": "c"})

    async def _boom(self, ctx, **kw):
        raise cred.CredentialError(502, "invalid_client", permanent=True)

    with patch.object(cred.ClientCredentialsProvider, "renew", _boom):
        out = run(cred.renew_route("acme", "payments"))
    assert out["renewed"] is False
    assert ostore.get_broker("acme", "payments")["status"] == ostore.STATUS_NEEDS_CONSENT


def test_transient_failure_marks_error_and_stays_retryable():
    ostore.set_broker("acme", "payments", {
        "mode": cred.MODE_CLIENT_CREDENTIALS, "status": ostore.STATUS_CONNECTED,
        "token_endpoint": "https://example.com/oauth2/token", "client_id": "c"})

    async def _boom(self, ctx, **kw):
        raise cred.CredentialError(502, "upstream 503", permanent=False)

    with patch.object(cred.ClientCredentialsProvider, "renew", _boom):
        run(cred.renew_route("acme", "payments"))
    assert ostore.get_broker("acme", "payments")["status"] == ostore.STATUS_ERROR


def test_escape_hatch_disables_renewal():
    ostore.set_broker("acme", "payments", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                           "status": ostore.STATUS_CONNECTED})
    with patch.dict("os.environ", {"SHIELD_MCP_CREDENTIAL_MODES": "0"}):
        assert run(cred.renew_route("acme", "payments"))["status"] == "disabled"


# ── mode 4: authorization code ───────────────────────────────────────


def test_auth_code_exchange_stores_both_tokens():
    seen, p = _captured_store()
    c = _Client(_Resp(200, {"access_token": "AT", "refresh_token": "RT",
                            "expires_in": 3600}))
    with p:
        run(cred.AuthCodeProvider().complete(
            _ctx(cred.MODE_AUTH_CODE, redirect_uri="https://s/cb"),
            code="the-code", code_verifier="v", client=c))
    assert seen["token"] == "AT" and seen["refresh_token"] == "RT"
    _, data, _ = c.calls[0]
    assert data["grant_type"] == "authorization_code"
    assert data["code_verifier"] == "v"          # PKCE proof is sent


def test_auth_code_refresh_replaces_a_rotated_refresh_token():
    """Providers that rotate invalidate the old one. Dropping the new value would
    strand the route at the NEXT renewal — a bug that only shows up later."""
    seen, p = _captured_store()
    c = _Client(_Resp(200, {"access_token": "AT2", "refresh_token": "RT2",
                            "expires_in": 3600}))
    with p, patch.object(cred.CredentialContext, "secret",
                         lambda self, f: "RT1" if "refresh" in f else ""):
        run(cred.AuthCodeProvider().renew(_ctx(cred.MODE_AUTH_CODE), client=c))
    assert seen["refresh_token"] == "RT2"


def test_auth_code_renew_without_a_stored_refresh_token_is_permanent():
    with patch.object(cred.CredentialContext, "secret", lambda self, f: ""):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.AuthCodeProvider().renew(_ctx(cred.MODE_AUTH_CODE), client=_Client()))
    assert ei.value.permanent is True


def test_revocation_failure_does_not_block_local_deletion():
    """A provider outage must not leave an un-deletable route behind."""
    c = _Client(_Resp(500, {}))
    with patch.object(cred.CredentialContext, "secret", lambda self, f: "RT"):
        run(cred.AuthCodeProvider().revoke(
            _ctx(cred.MODE_AUTH_CODE,
                 revocation_endpoint="https://example.com/revoke"), client=c))


# ── mode 6: client credentials ───────────────────────────────────────


def test_client_credentials_acquires_without_a_refresh_token():
    """RFC 6749 says not to issue one; re-running the grant IS the renewal."""
    seen, p = _captured_store()
    c = _Client(_Resp(200, {"access_token": "AT", "expires_in": 1800}))
    with p, patch.object(cred.CredentialContext, "secret", lambda self, f: "SECRET"):
        run(cred.ClientCredentialsProvider().renew(
            _ctx(cred.MODE_CLIENT_CREDENTIALS), client=c))
    assert seen["token"] == "AT" and seen["refresh_token"] == ""
    _, data, _ = c.calls[0]
    assert data["grant_type"] == "client_credentials"
    assert data["scope"] == "mcp.invoke"


def test_client_credentials_needs_a_secret():
    with patch.object(cred.CredentialContext, "secret", lambda self, f: ""):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.ClientCredentialsProvider().renew(
                _ctx(cred.MODE_CLIENT_CREDENTIALS), client=_Client()))
    assert ei.value.permanent is True


# ── mode 8: gateway-issued capability ────────────────────────────────


def test_capability_mints_without_any_vendor_credential():
    """The only mode with no upstream secret at all — nothing to leak or rotate."""
    seen, p = _captured_store()
    with p, patch("core.capabilities.mint_cap", return_value="CAP-TOKEN"):
        run(cred.CapabilityProvider().renew(_ctx(cred.MODE_CAPABILITY)))
    assert seen["token"] == "CAP-TOKEN"
    assert seen["expires_at"] > int(time.time())


def test_capability_fails_closed_when_signing_is_unavailable():
    """A route expecting a minted capability must never fall back to no auth."""
    with patch("core.capabilities.mint_cap", side_effect=RuntimeError("no signer")):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.CapabilityProvider().renew(_ctx(cred.MODE_CAPABILITY)))
    assert ei.value.permanent is True


def test_capability_ttl_is_short_and_overridable():
    seen, p = _captured_store()
    with p, patch("core.capabilities.mint_cap", return_value="CAP"):
        run(cred.CapabilityProvider().renew(
            _ctx(cred.MODE_CAPABILITY, capability_ttl=60)))
    assert seen["expires_at"] <= int(time.time()) + 61
    assert cred.CAPABILITY_TTL_SECONDS <= 3600


# ── mode 7: GitHub App ───────────────────────────────────────────────


def _gh_ctx(**over):
    return _ctx(cred.MODE_GITHUB_APP,
                github_app_id="12345",
                github_installation_id="678",
                token_endpoint="https://api.github.com/app/installations/678/access_tokens",
                **over)


def test_github_app_exchanges_an_app_jwt_for_an_installation_token():
    seen, p = _captured_store()
    c = _Client(_Resp(201, {"token": "ghs_installation",
                            "expires_at": "2026-07-29T21:00:00Z"}))
    with p, patch.object(cred.GitHubAppProvider, "_app_jwt", lambda s, a, k: "APPJWT"), \
         patch.object(cred.CredentialContext, "secret", lambda self, f: "PEM"):
        run(cred.GitHubAppProvider().renew(_gh_ctx(), client=c))
    assert seen["token"] == "ghs_installation"
    _, _, headers = c.calls[0]
    assert headers["Authorization"] == "Bearer APPJWT"


def test_github_app_missing_config_is_permanent():
    with patch.object(cred.CredentialContext, "secret", lambda self, f: ""):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.GitHubAppProvider().renew(_gh_ctx(), client=_Client()))
    assert ei.value.permanent is True


def test_github_app_uninstalled_needs_a_human():
    c = _Client(_Resp(404, {"message": "Not Found"}))
    with patch.object(cred.GitHubAppProvider, "_app_jwt", lambda s, a, k: "J"), \
         patch.object(cred.CredentialContext, "secret", lambda self, f: "PEM"):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.GitHubAppProvider().renew(_gh_ctx(), client=c))
    assert ei.value.permanent is True and "uninstalled" in ei.value.message


def test_github_app_bad_jwt_is_permanent():
    c = _Client(_Resp(401, {}))
    with patch.object(cred.GitHubAppProvider, "_app_jwt", lambda s, a, k: "J"), \
         patch.object(cred.CredentialContext, "secret", lambda self, f: "PEM"):
        with pytest.raises(cred.CredentialError) as ei:
            run(cred.GitHubAppProvider().renew(_gh_ctx(), client=c))
    assert ei.value.permanent is True


def test_github_app_jwt_is_backdated_for_clock_skew():
    """GitHub rejects future-dated JWTs, so iat is backdated deliberately."""
    import jwt

    key = _rsa_pem()
    token = cred.GitHubAppProvider()._app_jwt("12345", key)
    claims = jwt.decode(token, options={"verify_signature": False})
    now = int(time.time())
    assert claims["iat"] <= now - 1
    assert claims["exp"] - claims["iat"] <= 10 * 60      # GitHub's hard limit
    assert claims["iss"] == "12345"


def test_github_app_malformed_key_is_an_operator_error():
    with pytest.raises(cred.CredentialError) as ei:
        cred.GitHubAppProvider()._app_jwt("1", "not-a-pem")
    assert ei.value.permanent is True and ei.value.status == 400


def _rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()


# ── mode 5: device flow ──────────────────────────────────────────────


def _dev_ctx(**over):
    return _ctx(cred.MODE_DEVICE_CODE,
                device_authorization_endpoint="https://example.com/device",
                **over)


def test_device_begin_returns_what_the_operator_must_see():
    c = _Client(_Resp(200, {"device_code": "DC", "user_code": "WDJB-MJHT",
                            "verification_uri": "https://idp.example.com/activate",
                            "interval": 5, "expires_in": 900}))
    out = run(cred.DeviceCodeProvider().begin(_dev_ctx(), client=c))
    assert out["user_code"] == "WDJB-MJHT"
    assert out["verification_uri"].endswith("/activate")
    assert out["interval"] == 5


def test_device_begin_requires_the_endpoint():
    """Higgsfield advertises this flow but 404s on discovery, so an absent
    endpoint is the realistic case, not a hypothetical."""
    with pytest.raises(cred.CredentialError) as ei:
        run(cred.DeviceCodeProvider().begin(
            _ctx(cred.MODE_DEVICE_CODE), client=_Client()))
    assert ei.value.status == 422 and ei.value.permanent


def test_device_pending_is_not_a_permanent_failure():
    """authorization_pending is the normal 'not yet' of a device flow; treating it
    as permanent would abort every flow before the operator finished typing."""
    c = _Client(_Resp(400, {"error": "authorization_pending"}))
    with pytest.raises(cred.CredentialError) as ei:
        run(cred.DeviceCodeProvider().complete(_dev_ctx(), device_code="DC", client=c))
    assert ei.value.status == 202
    assert ei.value.permanent is False


def test_device_complete_stores_the_credential():
    seen, p = _captured_store()
    c = _Client(_Resp(200, {"access_token": "AT", "refresh_token": "RT",
                            "expires_in": 3600}))
    with p, patch.object(cred.CredentialContext, "secret", lambda self, f: ""):
        run(cred.DeviceCodeProvider().complete(_dev_ctx(), device_code="DC", client=c))
    assert seen["token"] == "AT" and seen["refresh_token"] == "RT"
    _, data, _ = c.calls[0]
    assert data["grant_type"].endswith("device_code")


def test_device_renewal_reuses_the_auth_code_refresh():
    """Same refresh_token grant; a second copy would be a second set of bugs."""
    seen, p = _captured_store()
    c = _Client(_Resp(200, {"access_token": "AT2", "expires_in": 60}))
    with p, patch.object(cred.CredentialContext, "secret",
                         lambda self, f: "RT" if "refresh" in f else ""):
        run(cred.DeviceCodeProvider().renew(_dev_ctx(), client=c))
    assert seen["token"] == "AT2"
    _, data, _ = c.calls[0]
    assert data["grant_type"] == "refresh_token"


# ── sweep ────────────────────────────────────────────────────────────


def test_sweep_only_touches_routes_that_are_due():
    from storage import mcp_gateway_store as gstore

    now = int(time.time())
    gstore.set_upstream("acme", "due", {"route": "due"})
    gstore.set_upstream("acme", "fresh", {"route": "fresh"})
    ostore.set_broker("acme", "due", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                      "status": ostore.STATUS_CONNECTED,
                                      "expires_at": now + 10})
    ostore.set_broker("acme", "fresh", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                       "status": ostore.STATUS_CONNECTED,
                                       "expires_at": now + 9999})

    async def _ok(self, ctx, **kw):
        return {"expires_at": now + 3600}

    with patch.object(cred.ClientCredentialsProvider, "renew", _ok):
        out = run(cred.sweep_tenant("acme"))
    assert out["renewed"] == ["due"]
    assert out["skipped"] == ["fresh"]


# ── task 7: reactive renewal on the guard path ───────────────────────
#
# The only guard-path change in the whole workstream, so the property that gets
# asserted hardest is the one that keeps the latency contract: a static or
# unbrokered route must do NO extra I/O.


def _reads_counted():
    """Count broker-record reads so 'zero I/O' is measured, not asserted."""
    reads = []
    import storage.mcp_oauth_store as s

    real = s.get_broker

    def _counting(tenant_id, route):
        reads.append((tenant_id, route))
        return real(tenant_id, route)

    return reads, patch.object(s, "get_broker", _counting)


@pytest.mark.parametrize("cfg", [
    {"route": "r"},                                        # predates brokering
    {"route": "r", "credential_mode": cred.MODE_NONE},
    {"route": "r", "credential_mode": cred.MODE_API_KEY},
    {"route": "r", "credential_mode": cred.MODE_STATIC_BEARER},
])
def test_static_routes_do_no_extra_io_on_the_guard_path(cfg):
    """This is the latency contract. If checking 'does this need renewal?' read the
    broker record on every call, every static route would pay a Redis GET per
    tools/call — which is exactly what denormalizing the mode onto the route
    document avoids."""
    from core.mcp.gateway import ensure_credential_fresh

    reads, counting = _reads_counted()
    with counting:
        run(ensure_credential_fresh(cfg, "acme"))
    assert reads == []


def test_dynamic_route_not_yet_due_reads_once_and_does_not_renew():
    from core.mcp.gateway import ensure_credential_fresh

    ostore.set_broker("acme", "r", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                    "status": ostore.STATUS_CONNECTED,
                                    "expires_at": int(time.time()) + 9999})
    renewed = []

    async def _spy(tenant_id, route, **kw):
        renewed.append(route)
        return {"renewed": True}

    reads, counting = _reads_counted()
    with counting, patch("core.mcp_credentials.renew_route", _spy):
        run(ensure_credential_fresh({"route": "r",
                                     "credential_mode": cred.MODE_CLIENT_CREDENTIALS},
                                    "acme"))
    assert len(reads) == 1        # one read to decide
    assert renewed == []          # nothing due, nothing renewed


def test_expiring_route_is_renewed_reactively():
    from core.mcp.gateway import ensure_credential_fresh

    ostore.set_broker("acme", "r", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                    "status": ostore.STATUS_CONNECTED,
                                    "expires_at": int(time.time()) + 5})
    renewed = []

    async def _spy(tenant_id, route, **kw):
        renewed.append(route)
        return {"renewed": True}

    with patch("core.mcp_credentials.renew_route", _spy):
        run(ensure_credential_fresh({"route": "r",
                                     "credential_mode": cred.MODE_CLIENT_CREDENTIALS},
                                    "acme"))
    assert renewed == ["r"]


def test_reactive_renewal_never_raises_into_the_guard_path():
    """A transient provider blip must not become a gateway exception. If the token
    really is dead, materialization fails closed with a clear message instead."""
    from core.mcp.gateway import ensure_credential_fresh

    ostore.set_broker("acme", "r", {"mode": cred.MODE_CLIENT_CREDENTIALS,
                                    "status": ostore.STATUS_CONNECTED,
                                    "expires_at": int(time.time()) - 1})

    async def _boom(*a, **kw):
        raise RuntimeError("provider on fire")

    with patch("core.mcp_credentials.renew_route", _boom):
        run(ensure_credential_fresh({"route": "r",
                                     "credential_mode": cred.MODE_CLIENT_CREDENTIALS},
                                    "acme"))   # must not raise


def test_needs_consent_is_not_retried_on_the_guard_path():
    """Otherwise every single call would fire a doomed token request at the
    provider — the worst possible place for a retry storm."""
    from core.mcp.gateway import ensure_credential_fresh

    ostore.set_broker("acme", "r", {"mode": cred.MODE_AUTH_CODE,
                                    "status": ostore.STATUS_NEEDS_CONSENT,
                                    "expires_at": int(time.time()) - 100})
    renewed = []

    async def _spy(tenant_id, route, **kw):
        renewed.append(route)
        return {}

    with patch("core.mcp_credentials.renew_route", _spy):
        run(ensure_credential_fresh({"route": "r",
                                     "credential_mode": cred.MODE_AUTH_CODE}, "acme"))
    assert renewed == []


def test_escape_hatch_disables_the_guard_path_work_entirely():
    from core.mcp.gateway import ensure_credential_fresh

    reads, counting = _reads_counted()
    with counting, patch.dict("os.environ", {"SHIELD_MCP_CREDENTIAL_MODES": "0"}):
        run(ensure_credential_fresh({"route": "r",
                                     "credential_mode": cred.MODE_CLIENT_CREDENTIALS},
                                    "acme"))
    assert reads == []
