"""Every route that creates an agent validates it, not just the one that did.

`POST /v1/agents/registry` was hardened for IEMLabs VAPT 8.7 (Improper Input
Validation). `POST /v1/agents/register` and the policy bundle import reach
`policy_store.register_agent()` directly and inherited none of it, so this was
a 200:

    agent_id: '../../etc/passwd'
    name:     '<script>alert(1)</script>'
    status:   absent, which _registry_agent_status() reads as active

Two routes, one hardened and one not, is what happens when validation lives in
a route module. The fix moves it to the sink both routes write through, so a
route added later inherits the check rather than having to remember it.

The load-bearing test is `test_both_creation_routes_reject_the_same_body`: it
drives the identical payload through both and asserts they agree. A test that
only checked the new route would pass just as well if the two drifted the
other way.
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_agent_policy as agent_policy
import api.routes_agents_registry as reg
from storage import policy_store

TENANT = "acme"

TRAVERSAL_ID = "../../etc/passwd"
XSS_NAME = "<script>alert(1)</script>"


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.tenant_id = TENANT
        return await call_next(request)


@pytest.fixture
def store(monkeypatch):
    """One in-memory store behind BOTH write paths, via the real kv_get/kv_set.

    Deliberately not a stub of `get_redis_data`/`_save_agents`. The two routes
    reach `agents:{tenant}` through different code (kv_set here,
    `r.set(json.dumps(...))` there) and a fixture that stubs one of them proves
    nothing about whether they agree on what is stored. Both modules bind
    `_fallback_store` at import, so both names are pointed at one dict.
    """
    from storage import tenant_store
    data: dict = {}
    for mod in (tenant_store, policy_store):
        monkeypatch.setattr(mod, "_get_redis", lambda: None)
        monkeypatch.setattr(mod, "_fallback_store", data)
    monkeypatch.setattr(reg, "get_tenant_from_api_key", lambda r: TENANT)
    return data


@pytest.fixture
def client(store):
    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.include_router(agent_policy.router)
    app.include_router(reg.router)
    return TestClient(app)


def _body(agent_id=TRAVERSAL_ID, name=XSS_NAME):
    return {"agent_id": agent_id, "name": name, "tools": ["rotate_credential"],
            "role_permissions": {"intern": ["rotate_credential"]}}


# ── the bug ──────────────────────────────────────────────────────────────


def test_register_rejects_a_traversal_agent_id(client):
    r = client.post("/v1/agents/register", json=_body())
    assert r.status_code == 400, r.text
    assert "agent_id" in r.text


def test_register_is_a_400_not_a_500(client):
    """Rejected input is the caller's fault. A 500 tells them nothing and
    pages whoever owns the service."""
    assert client.post("/v1/agents/register", json=_body()).status_code == 400


def test_register_sanitizes_the_name(client, store):
    r = client.post("/v1/agents/register", json=_body(agent_id="payments-bot"))
    assert r.status_code == 200, r.text
    assert "<script>" not in r.json()["agent"]["name"]


def test_nothing_is_stored_when_the_id_is_rejected(client, store):
    """A rejected create must not leave a partial entry behind."""
    client.post("/v1/agents/register", json=_body())
    assert policy_store.get_agent_registry(TENANT) == {}


def test_both_creation_routes_reject_the_same_body(client):
    """The two routes must agree. This is the assertion that would have caught
    the original bug, and the one that catches a future divergence."""
    hostile = _body()
    a = client.post("/v1/agents/register", json=hostile)
    b = client.post("/v1/agents/registry", json=hostile)
    assert a.status_code == b.status_code == 400, f"{a.status_code} vs {b.status_code}"


def test_both_creation_routes_accept_the_same_valid_body(client):
    """Agreement has to hold in the allowing direction too, or the fix is just
    a route that refuses everything. Distinct ids: /registry 409s a duplicate
    and /register does not, which is the next test."""
    assert client.post("/v1/agents/register",
                       json=_body(agent_id="bot-a", name="Bot A")).status_code == 200
    assert client.post("/v1/agents/registry",
                       json=_body(agent_id="bot-b", name="Bot B")).status_code == 200


@pytest.mark.xfail(reason="Known divergence, out of scope for this fix: "
                          "/v1/agents/register upserts silently while "
                          "/v1/agents/registry 409s. Recorded so it is a "
                          "decision rather than a discovery.",
                   strict=True)
def test_register_should_conflict_on_a_duplicate_like_registry_does(client):
    """/v1/agents/register overwrites an existing agent with no conflict check,
    so it can widen a live agent's grants through what looks like a create.

    Not fixed here: adding a 409 changes the behaviour of a shipped endpoint
    and belongs with the write-authorization work, not with an input-validation
    fix. Marked strict so it fails loudly the day someone does fix it.
    """
    body = _body(agent_id="payments-bot", name="Payments Bot")
    assert client.post("/v1/agents/register", json=body).status_code == 200
    assert client.post("/v1/agents/register", json=body).status_code == 409


# ── the sink ─────────────────────────────────────────────────────────────


def test_register_agent_raises_valueerror_not_httpexception():
    """Storage must not depend on the web framework. A route translates."""
    with pytest.raises(ValueError):
        policy_store.register_agent(TENANT, {"agent_id": TRAVERSAL_ID})


@pytest.mark.parametrize("bad", ["", None, "../x", "a/b", "a b", "x" * 129,
                                 "<script>", "a;b", "a\x00b"])
def test_sink_rejects_hostile_ids(store, bad):
    with pytest.raises(ValueError):
        policy_store.register_agent(TENANT, {"agent_id": bad})


@pytest.mark.parametrize("ok", ["a", "payments-bot", "payments_bot", "A1", "x" * 128])
def test_sink_accepts_legitimate_ids(store, ok):
    assert policy_store.register_agent(TENANT, {"agent_id": ok})["agent_id"] == ok


def test_sink_sanitizes_the_display_fields(store):
    stored = policy_store.register_agent(
        TENANT, {"agent_id": "bot", "name": XSS_NAME, "description": XSS_NAME})
    assert "<script>" not in stored["name"]
    assert "<script>" not in stored["description"]


# ── the collateral this fix must NOT cause ───────────────────────────────
#
# An earlier draft ran a recursive sanitizer over the whole config. It stripped
# anything shaped like a tag and truncated as it went, which silently cut tool
# lists to 200, descriptions to 500 characters, and turned the DLP pattern
# <\d+> into an empty string — disabling a data protection rule as a side
# effect of fixing stored XSS. These tests exist so re-widening it fails loudly.


def test_a_dlp_regex_containing_angle_brackets_survives(store):
    """The worst case: sanitizing a functional field silently disables a
    data-protection rule and nothing anywhere reports it."""
    pattern = r"<\d+>"
    stored = policy_store.register_agent(TENANT, {
        "agent_id": "bot",
        "data_sanitization": {"pattern": pattern, "replacement": "[N]"}})
    assert stored["data_sanitization"]["pattern"] == pattern


def test_a_long_description_is_not_truncated(store):
    long_desc = "x" * 600
    stored = policy_store.register_agent(
        TENANT, {"agent_id": "bot", "description": long_desc})
    assert stored["description"] == long_desc


def test_a_large_tool_list_is_not_capped(store):
    tools = [f"tool_{i}" for i in range(250)]
    stored = policy_store.register_agent(
        TENANT, {"agent_id": "bot", "tools": list(tools)})
    assert stored["tools"] == tools


def test_role_permissions_pass_through_unchanged(store):
    perms = {"analyst": [f"tool_{i}" for i in range(250)]}
    stored = policy_store.register_agent(
        TENANT, {"agent_id": "bot", "role_permissions": {"analyst": list(perms["analyst"])}})
    assert stored["role_permissions"] == perms


def test_only_the_display_fields_are_rewritten(store):
    """Whole-config assertion: everything except name and description must come
    back byte-identical. Catches a future field being swept in by accident."""
    cfg = {"agent_id": "bot", "name": "Bot", "description": "does things",
           "tools": ["a", "b"], "role_permissions": {"r": ["a"]},
           "data_sanitization": {"pattern": "<x>"},
           "llm_validation": {"prompt": "is <this> ok?"},
           "allowed_resources": ["db://<prod>"], "status": "active"}
    stored = policy_store.register_agent(TENANT, dict(cfg))
    for key, original in cfg.items():
        assert stored[key] == original, f"{key} was rewritten: {stored[key]!r}"


def test_sink_does_not_mutate_the_callers_dict(store):
    """routes_policy reuses the bundle dict after the call."""
    original = {"agent_id": "bot", "name": XSS_NAME}
    policy_store.register_agent(TENANT, original)
    assert original["name"] == XSS_NAME


# ── bundle import ────────────────────────────────────────────────────────


def test_bundle_import_rejects_a_hostile_agent_id(store):
    """The bundle path validated nothing at all and imported in bulk."""
    with pytest.raises(ValueError):
        policy_store.register_agent(TENANT, {"agent_id": TRAVERSAL_ID,
                                             "name": "from bundle"})


def test_bundle_import_error_names_the_agent():
    """A bundle carries many agents; "invalid agent_id" alone is not
    actionable."""
    import inspect
    src = inspect.getsource(__import__("api.routes_policy", fromlist=["x"]))
    assert "in bundle:" in src


# ── drift guard ──────────────────────────────────────────────────────────


def test_registry_route_uses_the_shared_definitions():
    """Not a style check. The duplicate copy in the route module is precisely
    why one route was hardened and the other was not."""
    assert reg._VALID_ID_RE is policy_store.AGENT_ID_RE
    assert reg._sanitize_string is policy_store.sanitize_string
    assert reg._sanitize_value is policy_store.sanitize_value
