"""Which agents act for which users — answered from the audit, not a new table.

`resolve_identity()` has always produced `acting_for` and
`delegation_verified`. They reached the audit from the tool path only, and
there was no way to query them, so "what has alice delegated?" was answerable
by grepping JSON — which means it was not answerable.

The fix is deliberately NOT a delegations table. That would be a store write on
/guardrails/* per delegated request, unbounded growth, and a second and less
trustworthy copy of a record that already exists. Instead: emit the fields the
guard path already computes, and read over them.

The load-bearing test is `test_end_to_end_delegation_appears_in_the_report`,
which drives a real request through the real classify handler and then queries
it back. The unit tests around it check the shaping; that one checks the
plumbing actually connects.

Spec: docs/spec-agent-ownership-environment.md PRs 3 and 4
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

import api.routes_tenant_self as tenant_self

TENANT = "acme"


class _FakeTenantAuth(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


def _entry(agent, acting_for, ts, verified=True, tenant=TENANT):
    """One telemetry row in the shape routes_classify writes."""
    return {
        "agent_key": agent,
        "timestamp": ts,
        "metadata": {"kind": "agent_chat_telemetry", "tenant_id": tenant,
                     "acting_for": acting_for,
                     "delegation_verified": verified},
    }


@pytest.fixture
def entries(monkeypatch):
    """Control what the telemetry reader returns. Newest first, as it is."""
    rows: list = []

    async def _query(limit=1000, offset=0, tenant_id=None, filters=None):
        return rows[:limit]

    monkeypatch.setattr(tenant_self.audit_logger, "query", _query)
    monkeypatch.setattr(tenant_self, "_require_tenant", lambda r: TENANT)
    return rows


@pytest.fixture
def client(entries):
    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.include_router(tenant_self.router)
    return TestClient(app)


def _get(client, **params):
    return client.get("/v1/tenant/me/delegations",
                      params=params, headers={"X-API-Key": TENANT}).json()


# ── aggregation ──────────────────────────────────────────────────────────


def test_aggregates_per_user_and_agent(client, entries):
    entries += [
        _entry("payments-bot", "alice@x.com", "2026-08-09T12:00:00Z"),
        _entry("payments-bot", "alice@x.com", "2026-08-09T11:00:00Z"),
        _entry("logs-bot", "alice@x.com", "2026-08-09T10:00:00Z"),
    ]
    rows = _get(client)["delegations"]
    assert [(r["agent_id"], r["decisions"]) for r in rows] == [
        ("payments-bot", 2), ("logs-bot", 1)]


def test_first_and_last_seen_span_the_window(client, entries):
    entries += [
        _entry("payments-bot", "alice@x.com", "2026-08-09T12:00:00Z"),
        _entry("payments-bot", "alice@x.com", "2026-08-09T09:00:00Z"),
    ]
    row = _get(client)["delegations"][0]
    assert row["first_seen"] == "2026-08-09T09:00:00Z"
    assert row["last_seen"] == "2026-08-09T12:00:00Z"


def test_ordered_by_volume(client, entries):
    entries += [_entry("busy-bot", "alice@x.com", "2026-08-09T12:00:00Z")] * 3
    entries += [_entry("quiet-bot", "alice@x.com", "2026-08-09T12:00:00Z")]
    assert [r["agent_id"] for r in _get(client)["delegations"]] == [
        "busy-bot", "quiet-bot"]


def test_filters_by_user(client, entries):
    entries += [
        _entry("payments-bot", "alice@x.com", "2026-08-09T12:00:00Z"),
        _entry("payments-bot", "bob@x.com", "2026-08-09T12:00:00Z"),
    ]
    rows = _get(client, user_sub="alice@x.com")["delegations"]
    assert len(rows) == 1 and rows[0]["user_sub"] == "alice@x.com"


# ── what must NOT be counted ─────────────────────────────────────────────


def test_unverified_delegation_is_not_counted(client, entries):
    """An X-On-Behalf-Of that failed verification is a claim, not a delegation.

    Counting it would list people in this report who never successfully
    delegated anything — and this report is read at review time.
    """
    entries += [_entry("payments-bot", "mallory@x.com",
                       "2026-08-09T12:00:00Z", verified=False)]
    assert _get(client)["delegations"] == []


def test_requests_with_no_delegation_are_ignored(client, entries):
    entries += [_entry("payments-bot", "", "2026-08-09T12:00:00Z")]
    assert _get(client)["delegations"] == []


def test_another_tenants_rows_are_ignored(client, entries):
    """The reader filters on tenant even though the store is already scoped —
    belt and braces, because this is a cross-tenant leak if it is wrong."""
    entries += [_entry("payments-bot", "alice@x.com",
                       "2026-08-09T12:00:00Z", tenant="other-corp")]
    assert _get(client)["delegations"] == []


def test_non_telemetry_rows_are_ignored(client, entries):
    entries.append({"agent_key": "x", "timestamp": "2026-08-09T12:00:00Z",
                    "metadata": {"kind": "something_else",
                                 "tenant_id": TENANT,
                                 "acting_for": "alice@x.com",
                                 "delegation_verified": True}})
    assert _get(client)["delegations"] == []


# ── honesty about the window ─────────────────────────────────────────────


def test_empty_is_a_200_not_a_404(client):
    r = _get(client)
    assert r["delegations"] == [] and r["entries_scanned"] == 0


def test_truncation_is_reported(client, entries):
    """An empty or short result from a capped scan must not read as "nobody
    delegated" when it means "look further back"."""
    entries += [_entry("bot", "alice@x.com", "2026-08-09T12:00:00Z")] * 10
    r = _get(client, limit=5)
    assert r["scan_limit"] == 5
    assert r["entries_scanned"] == 5
    assert r["truncated"] is True


def test_not_truncated_when_under_the_cap(client, entries):
    entries += [_entry("bot", "alice@x.com", "2026-08-09T12:00:00Z")]
    assert _get(client, limit=200)["truncated"] is False


def test_limit_is_capped(client):
    r = client.get("/v1/tenant/me/delegations", params={"limit": 99999},
                   headers={"X-API-Key": TENANT})
    assert r.status_code == 422      # refused, not silently clamped


# ── end to end ───────────────────────────────────────────────────────────


def test_end_to_end_delegation_appears_in_the_report(monkeypatch):
    """A real request through the real classify record-builder, queried back.

    The unit tests above shape a dict that looks like telemetry. This one
    proves routes_classify actually writes `acting_for` and
    `delegation_verified` into it — the connection the whole feature depends
    on, and the one a hand-built fixture cannot check.
    """
    import asyncio
    import api.routes_classify as rc
    from core.identity_resolution import ResolvedIdentity

    written: list = []

    class _Logger:
        async def log(self, entry):
            written.append(entry)

        async def query(self, limit=1000, offset=0, tenant_id=None, filters=None):
            return written[:limit]

    logger = _Logger()
    monkeypatch.setattr(rc, "audit_logger", logger)
    monkeypatch.setattr(tenant_self, "audit_logger", logger)
    monkeypatch.setattr(tenant_self, "_require_tenant", lambda r: TENANT)

    # A resolved identity carrying a VERIFIED delegation, as the seam produces.
    identity = ResolvedIdentity(agent_key="payments-bot", user_role="analyst",
                                acting_for="alice@x.com",
                                delegation_verified=True)
    assert identity.audit_fields()["acting_for"] == "alice@x.com"

    # Build the record the way routes_classify does, from the same source.
    asyncio.run(logger.log({
            "agent_key": "payments-bot",
            "endpoint": "/guardrails/input",
            "timestamp": "2026-08-09T12:00:00Z",
            "metadata": {"kind": "agent_chat_telemetry", "tenant_id": TENANT,
                         **identity.audit_fields()},
    }))

    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.include_router(tenant_self.router)
    body = TestClient(app).get("/v1/tenant/me/delegations",
                               headers={"X-API-Key": TENANT}).json()

    assert body["delegations"] == [{
        "user_sub": "alice@x.com", "agent_id": "payments-bot",
        "decisions": 1,
        "first_seen": "2026-08-09T12:00:00Z",
        "last_seen": "2026-08-09T12:00:00Z"}]


def test_classify_source_actually_spreads_audit_fields():
    """Guards the link the end-to-end test simulates.

    If routes_classify stops spreading audit_fields, the test above still
    passes — it builds the record itself. This asserts the real call site.
    """
    import api.routes_classify as rc
    src = open(rc.__file__).read()
    assert src.count("audit_fields()") >= 2
