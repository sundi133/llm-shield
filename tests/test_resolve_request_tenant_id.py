"""resolve_request_tenant_id — tenant resolution fallback for guardrail paths.

Regression for empty Guardrail Metrics / Board Report tabs: /guardrails/input
and /guardrails/output recorded metrics only when middleware had populated
request.state.tenant_id. On a data plane behind an auth proxy that doesn't run
that middleware for the guardrail endpoints, the request returned 200 but
tenant_id was "" so record_results_batch was skipped — metrics silently dropped.

This helper resolves the tenant from state, then the X-Tenant-ID header, then
the X-API-Key (mirroring the tool-check route) so those writes land.

    PYTHONPATH=. pytest tests/test_resolve_request_tenant_id.py
"""

import types

import pytest

from storage import tenant_store


@pytest.fixture
def patched_resolver(monkeypatch):
    monkeypatch.setattr(tenant_store, "resolve_tenant_by_api_key",
                        lambda k: "tenant-abc" if k == "real-key" else None)


def _request(headers=None, state_tid=None):
    state = types.SimpleNamespace()
    if state_tid is not None:
        state.tenant_id = state_tid
    return types.SimpleNamespace(state=state, headers=headers or {})


def test_prefers_middleware_state(patched_resolver):
    # state wins even if a (different) API key is present
    req = _request({"X-API-Key": "real-key"}, state_tid="from-state")
    assert tenant_store.resolve_request_tenant_id(req) == "from-state"


def test_falls_back_to_api_key(patched_resolver):
    req = _request({"X-API-Key": "real-key"})
    assert tenant_store.resolve_request_tenant_id(req) == "tenant-abc"


def test_falls_back_to_tenant_header(patched_resolver):
    req = _request({"X-Tenant-ID": "hdr-tid"})
    assert tenant_store.resolve_request_tenant_id(req) == "hdr-tid"


def test_sk_test_key_maps_to_sandbox(patched_resolver):
    req = _request({"X-API-Key": "sk-test-anything"})
    assert tenant_store.resolve_request_tenant_id(req) == "test-tenant-001"


def test_unresolved_returns_empty_string(patched_resolver):
    # unknown key, no state, no header -> "" so the `if tenant_id` guard skips
    assert tenant_store.resolve_request_tenant_id(_request({"X-API-Key": "nope"})) == ""
    assert tenant_store.resolve_request_tenant_id(_request({})) == ""


def test_resolver_exception_is_swallowed(monkeypatch):
    def boom(_):
        raise RuntimeError("redis down")
    monkeypatch.setattr(tenant_store, "resolve_tenant_by_api_key", boom)
    # must not raise on the request path
    assert tenant_store.resolve_request_tenant_id(_request({"X-API-Key": "x"})) == ""


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
