"""Regression test for QA finding tel-004.

The guardrail-metrics route (`/v1/tenant/me/guardrails/metrics`) was mounted
only on the admin plane, so it 404'd on the data-plane host the QA tested.
This guards against that route silently dropping off the data-plane app again.
"""


def _data_plane_app_no_auth():
    """Build the data-plane app with auth disabled so we can tell a missing
    route (404) apart from a mounted-but-tenant-gated route (401)."""
    from unittest.mock import patch

    import config.schema as cs
    from config.schema import ShieldConfig, AuthConfig

    cfg = ShieldConfig(auth=AuthConfig(enabled=False))
    original = cs.config
    cs.config = cfg
    try:
        with patch("config.schema.load_config", return_value=cfg):
            from core.app import create_app

            app = create_app()
    finally:
        cs.config = original
    return app


def test_guardrail_metrics_mounted_on_data_plane():
    """tel-004: the metrics route must exist on the data-plane app (not 404).

    Introspecting ``app.routes[*].path`` is fragile across Starlette versions
    (newer versions report ``None``), so we assert the observable symptom: the
    route responds (tenant-gated 401) rather than 404, while a bogus sibling
    path under the same prefix 404s.
    """
    from starlette.testclient import TestClient

    client = TestClient(_data_plane_app_no_auth())

    # Mounted route, no tenant context -> handler raises 401 (NOT 404).
    assert client.get("/v1/tenant/me/guardrails/metrics").status_code == 401
    assert (
        client.get("/v1/tenant/me/guardrails/metrics/some_guardrail").status_code
        == 401
    )
    # A path that was never registered under the same prefix -> 404.
    assert client.get("/v1/tenant/me/guardrails/nonexistent-xyz").status_code == 404


def test_metrics_route_returns_summary_shape(monkeypatch):
    """With a tenant context, the route returns the summary shape (not 404)."""
    from starlette.testclient import TestClient

    import config.schema as cs
    from config.schema import ShieldConfig, AuthConfig

    cfg = ShieldConfig(
        auth=AuthConfig(
            enabled=True,
            api_keys=["test-key-123"],
            public_paths=["/health"],
        ),
    )

    # Make the tenant key resolve to a tenant so request.state.tenant_id is set.
    monkeypatch.setattr(
        "core.middleware._get_cached_tenant",
        lambda api_key: ("tenant-acme", {"name": "Acme"})
        if api_key == "tenant-acme-key"
        else (None, None),
    )
    monkeypatch.setattr(
        "storage.tenant_store.resolve_tenant_by_api_key",
        lambda api_key: "tenant-acme" if api_key == "tenant-acme-key" else None,
    )
    monkeypatch.setattr(
        "api.routes_guardrail_metrics.get_all_guardrails_summary",
        lambda tenant_id, days=30: [],
    )

    original = cs.config
    cs.config = cfg
    try:
        from unittest.mock import patch

        with patch("config.schema.load_config", return_value=cfg):
            from core.app import create_app

            app = create_app()
        resp = TestClient(app).get(
            "/v1/tenant/me/guardrails/metrics",
            headers={"X-API-Key": "tenant-acme-key"},
        )
    finally:
        cs.config = original

    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "tenant-acme"
    assert body["total_guardrails"] == 0
