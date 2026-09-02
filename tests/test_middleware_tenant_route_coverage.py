"""Every tenant-scoped route must be reachable through ShieldMiddleware.

`get_tenant_from_request` reads `request.state.tenant_id`, and ONLY
ShieldMiddleware sets that field. A router that depends on it but whose path is
not matched by the middleware's guarded prefixes answers 401 to every caller,
including one holding a perfectly valid tenant API key.

That is not hypothetical. `/v1/edge/policy-bundle` shipped in exactly that
state: mounted, correct, and unreachable. Its own unit tests could not see it
because they install a `dependency_overrides` entry for
`get_tenant_from_request`, which replaces the very thing that was broken. The
bug surfaced only when a real key was used against the deployed data plane.

So this test looks at the wiring rather than the handler: for each route that
declares the dependency, assert the middleware would enrich its path.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

from core.auth import get_tenant_from_request
from core.middleware import ShieldMiddleware


def _tenant_scoped_routes() -> list[tuple[str, str]]:
    """(path, router name) for every route depending on get_tenant_from_request."""
    import api.routes_edge as routes_edge

    routers = [("routes_edge", routes_edge.router)]
    for name in ("routes_data_policies", "routes_agent_policy", "routes_classify"):
        try:
            mod = __import__(f"api.{name}", fromlist=["router"])
        except Exception:  # optional module in a slim install
            continue
        if hasattr(mod, "router"):
            routers.append((name, mod.router))

    found: list[tuple[str, str]] = []
    for name, router in routers:
        app = FastAPI()
        app.include_router(router)
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for dep in route.dependant.dependencies:
                if dep.call is get_tenant_from_request:
                    found.append((route.path, name))
                    break
    return found


def _enriched(path: str) -> bool:
    return (
        any(path.startswith(p) for p in ShieldMiddleware._GUARDED_PREFIXES)
        or path in ShieldMiddleware._GUARDED_EXACT
    )


def test_at_least_one_tenant_scoped_route_is_discovered():
    """Guard the guard: if the discovery breaks, the test below passes vacuously."""
    assert _tenant_scoped_routes(), "found no routes depending on get_tenant_from_request"


def test_every_tenant_scoped_route_is_enriched_by_the_middleware():
    unreachable = [
        f"{path}  (from {name})"
        for path, name in _tenant_scoped_routes()
        if not _enriched(path)
    ]
    assert not unreachable, (
        "these routes depend on request.state.tenant_id but their path is not "
        "matched by ShieldMiddleware._GUARDED_PREFIXES / _GUARDED_EXACT, so the "
        "field is never set and they answer 401 to a valid tenant key:\n  "
        + "\n  ".join(unreachable)
    )


@pytest.mark.parametrize("path", ["/v1/edge/policy-bundle", "/v1/edge/anything"])
def test_edge_paths_are_enriched(path):
    """The specific regression. Named so a future edit to the prefix tuple
    cannot silently drop it again."""
    assert _enriched(path)


def test_edge_is_not_added_to_require_tenant_key():
    """Enrichment, not enforcement. _REQUIRE_TENANT_KEY changes what the
    middleware REJECTS, and the fix for a 401 must not quietly start rejecting
    other traffic. The route's own dependency is what refuses an anonymous
    caller."""
    assert not any(p.startswith("/v1/edge") for p in ShieldMiddleware._REQUIRE_TENANT_KEY)
