"""Walk an app's live route table, whatever the FastAPI version.

FastAPI 0.143 keeps each included router as one `_IncludedRouter` entry in
`app.routes` (its routes under `.original_router`, the include prefix under
`.include_context.prefix`); older versions copied the routes in flat. A test
that iterates `app.routes` directly sees almost nothing on the newer version
and passes because it checked nothing. CI installs the newer one (fastapi is
unpinned), so every route-table guard goes through this.
"""


def flat_routes(app_or_routes, prefix: str = ""):
    """Yield (path, route) for every endpoint route, nested includes expanded."""
    routes = getattr(app_or_routes, "routes", app_or_routes)
    for r in routes:
        inner = getattr(r, "original_router", None)
        if inner is not None:
            ctx = getattr(r, "include_context", None)
            yield from flat_routes(inner.routes, prefix + (getattr(ctx, "prefix", "") or ""))
            continue
        yield prefix + (getattr(r, "path", "") or ""), r
