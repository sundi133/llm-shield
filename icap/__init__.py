"""ICAP adapter (`shield-icap`) — inline prompt/DLP enforcement behind an
enterprise Secure Web Gateway.

Per docs/spec-swg-icap-adapter.md. This package is a *customer-hosted edge
artifact*: it runs in its own image (`Dockerfile.icap`), imports nothing from
`core/` or `admin_app.py`, and reaches Shield only over HTTPS. Nothing here is
mounted by either plane.
"""
